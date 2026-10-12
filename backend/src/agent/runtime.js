import { randomUUID } from 'crypto';
import { AgentContext } from './context.js';
import { generateLLMPlan } from './planner.js';
import { executePlan } from './executor.js';
import { askFoundation, buildModelMessages } from '../llm/foundation.js';
import { streamChatCompletion } from '../llm/streamChat.js';
import { createClaimScanner } from './claimStream.js';
import { LLM_STREAM_IDLE_TIMEOUT_MS } from '../config/env.js';
import { modelFor } from '../llm/models.js';
import { LLM_REPORT_TIMEOUT_MS } from '../config/env.js';
import { SYSTEM_PROMPTS } from '../llm/prompts.js';
import { buildEvidenceIndex, evidenceForModel, fitEvidenceToBudget } from './evidenceIndex.js';
import { listingRequest } from './listing.js';
import { applySeverityFloor, rightNowMinSeverity } from './severityFloor.js';
import { storeEvidence } from './evidenceCache.js';
import { clarificationFor, priorClarification, CLARIFICATION_LEAD } from './clarify.js';
import {
    parseClaims, verifyClaims, renderGroundedReport, renderInsufficient, renderNoResults, renderSearchFailed, renderHeader, renderRecentRecords, SUMMARY_NOTES
} from './grounding.js';

// Central Tool Registration
import registry from '../llm/registry.js';
import { searchSecurityLogsTool } from '../tools/searchSecurityLogs.js';
import { getEndpointStatusTool } from '../tools/getEndpointStatus.js';
import { lookupThreatIntelTool } from '../tools/lookupThreatIntel.js';
import { searchMemoryTool } from '../tools/searchMemory.js';
import { checkProcessListTool } from '../tools/checkProcessList.js';
import { blockIpActionTool } from '../tools/blockIpAction.js';

// Memory Subsystem
import { memoryManager } from '../memory/manager.js';

// Run Records & Observability
import { RunModel } from '../models/Run.js';
import { SERVER_INSTANCE_ID } from '../observability/instance.js';
import { withRunScope, runLog, recordRunError, currentRunErrors } from '../observability/runContext.js';

// Register tools at runtime startup
registry.registerTool(searchSecurityLogsTool);
registry.registerTool(getEndpointStatusTool);
registry.registerTool(lookupThreatIntelTool);
registry.registerTool(searchMemoryTool);
// Read-only, and honest: returns "not available" until a process data source exists.
registry.registerTool(checkProcessListTool);
// Approval-gated: never offered to the planner, and refused by the gateway without a human approval.
registry.registerTool(blockIpActionTool);

/**
 * Where the report text came from. Only 'model' means the model wrote it.
 * - 'fallback_model_unavailable': the model call failed or returned nothing; the text is a fixed notice.
 * - 'fallback_unverifiable': the model answered, but none of its statements could be verified against
 *   the evidence (or its output wasn't the required JSON), so none is shown; the text is code-written.
 * - 'insufficient_evidence': the model said the evidence doesn't answer the question; code-written text.
 * - 'template_no_results': no matching data, so the model was not asked; the text is a fixed message.
 * - 'template_search_failed': every search failed, so the model was not asked; the text is a fixed message.
 */
export const REPORT_SOURCE = {
    MODEL: 'model',
    MODEL_UNAVAILABLE: 'fallback_model_unavailable',
    UNVERIFIABLE: 'fallback_unverifiable',
    STOPPED: 'stopped',
    INSUFFICIENT_EVIDENCE: 'insufficient_evidence',
    RECENT_RECORDS: 'template_recent_records',
    NO_RESULTS_TEMPLATE: 'template_no_results',
    SEARCH_FAILED: 'template_search_failed'
};

// The closing line of an answer written without the model (kept as an export for callers and tests).
export const MODEL_UNAVAILABLE_NOTICE = SUMMARY_NOTES.modelUnavailable;

function buildFooter(reportSource, plannerSource, durationMs, droppedClaims = 0, models = currentModels()) {
    const report = {
        [REPORT_SOURCE.MODEL]: `Analyzed by ${models.report}${models.planner !== models.report && plannerSource === 'model' ? ` | Planned by ${models.planner}` : ''}`,
        [REPORT_SOURCE.MODEL_UNAVAILABLE]: 'System summary: AI analysis unavailable',
        [REPORT_SOURCE.UNVERIFIABLE]: 'System summary: AI response withheld (not verifiable)',
        [REPORT_SOURCE.STOPPED]: 'Stopped before the analysis finished',
        [REPORT_SOURCE.INSUFFICIENT_EVIDENCE]: 'No model analysis: not enough evidence',
        [REPORT_SOURCE.RECENT_RECORDS]: 'Records listed by the system: no model analysis',
        [REPORT_SOURCE.NO_RESULTS_TEMPLATE]: 'No model analysis: no matching data',
        [REPORT_SOURCE.SEARCH_FAILED]: 'No model analysis: search failed'
    }[reportSource];
    const removed = droppedClaims > 0 && reportSource === REPORT_SOURCE.MODEL
        ? ` | ${droppedClaims} unsupported ${droppedClaims === 1 ? 'statement' : 'statements'} removed`
        : '';
    const plan = {
        fallback_rules: ' | Plan: rule-based fallback',
        fixture_replay: ' | Plan: replayed from fixture'
    }[plannerSource] ?? '';
    return `${report}${removed}${plan} | Runtime: ${durationMs}ms`;
}

/** Size limits for the report request (read per request, so they can be tuned without code changes). */
const positiveSetting = (name, fallback) => {
    const value = Number(process.env[name]);
    return Number.isFinite(value) && value > 0 ? value : fallback;
};
/** Total characters sent to the report model: system prompt, history and evidence (default 16,000, about 5,000 tokens). */
const reportPromptMaxChars = () => positiveSetting('REPORT_PROMPT_MAX_CHARS', 16000);
/** The longest report the model may write, in tokens (default 1,000), so request and answer fit together. */
const reportMaxTokens = () => positiveSetting('LLM_REPORT_MAX_TOKENS', 1000);
/** The report needs the evidence, not the conversation: the last two turns at most, each shortened. */
function boundedReportHistory(history = []) {
    return (Array.isArray(history) ? history : [])
        .filter(m => m && (m.role === 'user' || m.role === 'assistant') && typeof m.content === 'string')
        .slice(-2)
        .map(m => ({ role: m.role, content: m.content.length > 1000 ? `${m.content.slice(0, 997)}...` : m.content }));
}

/** The models this run uses, by role (Phase 6). Names only, never URLs or keys. */
const currentModels = () => ({ planner: modelFor('planner').model, report: modelFor('report').model });

export const THREAT_INTEL_ABSENT_NOTE = '**Threat Intelligence**: Not available. No threat intelligence source is configured, so no reputation data was consulted for this report.';
export const PROCESS_DATA_ABSENT_NOTE = '**Process inspection**: Not available. No endpoint process data source is connected, so no running processes were checked.';

// The note the runtime itself appends when a source had nothing to give. Not left to the model.
const ABSENT_NOTES = {
    lookupThreatIntel: THREAT_INTEL_ABSENT_NOTE,
    checkProcessList: PROCESS_DATA_ABSENT_NOTE
};

/**
 * Tool result metadata for the run record: what ran, with which parameters, the query actually sent,
 * and counts. Never the raw logs.
 */
function toolRunMetadata(result) {
    const meta = {
        tool: result.tool,
        parameters: result.parameters ?? null,
        success: result.success,
        executionTimeMs: result.executionTime,
        error: result.error
    };
    if (!result.success) return meta;

    const data = result.data || {};
    switch (result.tool) {
        case 'searchSecurityLogs':
            return {
                ...meta, totalHits: data.totalHits ?? null, returnedCount: data.rawData?.length ?? 0, targetIndex: data.targetIndex ?? null, query: data.query ?? null,
                // Counts only: whether exact counts were available, and the window totals.
                aggregations: data.aggregations ? {
                    available: data.aggregations.available,
                    error: data.aggregations.error ?? null,
                    currentTotal: data.aggregations.current?.total ?? null,
                    previousTotal: data.aggregations.previous?.total ?? null,
                    previousWindow: data.aggregations.previousWindow ?? null,
                    query: data.aggregationQuery ?? null
                } : null
            };
        case 'getEndpointStatus':
            return { ...meta, total: data.total ?? null, returnedCount: data.data?.length ?? 0, url: data.url ?? null, query: data.query ?? null };
        case 'lookupThreatIntel':
            return { ...meta, available: data.available === true, indicator: data.indicator ?? null, source: data.source ?? null, reason: data.reason ?? null };
        case 'searchMemory':
            return { ...meta, resultCount: Array.isArray(data) ? data.length : 0 };
        default:
            return { ...meta, dataKeys: Object.keys(data) };
    }
}

// A run-record write failure must not fail the analyst's request, but it must be loud.
function startRunRecord(run) {
    try {
        RunModel.start({ requestId: run.requestId, userId: run.userId, instanceId: SERVER_INSTANCE_ID, question: run.question, startedAt: new Date(run.startMs).toISOString() });
    } catch (error) {
        runLog.error(`[Run Record] Failed to create run record: ${error.message}`);
    }
}

function finishRunRecord(run, status) {
    try {
        const updated = RunModel.finish(run.requestId, {
            status,
            planner: run.planner,
            tools: run.context ? run.context.getEvidence().map(toolRunMetadata) : [],
            reportText: run.reportText,
            timings: run.telemetry,
            errors: currentRunErrors(),
            modelGenerated: run.modelGenerated,
            generation: run.generation,
            grounding: run.grounding,
            completedAt: new Date().toISOString()
        });
        if (updated !== 1) {
            runLog.error(`[Run Record] Run record was not updated to '${status}' (initial write likely failed).`);
        }
    } catch (error) {
        runLog.error(`[Run Record] Failed to finalize run record as '${status}': ${error.message}`);
    }
}

/**
 * Phase 4 AI Agent Runtime Coordinator
 * Implements two-stage LLM workflow: Planning & Reasoning, with structured observability and MEMORY LIFECYCLE.
 * Every execution is persisted to the `runs` table under its request ID, which also tags every console
 * line of the run ([req:<id>]) and is returned to the client as `request_id`.
 */
export async function runAgentWorkflow(text, history, userId = 'default_user_1', options = {}) {
    const requestId = randomUUID();
    return withRunScope(requestId, async () => {
        const run = {
            requestId,
            userId,
            question: text,
            startMs: Date.now(),
            // Per-stage timings in ms (Phase 5). null means the stage was not reached (or, for
            // reasoningDuration, that the model was not asked). reasoningDuration is the model call alone;
            // verificationDuration is everything else in the report stage (evidence index, claim checks, rendering).
            telemetry: {
                memoryRetrievalDuration: null,
                planningDuration: null,
                executionDuration: null,
                aggregationDuration: null,
                reasoningDuration: null,
                verificationDuration: null,
                totalDuration: null,
                reportPromptChars: null,
                tools: []
            },
            context: null,
            planner: null,
            reportText: null,
            modelGenerated: null,
            generation: null,
            grounding: null
        };

        // Written before any work, so a run that never finishes (e.g. a hung model call) stays visible as 'running'.
        startRunRecord(run);
        options.emit?.('meta', { request_id: requestId, mode: 'search' });
        try {
            const response = await runPipeline(run, text, history, options);
            finishRunRecord(run, 'completed');
            return response;
        } catch (error) {
            run.telemetry.totalDuration = Date.now() - run.startMs;
            recordRunError('runtime', error.message);
            runLog.error(`[Runtime Failed] RequestID: ${requestId} | ${error.message}`);
            finishRunRecord(run, 'failed');
            error.requestId = requestId;
            throw error;
        }
    }, { question: text });
}

/** A clarifying question as the whole answer (Phase 7): nothing planned or searched. */
function clarificationResponse(run, questionText, { source, modelGenerated }) {
    const text = `${CLARIFICATION_LEAD} ${questionText}`;
    run.planner = { ...(run.planner ?? {}), source, tools: [], clarification: questionText };
    run.reportText = text;
    run.modelGenerated = modelGenerated;
    run.generation = { planner: source, report: 'clarification', model: modelFor('report').model, models: currentModels() };
    run.telemetry.totalDuration = Date.now() - run.startMs;
    return { type: 'text', text, clarification: true, request_id: run.requestId, model_generated: modelGenerated, generation: run.generation };
}

/**
 * options.followUp: evidence from a previous search (evidenceCache entry). Planning and searching are
 * skipped; the report is written from that evidence and says so (Phase 7).
 */
async function runPipeline(run, text, history, options = {}) {
    const { requestId, userId, telemetry } = run;
    const context = new AgentContext(text, history, userId, requestId);
    run.context = context;
    const runStart = run.startMs;
    const followUp = options.followUp ?? null;
    // options.emit(event, data): streaming (Phase 7). Only things that are actually happening, or text
    // that has passed verification, are emitted.
    const emit = (event, data) => options.emit?.(event, data);
    // The reply to a clarification is combined with the question it answers, and never asked about again.
    const clarified = followUp ? null : priorClarification(history);
    const question = clarified ? `${clarified} (${text})` : text;
    let plannerSource;
    let plan;
    let executionPlan;

    if (followUp) {
        plannerSource = 'follow_up';
        plan = followUp.plan;
        executionPlan = followUp.results;
        run.planner = { source: 'follow_up', followUpOf: followUp.originalRequestId, question: followUp.question, thought: null, rawOutput: null, error: null, tools: plan };
        emit('stage', { stage: 'reading', label: 'Using the evidence from your previous search' });
        for (const result of followUp.results) context.addToolResult(structuredClone(result));
        telemetry.tools = followUp.results.map(r => ({ tool: r.tool, scope: r.parameters?.sourceScope ?? null, durationMs: 0, success: r.success, reused: true }));
    } else {

        // ==========================================
        // 0. Context Enrichment (Memory)
        // ==========================================
        const memoryStart = Date.now();
        const preMemories = await memoryManager.retrieve(userId, text);
        telemetry.memoryRetrievalDuration = Date.now() - memoryStart;
        const storedContext = {
            recent: preMemories.shortTerm.slice(0, 2).map(m => m.content),
            preferences: preMemories.longTerm.filter(m => m.category === 'preference').map(m => m.content)
        };
    
        if (!clarified) {
            const rule = clarificationFor(text);
            if (rule) return clarificationResponse(run, rule, { source: 'clarification_rule', modelGenerated: false });
        }

        // ==========================================
        // 1. LLM Planning Phase
        // ==========================================
        emit('stage', { stage: 'planning', label: 'Planning the search' });
        const planStart = Date.now();
        // Memories are passed as data inside the planner's user prompt, never with system authority (F-20).
        const planResult = await generateLLMPlan(question, context.conversationHistory, { storedContext });
        ({ tools: plan, source: plannerSource } = planResult);
        run.planner = {
            source: plannerSource,
            thought: planResult.thought,
            rawOutput: planResult.rawOutput,
            error: planResult.error,
            tools: plan,
            replayedFrom: planResult.replayedFrom ?? null,
            promptChars: planResult.promptChars ?? null,
            promptTrimmed: planResult.promptTrimmed ?? []
        };
        telemetry.plannerPromptChars = planResult.promptChars ?? null;
        telemetry.planningDuration = Date.now() - planStart;
        if (planResult.clarification && !clarified && plan.length === 0) {
            return clarificationResponse(run, planResult.clarification, { source: plannerSource, modelGenerated: true });
        }

        if (plan.length === 0) {
            const noPlanText = 'I could not determine how to help with that request based on my available tools.';
            telemetry.totalDuration = Date.now() - runStart;
            run.reportText = noPlanText;
            run.modelGenerated = false;
            run.generation = { planner: plannerSource, report: null, model: modelFor('report').model, models: currentModels() };
            return {
                type: 'text',
                text: noPlanText,
                request_id: requestId,
                model_generated: false,
                generation: run.generation
            };
        }

        // "Right now" questions search only what matters, unless the analyst asked for a level (Phase 5).
        const floorLevel = rightNowMinSeverity();
        const flooredPlan = applySeverityFloor(plan, question, floorLevel);
        run.planner.severityFloor = flooredPlan.some((instruction, i) => instruction !== plan[i]) ? { level: floorLevel, applied: true } : null;

        // Every security log search includes Wazuh and Firewall evidence. Their
        // scopes are mutually exclusive, so records are never counted twice.
        const logScopes = ['non_firewall', 'firewall'];
        // Vulnerability searches are not split: firewall records never carry CVE data.
        executionPlan = flooredPlan.flatMap(instruction => {
            if (instruction.tool !== 'searchSecurityLogs') return instruction;
            if (instruction.parameters?.intent === 'vulnerabilities') return instruction;
            return logScopes.map(sourceScope => ({
                ...instruction,
                parameters: { ...instruction.parameters, sourceScope }
            }));
        });

        // ==========================================
        // 2. Execution Phase
        // ==========================================
        const searchCount = executionPlan.filter(i => i.tool === 'searchSecurityLogs').length;
        const otherTools = [...new Set(executionPlan.filter(i => i.tool !== 'searchSecurityLogs').map(i => ({ getEndpointStatus: 'agent status', lookupThreatIntel: 'threat intelligence', checkProcessList: 'process data', searchMemory: 'past investigations' }[i.tool] ?? i.tool)))];
        const searchParts = [searchCount ? `Wazuh alerts and firewall events (${searchCount} ${searchCount === 1 ? 'query' : 'queries'})` : null, ...otherTools].filter(Boolean);
        emit('stage', { stage: 'searching', label: `Searching ${searchParts.join(', ')}` });
        const execStart = Date.now();
        await executePlan(executionPlan, context);
        telemetry.executionDuration = Date.now() - execStart;
        telemetry.tools = [...context.getEvidence()]
            .sort((a, b) => (a.planIndex ?? 0) - (b.planIndex ?? 0))
            .map(r => ({ tool: r.tool, scope: r.parameters?.sourceScope ?? null, durationMs: r.executionTime ?? null, success: r.success }));
    }

    // ==========================================
    // 3. Evidence Aggregation Phase
    // ==========================================
    const aggStart = Date.now();
    const rawEvidence = context.getEvidence();
    
    const structuredEvidence = {
        summary: {
            toolsExecuted: executionPlan.length,
            successful: rawEvidence.filter(e => e.success).length,
            failed: rawEvidence.filter(e => !e.success).length
        },
        evidence: {},
        // Sources that were asked but have no data to give. Listed so the model knows
        // they are absent; never placed under `evidence`.
        unavailableSources: [],
        errors: context.errors
    };

    let totalHits = 0;
    let sourceLabel = 'agent-runtime';
    const sourceLabels = new Set();
    const sourceTotals = {};

    // Raw logs keyed per tool invocation, in plan order: 'searchSecurityLogs', 'getEndpointStatus',
    // 'searchSecurityLogs#2' for a second call to the same tool, and a ':firewall' suffix for the
    // firewall half of a search. Every tool's logs are kept; empty result sets are not listed
    // (their counts are in the run record).
    const rawLogsByTool = {};
    const invocationCounts = {};
    const addRawLogs = (tool, logs, scope) => {
        const suffix = scope === 'firewall' ? ':firewall' : '';
        const counter = tool + suffix;
        invocationCounts[counter] = (invocationCounts[counter] || 0) + 1;
        const n = invocationCounts[counter];
        if (logs.length > 0) rawLogsByTool[n === 1 ? counter : `${tool}#${n}${suffix}`] = logs;
    };

    // Evidence for the model is keyed per tool call too (F-29): 'searchSecurityLogs',
    // 'searchSecurityLogs#2', 'firewallLogs', 'firewallLogs#2', … so no call overwrites another.
    const evidenceCounts = {};
    const evidenceKey = base => {
        evidenceCounts[base] = (evidenceCounts[base] || 0) + 1;
        return evidenceCounts[base] === 1 ? base : `${base}#${evidenceCounts[base]}`;
    };

    const inPlanOrder = [...rawEvidence].sort((a, b) => (a.planIndex ?? 0) - (b.planIndex ?? 0));
    // Kept briefly so a follow-up can be answered from this evidence (Phase 7). A follow-up keeps
    // pointing at the original search.
    if (followUp) storeEvidence(requestId, followUp);
    else if (inPlanOrder.some(r => r.tool === 'searchSecurityLogs' || r.tool === 'getEndpointStatus')) {
        storeEvidence(requestId, { userId, question, results: inPlanOrder, plan, searchedAt: new Date(runStart).toISOString(), originalRequestId: requestId });
    }
    for (const result of inPlanOrder) {
        if (!result.success) continue;

        if (result.tool === 'getEndpointStatus') {
            totalHits += result.data.total || 0;
            addRawLogs(result.tool, result.data.data || []);
            sourceLabels.add('Wazuh Agents');
            structuredEvidence.evidence[evidenceKey(result.tool)] = {
                total: result.data.total,
                data: result.data.data
            };
        } 
        else if (result.tool === 'searchSecurityLogs') {
            totalHits += result.data.totalHits || 0;
            addRawLogs(result.tool, result.data.rawData || [], result.data.sourceScope);
            const searchKey = evidenceKey(result.data.sourceScope === 'firewall' ? 'firewallLogs' : 'searchSecurityLogs');
            const sourceName = result.data.sourceScope === 'firewall' ? 'Firewall (Wazuh)' : 'Wazuh';
            sourceLabels.add(sourceName);
            sourceTotals[sourceName] = (sourceTotals[sourceName] || 0) + (result.data.totalHits || 0);

            const minifiedLogs = (result.data.rawData || []).slice(0, 30).map(log => ({
                time: log['@timestamp'] || log.vulnerability?.detected_at || 'N/A',
                level: typeof log.rule?.level === 'number' ? log.rule.level : log.vulnerability?.severity || 0,
                desc: log.rule?.description || log.vulnerability?.description || 'N/A',
                srcip: log.data?.srcip || log.srcip || log.agent?.ip || 'N/A',
                user: log.data?.srcuser || log.data?.dstuser || log.data?.user || 'N/A',
                agent: log.agent?.name || log.agent?.id || 'N/A',
                cve: log.vulnerability?.id || 'N/A'
            }));

            structuredEvidence.evidence[searchKey] = {
                totalMatches: result.data.totalHits,
                sampleSize: minifiedLogs.length,
                sampleLogs: minifiedLogs
            };
        }
        else if (result.data?.available === false) {
            // A source with nothing to give (threat intel, process inspection): listed so the model
            // knows it is absent, never placed under `evidence`.
            structuredEvidence.unavailableSources.push({
                tool: result.tool,
                indicator: result.data.indicator ?? result.data.endpointId ?? null,
                reason: result.data.reason || 'Not available.'
            });
        }
        else if (result.tool === 'lookupThreatIntel' || result.tool === 'checkProcessList') {
            // Only a real provider response (available: true) counts as evidence.
            if (result.data?.available === true) structuredEvidence.evidence[result.tool] = result.data;
        }
        else if (result.tool === 'searchMemory') {
            structuredEvidence.evidence[result.tool] = result.data;
        }
    }
    // A tool that ran but had no data to give is not a successful source of evidence.
    structuredEvidence.summary.unavailable = structuredEvidence.unavailableSources.length;
    structuredEvidence.summary.successful -= structuredEvidence.summary.unavailable;
    const absentTools = [...new Set(structuredEvidence.unavailableSources.map(s => s.tool))];
    const sourceAbsent = absentTools.length > 0;
    structuredEvidence.summary.totalMatches = totalHits;
    structuredEvidence.summary.sourceTotals = sourceTotals;
    if (sourceLabels.size > 0) sourceLabel = [...sourceLabels].join(' + ');
    telemetry.aggregationDuration = Date.now() - aggStart;

    // ==========================================
    // 4. LLM Reasoning Phase (grounded: claims with citations, verified in code before rendering)
    // ==========================================
    const reasonStart = Date.now();
    const index = buildEvidenceIndex(inPlanOrder);
    const listing = listingRequest(question);
    let finalSummary = '';
    let reportSource;
    const followUpLine = followUp
        ? `**Answered from the evidence of your previous search** ("${followUp.question}"${followUp.searchedAt ? ` at ${followUp.searchedAt.slice(11, 16)} UTC` : ''}). Nothing new was searched; ask me to search again for fresh data.`
        : null;
    const withPrefix = markdown => (followUpLine ? `${followUpLine}\n\n${markdown}` : markdown);
    // The code-written header can be shown as soon as the evidence is in, before any model answers.
    emit('report', { markdown: withPrefix(renderHeader(index)) });
    const hasOtherEvidence = Boolean(structuredEvidence.evidence.lookupThreatIntel || structuredEvidence.evidence.checkProcessList || index.memories.length);

    if (totalHits === 0 && !hasOtherEvidence && index.anySearchRan && !index.anySearchSucceeded) {
        finalSummary = renderSearchFailed(index);
        reportSource = REPORT_SOURCE.SEARCH_FAILED;
    } else if (totalHits === 0 && !hasOtherEvidence && (structuredEvidence.summary.successful > 0 || sourceAbsent)) {
        finalSummary = renderNoResults(index);
        reportSource = REPORT_SOURCE.NO_RESULTS_TEMPLATE;
    } else if (listing && totalHits > 0 && index.anySearchSucceeded) {
        // "The N most recent logs": listed by the code from the records retrieved (F-68).
        finalSummary = renderRecentRecords(index, listing.count);
        reportSource = REPORT_SOURCE.RECENT_RECORDS;
    } else {
        // Keep the request within what the model accepts, whatever the volume (fixes 2-4): compact JSON,
        // at most the last two chat turns, shortened, and a hard size limit that trims the evidence.
        const reportHistory = boundedReportHistory(context.conversationHistory);
        const fixedChars = SYSTEM_PROMPTS.AGENT_REASONING_PROMPT.length + reportHistory.reduce((n, m) => n + m.content.length, 0)
            + `User Request: "${question}"\n\nEvidence JSON:\n`.length;
        const fitted = fitEvidenceToBudget(evidenceForModel(index), reportPromptMaxChars() - fixedChars);
        const modelEvidence = fitted.evidence;
        const reasoningPrompt = `User Request: "${question}"\n\nEvidence JSON:\n${JSON.stringify(modelEvidence)}`;
        telemetry.reportPromptChars = fixedChars - `User Request: "${question}"\n\nEvidence JSON:\n`.length + reasoningPrompt.length;
        telemetry.reportPromptTrimmed = fitted.trimmed;
        if (fitted.trimmed.length) runLog.info(`[Report] Evidence trimmed to fit ${reportPromptMaxChars()} characters: ${fitted.trimmed.join('; ')}`);
        emit('stage', { stage: 'analysing', label: `${modelFor('report').model} is analysing ${index.totalMatches.toLocaleString('en-US')} ${index.totalMatches === 1 ? 'match' : 'matches'}` });
        const modelStart = Date.now();
        let rawReport = null;
        let stopped = false;
        if (options.emit) {
            // Streamed: each claim is verified as soon as its JSON object is complete, and only a claim
            // that passes is shown. The final answer below is still rebuilt from the complete output.
            const keptSoFar = { answer: [], findings: [], assessment: [], next_steps: [] };
            let insufficientSeen = false;
            const scanner = createClaimScanner({
                onInsufficient: () => { insufficientSeen = true; },
                onClaim: (section, claim) => {
                    if (insufficientSeen) return;
                    const { kept } = verifyClaims({ [section]: [claim] }, index, modelEvidence);
                    if (kept[section].length === 0) return;
                    keptSoFar[section].push(kept[section][0]);
                    emit('report', { markdown: withPrefix(renderGroundedReport(index, keptSoFar)) });
                }
            });
            try {
                const result = await streamChatCompletion({
                    messages: buildModelMessages(reasoningPrompt, SYSTEM_PROMPTS.AGENT_REASONING_PROMPT, reportHistory),
                    maxTokens: reportMaxTokens(),
                    role: 'report',
                    signal: options.signal,
                    firstTokenTimeoutMs: LLM_REPORT_TIMEOUT_MS,
                    idleTimeoutMs: LLM_STREAM_IDLE_TIMEOUT_MS,
                    totalTimeoutMs: LLM_REPORT_TIMEOUT_MS,
                    onToken: piece => scanner.push(piece)
                });
                rawReport = result.text?.trim() || null;
            } catch (error) {
                stopped = error.code === 'aborted';
                recordRunError(stopped ? 'client' : 'llm', error.message);
                runLog.warn(`[Report] Model stream ${stopped ? 'stopped by the client' : `failed (${error.code})`}: ${error.message}`);
            }
        } else {
            rawReport = await askFoundation(reasoningPrompt, SYSTEM_PROMPTS.AGENT_REASONING_PROMPT, reportHistory, { timeout: LLM_REPORT_TIMEOUT_MS, role: 'report', maxTokens: reportMaxTokens() });
        }
        telemetry.reasoningDuration = Date.now() - modelStart;
        emit('stage', { stage: 'verifying', label: 'Checking every statement against the evidence' });

        if (stopped) {
            finalSummary = `${renderHeader(index)}\n\n**Stopped** before the analysis finished. Nothing the model wrote was checked, so none of it is shown.`;
            reportSource = REPORT_SOURCE.STOPPED;
        } else if (!rawReport) {
            finalSummary = renderInsufficient(index, null, SUMMARY_NOTES.modelUnavailable);
            reportSource = REPORT_SOURCE.MODEL_UNAVAILABLE;
        } else {
            const parsed = parseClaims(rawReport);
            if (!parsed.ok) {
                run.grounding = { claims: 0, shown: 0, dropped: [], parseError: parsed.error, rawOutput: rawReport.slice(0, 4000) };
                runLog.warn(`[Grounding] Model output is not the required JSON (${parsed.error}); nothing it wrote is shown.`);
                finalSummary = renderInsufficient(index, null, SUMMARY_NOTES.withheld);
                reportSource = REPORT_SOURCE.UNVERIFIABLE;
            } else {
                const { kept, dropped, total } = verifyClaims(parsed.claims, index, modelEvidence);
                const shown = Object.values(kept).reduce((n, list) => n + list.length, 0);
                run.grounding = { claims: total, shown: parsed.insufficient ? 0 : shown, dropped, insufficientEvidence: parsed.insufficient, rawOutput: rawReport.slice(0, 4000) };
                for (const d of dropped) runLog.warn(`[Grounding] Dropped ${d.section} claim: ${d.reason}`);

                if (parsed.insufficient) {
                    finalSummary = renderInsufficient(index, '**Not enough evidence** in these results to answer the question.');
                    reportSource = REPORT_SOURCE.INSUFFICIENT_EVIDENCE;
                } else if (shown === 0) {
                    finalSummary = renderInsufficient(index, null, SUMMARY_NOTES.withheld);
                    reportSource = REPORT_SOURCE.UNVERIFIABLE;
                } else {
                    finalSummary = renderGroundedReport(index, kept);
                    reportSource = REPORT_SOURCE.MODEL;
                }
            }
        }
    }
    finalSummary = withPrefix(finalSummary);
    // Stated by the runtime, not left to the model, so each absence is always visible.

    for (const tool of absentTools) {
        finalSummary += `\n\n${ABSENT_NOTES[tool] ?? `**${tool}**: Not available.`}`;
    }
    telemetry.verificationDuration = Date.now() - reasonStart - (telemetry.reasoningDuration ?? 0);

    // ==========================================
    // 5. Memory Write (Automatic Runtime Policy)
    // ==========================================
    // If the investigation yielded results, we summarize and save it to memory in the background
    if (totalHits > 0 || structuredEvidence.evidence.lookupThreatIntel || structuredEvidence.evidence.searchMemory) {
        memoryManager.summarize(text, finalSummary, structuredEvidence).then(async (summaryJsonStr) => {
            try {
                // The summarizer returns a string, we want to store it as JSON if possible
                let content = JSON.parse(summaryJsonStr);
                await memoryManager.write(userId, 'investigation', content, { isImportant: true });
            } catch(e) {
                // Fallback to storing raw string
                await memoryManager.write(userId, 'investigation', { summary: summaryJsonStr, keyEntities: [] }, { isImportant: false });
            }
        }).catch(err => runLog.error("[Memory Summarization Failed]", err));
    } else {
        // Just store short term interaction
        memoryManager.write(userId, 'conversation', { user: text, bot: finalSummary }, { isImportant: false })
            .catch(err => runLog.error('[Memory Write Failed]', err.message)); // F-12: never an unhandled rejection
    }

    // ==========================================
    // 6. Finalize & Telemetry
    // ==========================================
    telemetry.totalDuration = Date.now() - runStart;
    
    const modelGenerated = reportSource === REPORT_SOURCE.MODEL;

    run.reportText = finalSummary;
    run.modelGenerated = modelGenerated;
    run.generation = { planner: plannerSource, report: reportSource, model: modelFor('report').model, models: currentModels() };

    runLog.info(`[Runtime Complete] RequestID: ${context.requestId} | planner=${plannerSource} report=${reportSource} model_generated=${modelGenerated}`);
    runLog.info(`[Telemetry] Memory: ${telemetry.memoryRetrievalDuration}ms | Plan: ${telemetry.planningDuration}ms | Exec: ${telemetry.executionDuration}ms | Agg: ${telemetry.aggregationDuration}ms | Model: ${telemetry.reasoningDuration ?? '-'}ms | Verify: ${telemetry.verificationDuration}ms | Total: ${telemetry.totalDuration}ms | Prompt: ${telemetry.reportPromptChars ?? '-'} chars`);

    return {
        type: 'agent_response',
        request_id: requestId,
        follow_up_of: followUp?.originalRequestId ?? null,
        source: sourceLabel,
        summary: finalSummary,
        raw_logs: rawLogsByTool,
        total_hits: totalHits,
        // Machine-readable provenance: model_generated is true only when the model wrote the report text.
        model_generated: modelGenerated,
        generation: run.generation,
        // Counts only: dropped claims are kept in the run record, never sent to the client.
        grounding: run.grounding ? { claims: run.grounding.claims, shown: run.grounding.shown, dropped: run.grounding.dropped.length } : null,
        footer: buildFooter(reportSource, plannerSource, telemetry.totalDuration, run.grounding?.dropped.length ?? 0)
    };
}
