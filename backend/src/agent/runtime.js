import { AgentContext } from './context.js';
import { generateLLMPlan } from './planner.js';
import { executePlan } from './executor.js';
import { askFoundation } from '../llm/foundation.js';
import { SYSTEM_PROMPTS } from '../llm/prompts.js';

// Central Tool Registration
import registry from '../llm/registry.js';
import { searchSecurityLogsTool } from '../tools/searchSecurityLogs.js';
import { getEndpointStatusTool } from '../tools/getEndpointStatus.js';
import { lookupThreatIntelTool } from '../tools/lookupThreatIntel.js';
import { searchMemoryTool } from '../tools/searchMemory.js';

// Memory Subsystem
import { memoryManager } from '../memory/manager.js';

// Register tools at runtime startup
registry.registerTool(searchSecurityLogsTool);
registry.registerTool(getEndpointStatusTool);
registry.registerTool(lookupThreatIntelTool);
registry.registerTool(searchMemoryTool);

// HOTFIX: blockIpAction and checkProcessList are NOT registered. Both return fabricated
// results (a fake "IP blocked" confirmation; a hard-coded process list containing
// "unknown_miner") that would reach the analyst as evidence. Do not register them until they
// call a real system, and never let the planner trigger a blocking action on its own.

/**
 * Phase 4 AI Agent Runtime Coordinator
 * Implements two-stage LLM workflow: Planning & Reasoning, with structured observability and MEMORY LIFECYCLE.
 */
export async function runAgentWorkflow(text, history, userId = 'default_user_1') {
    const context = new AgentContext(text, history, userId);
    const telemetry = {
        planningDuration: 0,
        executionDuration: 0,
        aggregationDuration: 0,
        reasoningDuration: 0,
        totalDuration: 0
    };

    const runStart = Date.now();

    // ==========================================
    // 0. Context Enrichment (Memory)
    // ==========================================
    const preMemories = await memoryManager.retrieve(userId, text);
    const preContextStr = `Recent Context: ${JSON.stringify(preMemories.shortTerm.slice(0,2))}\nPreferences: ${JSON.stringify(preMemories.longTerm.filter(m => m.category === 'preference'))}`;
    
    // ==========================================
    // 1. LLM Planning Phase
    // ==========================================
    const planStart = Date.now();
    // Pass the preContextStr as part of the history context for the planner
    const enrichedHistory = [...context.conversationHistory, { role: "system", content: preContextStr }];
    let plan = await generateLLMPlan(text, enrichedHistory);
    telemetry.planningDuration = Date.now() - planStart;
    
    if (plan.length === 0) {
        return {
            type: 'text',
            text: 'I could not determine how to help with that request based on my available tools.'
        };
    }

    // Every security log search includes Wazuh and Firewall evidence. Their
    // scopes are mutually exclusive, so records are never counted twice.
    const logScopes = ['non_firewall', 'firewall'];

    plan = plan.flatMap(instruction => {
        if (instruction.tool !== 'searchSecurityLogs') return instruction;
        return logScopes.map(sourceScope => ({
            ...instruction,
            parameters: { ...instruction.parameters, sourceScope }
        }));
    });

    // ==========================================
    // 2. Execution Phase
    // ==========================================
    const execStart = Date.now();
    await executePlan(plan, context);
    telemetry.executionDuration = Date.now() - execStart;

    // ==========================================
    // 3. Evidence Aggregation Phase
    // ==========================================
    const aggStart = Date.now();
    const rawEvidence = context.getEvidence();
    
    const structuredEvidence = {
        summary: {
            toolsExecuted: plan.length,
            successful: rawEvidence.filter(e => e.success).length,
            failed: rawEvidence.filter(e => !e.success).length
        },
        evidence: {},
        errors: context.errors
    };

    let totalHits = 0;
    let rawLogsToReturn = [];
    let sourceLabel = 'agent-runtime';
    const sourceLabels = new Set();
    const sourceTotals = {};

    for (const result of rawEvidence) {
        if (!result.success) continue;

        if (result.tool === 'getEndpointStatus') {
            totalHits += result.data.total || 0;
            rawLogsToReturn = result.data.data || [];
            sourceLabels.add('Wazuh Agents');
            structuredEvidence.evidence[result.tool] = {
                total: result.data.total,
                data: result.data.data
            };
        } 
        else if (result.tool === 'searchSecurityLogs') {
            totalHits += result.data.totalHits || 0;
            rawLogsToReturn = [...rawLogsToReturn, ...(result.data.rawData || [])];
            const evidenceKey = result.data.sourceScope === 'firewall'
                ? 'firewallLogs'
                : 'searchSecurityLogs';
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

            structuredEvidence.evidence[evidenceKey] = {
                totalMatches: result.data.totalHits,
                sampleSize: minifiedLogs.length,
                sampleLogs: minifiedLogs
            };
        }
        else if (result.tool === 'lookupThreatIntel' || result.tool === 'searchMemory' || result.tool === 'blockIpAction' || result.tool === 'checkProcessList') {
            structuredEvidence.evidence[result.tool] = result.data;
        }
    }
    structuredEvidence.summary.totalMatches = totalHits;
    structuredEvidence.summary.sourceTotals = sourceTotals;
    if (sourceLabels.size > 0) sourceLabel = [...sourceLabels].join(' + ');
    telemetry.aggregationDuration = Date.now() - aggStart;

    // ==========================================
    // 4. LLM Reasoning Phase
    // ==========================================
    const reasonStart = Date.now();
    let finalSummary = '';
    
    if (totalHits === 0 && structuredEvidence.summary.successful > 0 && !structuredEvidence.evidence.lookupThreatIntel && !structuredEvidence.evidence.searchMemory && !structuredEvidence.evidence.blockIpAction && !structuredEvidence.evidence.checkProcessList) {
        finalSummary = `I searched the database and intelligence sources, but found zero matching alerts or data for your query.`;
    } else {
        const reasoningPrompt = `User Request: "${text}"\n\nStructured Evidence JSON:\n${JSON.stringify(structuredEvidence, null, 2)}`;
        
        const llamaSummary = await askFoundation(reasoningPrompt, SYSTEM_PROMPTS.AGENT_REASONING_PROMPT, context.conversationHistory);
        finalSummary = llamaSummary || `Successfully retrieved records. Click "View Full Details" to see the raw JSON logs.`;
    }
    telemetry.reasoningDuration = Date.now() - reasonStart;

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
        }).catch(err => console.error("[Memory Summarization Failed]", err));
    } else {
        // Just store short term interaction
        memoryManager.write(userId, 'conversation', { user: text, bot: finalSummary }, { isImportant: false });
    }

    // ==========================================
    // 6. Finalize & Telemetry
    // ==========================================
    telemetry.totalDuration = Date.now() - runStart;
    
    console.log(`[Runtime Complete] RequestID: ${context.requestId}`);
    console.log(`[Telemetry] Plan: ${telemetry.planningDuration}ms | Exec: ${telemetry.executionDuration}ms | Agg: ${telemetry.aggregationDuration}ms | Reason: ${telemetry.reasoningDuration}ms | Total: ${telemetry.totalDuration}ms`);

    return {
        type: 'agent_response',
        source: sourceLabel,
        summary: finalSummary,
        raw_logs: rawLogsToReturn,
        total_hits: totalHits,
        footer: `Analyzed by foundation-sec-8b | Runtime: ${telemetry.totalDuration}ms`
    };
}
