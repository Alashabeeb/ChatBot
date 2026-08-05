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

// Register tools at runtime startup
registry.registerTool(searchSecurityLogsTool);
registry.registerTool(getEndpointStatusTool);
registry.registerTool(lookupThreatIntelTool);

/**
 * Phase 3 AI Agent Runtime Coordinator
 * Implements two-stage LLM workflow: Planning & Reasoning, with structured observability.
 */
export async function runAgentWorkflow(text, history) {
    const context = new AgentContext(text, history);
    const telemetry = {
        planningDuration: 0,
        executionDuration: 0,
        aggregationDuration: 0,
        reasoningDuration: 0,
        totalDuration: 0
    };

    const runStart = Date.now();

    // ==========================================
    // 1. LLM Planning Phase
    // ==========================================
    const planStart = Date.now();
    const plan = await generateLLMPlan(text, context.conversationHistory);
    telemetry.planningDuration = Date.now() - planStart;
    
    if (plan.length === 0) {
        return {
            type: 'text',
            text: 'I could not determine how to help with that request based on my available tools.'
        };
    }

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

    for (const result of rawEvidence) {
        if (!result.success) continue;

        if (result.tool === 'getEndpointStatus') {
            totalHits += result.data.total || 0;
            rawLogsToReturn = result.data.data || [];
            sourceLabel = result.data.url || sourceLabel;
            structuredEvidence.evidence[result.tool] = {
                total: result.data.total,
                data: result.data.data
            };
        } 
        else if (result.tool === 'searchSecurityLogs') {
            totalHits += result.data.totalHits || 0;
            rawLogsToReturn = result.data.rawData || [];
            sourceLabel = result.data.targetIndex || sourceLabel;

            // Minify logs according to schema to fit context window
            const minifiedLogs = (result.data.rawData || []).slice(0, 30).map(log => ({
                time: log['@timestamp'] || log.vulnerability?.detected_at || 'N/A',
                level: typeof log.rule?.level === 'number' ? log.rule.level : log.vulnerability?.severity || 0,
                desc: log.rule?.description || log.vulnerability?.description || 'N/A',
                srcip: log.data?.srcip || log.srcip || log.agent?.ip || 'N/A',
                user: log.data?.srcuser || log.data?.dstuser || log.data?.user || 'N/A',
                agent: log.agent?.name || log.agent?.id || 'N/A',
                cve: log.vulnerability?.id || 'N/A'
            }));

            structuredEvidence.evidence[result.tool] = {
                totalMatches: result.data.totalHits,
                sampleLogs: minifiedLogs
            };
        }
        else if (result.tool === 'lookupThreatIntel') {
            structuredEvidence.evidence[result.tool] = result.data;
        }
    }
    telemetry.aggregationDuration = Date.now() - aggStart;

    // ==========================================
    // 4. LLM Reasoning Phase
    // ==========================================
    const reasonStart = Date.now();
    let finalSummary = '';
    
    if (totalHits === 0 && structuredEvidence.summary.successful > 0 && !structuredEvidence.evidence.lookupThreatIntel) {
        finalSummary = `I searched the database and intelligence sources, but found zero matching alerts or data for your query.`;
    } else {
        const reasoningPrompt = `User Request: "${text}"\n\nStructured Evidence JSON:\n${JSON.stringify(structuredEvidence, null, 2)}`;
        
        const llamaSummary = await askFoundation(reasoningPrompt, SYSTEM_PROMPTS.AGENT_REASONING_PROMPT, context.conversationHistory);
        finalSummary = llamaSummary || `Successfully retrieved ${totalHits} records. Click "View Full Details" to see the raw JSON logs.`;
    }
    telemetry.reasoningDuration = Date.now() - reasonStart;

    // ==========================================
    // 5. Finalize & Telemetry
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
