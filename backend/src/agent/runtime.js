import { AgentContext } from './context.js';
import { generateExecutionPlan } from './planner.js';
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
 * AI Agent Runtime Coordinator
 * Coordinates the entire execution flow from receiving a request to returning the human-readable response.
 */
export async function runAgentWorkflow(text, history) {
    // 1. Initialize Context
    const context = new AgentContext(text, history);

    // 2. Planning Phase
    const plan = generateExecutionPlan(text);
    
    if (plan.length === 0) {
        return {
            type: 'text',
            text: 'I could not determine how to help with that request based on my available tools.'
        };
    }

    // 3. Execution Phase
    await executePlan(plan, context);

    // 4. Evidence Aggregation Phase
    const evidence = context.getEvidence();
    
    // Analyze results to determine what to send to the LLM
    let sourceLabel = 'agent-runtime';
    let totalHits = 0;
    let rawLogs = [];
    let summaryPrompt = `User asked: "${text}"\n\n`;
    
    // Aggregate data from all executed tools
    let usedSystemPrompt = SYSTEM_PROMPTS.STRICT_FACTUAL_RAG; // Default
    
    for (const result of evidence) {
        if (!result.success) {
            summaryPrompt += `TOOL FAILURE (${result.tool}): ${result.error}\n\n`;
            continue;
        }

        if (result.tool === 'getEndpointStatus') {
            totalHits += result.data.total;
            rawLogs = result.data.data;
            sourceLabel = result.data.url;
            usedSystemPrompt = SYSTEM_PROMPTS.WAZUH_SERVER_API;
            
            summaryPrompt += `TOOL EVIDENCE (${result.tool}):\nTOTAL RESULTS: ${result.data.total}\nDATA:\n${JSON.stringify(rawLogs)}\n\n`;
        } 
        else if (result.tool === 'searchSecurityLogs') {
            totalHits += result.data.totalHits;
            rawLogs = result.data.rawData;
            sourceLabel = result.data.targetIndex;

            // Minify logs according to schema
            const minifiedLogs = rawLogs.slice(0, 50).map(log => ({
                time: log['@timestamp'] || log.vulnerability?.detected_at || 'N/A',
                level: typeof log.rule?.level === 'number' ? log.rule.level : log.vulnerability?.severity || 0,
                desc: log.rule?.description || log.vulnerability?.description || 'N/A',
                srcip: log.data?.srcip || log.srcip || log.agent?.ip || 'N/A',
                user: log.data?.srcuser || log.data?.dstuser || log.data?.user || 'N/A',
                agent: log.agent?.name || log.agent?.id || 'N/A',
                cve: log.vulnerability?.id || 'N/A'
            }));

            summaryPrompt += `TOOL EVIDENCE (${result.tool}):\nTOTAL MATCHES: ${result.data.totalHits}\nSAMPLE LOGS (TOP ${minifiedLogs.length}):\n${JSON.stringify(minifiedLogs)}\n\n`;
        }
        else if (result.tool === 'lookupThreatIntel') {
            summaryPrompt += `TOOL EVIDENCE (${result.tool}):\nDATA:\n${JSON.stringify(result.data)}\n\n`;
        }
    }

    // 5. LLM Reasoning Phase
    let finalSummary = '';
    
    if (totalHits === 0 && evidence.some(e => e.tool === 'searchSecurityLogs')) {
        finalSummary = `I searched the database and intelligence sources, but found zero matching alerts or data for your query.`;
    } else {
        // Only run LLM if we actually got some hits or if there was a specific response
        const llamaSummary = await askFoundation(summaryPrompt, usedSystemPrompt, history);
        finalSummary = llamaSummary || `Successfully retrieved ${totalHits} records. Click "View Full Details" to see the raw JSON logs.`;
    }

    console.log(`[Runtime Complete] RequestID: ${context.requestId} | Duration: ${context.getDuration()}ms`);

    // 6. Return standard structured response to Frontend
    return {
        type: 'agent_response',
        source: sourceLabel,
        summary: finalSummary,
        raw_logs: rawLogs,
        total_hits: totalHits,
        footer: `Analyzed by foundation-sec-8b | Runtime: ${context.getDuration()}ms`
    };
}
