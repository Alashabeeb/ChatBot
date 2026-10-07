import {
    extractLegacyIntent,
    extractIPs,
    extractSeverity,
    extractTimeRange,
    cleanSearchQuery
} from '../utils/parser.util.js';
import { askFoundation, extractJSON } from '../llm/foundation.js';
import { SYSTEM_PROMPTS } from '../llm/prompts.js';
import registry from '../llm/registry.js';
import { validateExecutionPlan } from '../schemas/ExecutionPlan.schema.js';
import { runLog, recordRunError } from '../observability/runContext.js';
import { fixturesEnabled, replayPlan } from '../recording/replay.js';

/**
 * Phase 3 LLM-Driven Planner
 * Interacts with Foundation-sec-8B to dynamically generate an execution plan.
 * Returns { tools, source, thought, rawOutput, error }: source is 'model' or 'fallback_rules' (legacy planner used),
 * rawOutput is the model's unparsed reply (null if none), error is why the model plan was rejected.
 * With FIXTURES=1 the plan recorded at capture is returned instead (source 'fixture_replay'), so the
 * queries built downstream are the same on every run.
 */
export async function generateLLMPlan(text, history = []) {
    if (fixturesEnabled()) {
        return replayPlan(text);
    }

    let llmResponse = null;
    try {
        const availableTools = registry.listTools();
        const toolsContext = JSON.stringify(availableTools, null, 2);
        
        const prompt = `User Request: "${text}"\n\nAvailable Tools:\n${toolsContext}\n\nGenerate the execution plan.`;
        
        llmResponse = await askFoundation(prompt, SYSTEM_PROMPTS.AGENT_PLANNER_PROMPT, history);
        
        if (!llmResponse) {
            throw new Error("LLM did not return a response.");
        }

        const planJson = extractJSON(llmResponse);
        
        // Strictly validate against our single schema contract
        validateExecutionPlan(planJson, registry);
        
        runLog.info(`[Planner LLM Success] Generated plan with ${planJson.tools.length} tool(s). Thought: "${planJson.thought}"`);
        return { tools: planJson.tools, source: 'model', thought: planJson.thought, rawOutput: llmResponse, error: null };

    } catch (error) {
        runLog.warn(`[Planner LLM Failure] ${error.message}. Falling back to legacy planner.`);
        recordRunError('planner', error.message);
        return { tools: fallbackLegacyPlanner(text), source: 'fallback_rules', thought: null, rawOutput: llmResponse, error: error.message };
    }
}

/**
 * Phase 2 Legacy Planner (Now used strictly as a fallback)
 */
export function fallbackLegacyPlanner(text) {
    const lowerText = text.toLowerCase().trim();
    const instructions = [];

    const intent = extractLegacyIntent(lowerText);
    const extractedIPs = extractIPs(text);
    const minSeverity = extractSeverity(lowerText);
    const { timeRange, lteTime, timeLabel, chronoTimeStr } = extractTimeRange(text, lowerText);
    const cleanedSearchText = cleanSearchQuery(lowerText, chronoTimeStr);

    if (intent === 'agent_inventory' || intent === 'manager_status') {
        let wqlStatus = 'any';
        if (lowerText.includes('disconnected')) wqlStatus = 'disconnected';
        else if (lowerText.includes('active') || lowerText.includes('connected')) wqlStatus = 'active';

        instructions.push({
            tool: 'getEndpointStatus',
            parameters: {
                target: intent === 'manager_status' ? 'manager' : 'agents',
                status: wqlStatus
            }
        });
    } else {
        // Default to security logs search
        instructions.push({
            tool: 'searchSecurityLogs',
            parameters: {
                timeRange: timeRange || 'now-24h',
                lteTime: lteTime || null,
                minSeverity: minSeverity || null,
                extractedIPs: extractedIPs || [],
                intent: intent || 'alerts',
                cleanedSearchText: cleanedSearchText || ''
            }
        });

        // If an IP is found, we might want to also lookup threat intel in parallel
        if (extractedIPs.length > 0) {
            instructions.push({
                tool: 'lookupThreatIntel',
                parameters: {
                    indicator: extractedIPs[0],
                    type: 'ip'
                }
            });
        }
    }

    return instructions;
}
