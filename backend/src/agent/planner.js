import {
    extractLegacyIntent,
    extractIPs,
    extractSeverity,
    extractTimeRange,
    cleanSearchQuery
} from '../utils/parser.util.js';

/**
 * Phase 2 Planner
 * Temporarily wraps legacy intent logic. In future phases, this will be 
 * replaced by the LLM deciding which tools to call dynamically.
 * 
 * Always returns an ordered array of tool execution instructions.
 */
export function generateExecutionPlan(text) {
    const lowerText = text.toLowerCase().trim();
    const instructions = [];

    const intent = extractLegacyIntent(lowerText);
    const extractedIPs = extractIPs(text);
    const minSeverity = extractSeverity(lowerText);
    const { timeRange, lteTime, timeLabel, chronoTimeStr } = extractTimeRange(text, lowerText);
    const cleanedSearchText = cleanSearchQuery(lowerText, chronoTimeStr);

    if (intent === 'agent_inventory' || intent === 'manager_status') {
        let wqlStatus = '';
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
                timeRange,
                lteTime,
                minSeverity,
                extractedIPs,
                intent,
                cleanedSearchText
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
