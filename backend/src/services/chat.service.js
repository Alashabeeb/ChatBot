import {
    GREETINGS,
    CONVERSATIONAL_PATTERNS,
    hasSecurityKeyword,
    extractLegacyIntent,
    extractIPs,
    extractSeverity,
    extractTimeRange,
    cleanSearchQuery
} from '../utils/parser.util.js';

import { getEndpointStatus, getManagerStatus } from '../integrations/wazuh.integration.js';
import { searchSecurityLogs } from '../integrations/opensearch.integration.js';
import { askFoundation } from '../llm/foundation.js';
import { SYSTEM_PROMPTS } from '../llm/prompts.js';

/**
 * Handles incoming chat messages, orchestrating parsing, capability execution, and LLM reasoning.
 * Phase 1 Note: Retains legacy intent-based routing for backward compatibility. Future phases 
 * will replace this with LLM-driven tool selection.
 */
export async function processChatQuery(text, sources, history = []) {
    const lowerText = text.toLowerCase().trim();

    // ==========================================
    // ZERO-LATENCY CONVERSATIONAL FAST-PATH
    // ==========================================
    if (GREETINGS.includes(lowerText) || (GREETINGS.some(g => lowerText.startsWith(g)) && lowerText.length < 20)) {
        return {
            type: 'text',
            text: 'Hello! I am your AI SOC Assistant powered by Cisco Foundation Sec 8B. I am directly connected to the Wazuh SIEM Indexer. Here is what I can do:\n\n• **Check an IP:** "Check this IP 190.03.12.56"\n• **Find attacks:** "Show me brute force attacks"\n• **Count alerts:** "How many authentication failures today?"\n• **Find vulnerabilities:** "Show recent CVEs"\n• **Investigate users:** "Show login failures for admin"'
        };
    }

    const isSecurityQuery = hasSecurityKeyword(lowerText);
    if (CONVERSATIONAL_PATTERNS.some(p => lowerText.includes(p)) && !isSecurityQuery) {
        return {
            type: 'text',
            text: 'I am your AI SOC Assistant, and I am here to help! I specialize in analyzing your Wazuh SIEM security data in real-time. Try asking me something like:\n\n• "Check this IP address 41.203.12.56"\n• "Show me the total authentication failures for the last 24 hours"\n• "What are the latest vulnerability alerts?"\n• "Find brute force attacks targeting our network"\n\nJust type your security question and I will query the live database for you!'
        };
    }

    // ==========================================
    // INSTANT INTENT & ENTITY EXTRACTION
    // ==========================================
    const intent = extractLegacyIntent(lowerText);
    const extractedIPs = extractIPs(text);
    const minSeverity = extractSeverity(lowerText);
    const { timeRange, lteTime, timeLabel, chronoTimeStr } = extractTimeRange(text, lowerText);
    const cleanedSearchText = cleanSearchQuery(lowerText, chronoTimeStr);

    // ==========================================
    // CAPABILITY EXECUTION: Server/Agent Status
    // ==========================================
    if (intent === 'agent_inventory' || intent === 'manager_status') {
        let capabilityResult;
        let sourceLabel;

        if (intent === 'agent_inventory') {
            let wqlStatus = '';
            if (lowerText.includes('disconnected')) wqlStatus = 'status=disconnected';
            else if (lowerText.includes('active') || lowerText.includes('connected')) wqlStatus = 'status=active';
            
            capabilityResult = await getEndpointStatus(wqlStatus);
            sourceLabel = `wazuh-server-api /agents`;
        } else {
            capabilityResult = await getManagerStatus();
            sourceLabel = `wazuh-server-api /manager/status`;
        }

        let summary = '';
        if (capabilityResult.total === 0) {
            summary = `I checked the Wazuh Server API, but found zero results for your query.`;
        } else {
            const summaryPrompt = `User asked: "${text}"\n\nAPI ENDPOINT: ${capabilityResult.url}\nTOTAL RESULTS: ${capabilityResult.total}\nAPI DATA:\n${JSON.stringify(capabilityResult.data)}`;
            const llamaSummary = await askFoundation(summaryPrompt, SYSTEM_PROMPTS.WAZUH_SERVER_API, history);
            summary = llamaSummary || `Successfully retrieved ${capabilityResult.total} items from the Wazuh Server API.`;
        }

        return {
            type: 'agent_response',
            source: sourceLabel,
            summary: summary,
            raw_logs: capabilityResult.data,
            total_hits: capabilityResult.total,
            footer: `Analyzed by foundation-sec-8b | Debug: ${timeLabel} (hits: ${capabilityResult.total})`
        };
    }

    // ==========================================
    // CAPABILITY EXECUTION: Security Logs
    // ==========================================
    const logResult = await searchSecurityLogs({
        timeRange,
        lteTime,
        minSeverity,
        extractedIPs,
        intent,
        cleanedSearchText
    });

    let sourceLabel = `wazuh-indexer /wazuh-alerts-* [${timeLabel}]`;
    if (extractedIPs.length > 0) sourceLabel += ` (Target: ${extractedIPs[0]})`;

    let summary = '';
    
    if (logResult.totalHits === 0) {
        summary = extractedIPs.length > 0 
            ? `I scanned the SIEM logs for the ${timeLabel}, but found zero alerts for IP ${extractedIPs[0]}. You can ask for a wider window (e.g. "past 7 days").` 
            : `I searched the database for the ${timeLabel}, but found zero matching alerts. You can try adjusting the time range (e.g. "past 7 days").`;
    } else {
        // Minify logs according to official Wazuh alert & vulnerability index schemas
        const minifiedLogs = logResult.rawData.slice(0, 50).map(log => ({
            time: log['@timestamp'] || log.vulnerability?.detected_at || 'N/A',
            level: typeof log.rule?.level === 'number' ? log.rule.level : log.vulnerability?.severity || 0,
            desc: log.rule?.description || log.vulnerability?.description || 'N/A',
            srcip: log.data?.srcip || log.srcip || log.agent?.ip || 'N/A',
            user: log.data?.srcuser || log.data?.dstuser || log.data?.user || 'N/A',
            agent: log.agent?.name || log.agent?.id || 'N/A',
            cve: log.vulnerability?.id || 'N/A'
        }));

        const dynamicSystemPrompt = SYSTEM_PROMPTS.STRICT_FACTUAL_RAG.replace('{TIME_LABEL}', timeLabel).replace('{TIME_LABEL}', timeLabel);

        const summaryPrompt = `User asked: "${text}"\n\nTIME WINDOW ANALYZED: ${timeLabel} (${timeRange})\nEXACT TOTAL MATCHES IN ${timeLabel.toUpperCase()}: ${logResult.totalHits}\nSAMPLE LOGS (TOP ${minifiedLogs.length}):\n${JSON.stringify(minifiedLogs)}`;
        
        const llamaSummary = await askFoundation(summaryPrompt, dynamicSystemPrompt, history);
        
        if (llamaSummary) {
            summary = llamaSummary;
        } else {
            summary = `Successfully retrieved ${logResult.totalHits} alerts from the Wazuh Indexer matching your query. Click "View Full Details" to see the raw JSON logs.`;
        }
    }

    return {
        type: 'agent_response',
        source: sourceLabel,
        summary: summary,
        raw_logs: logResult.rawData,
        total_hits: logResult.totalHits,
        footer: summary.includes('SIEM logs found') || logResult.rawData.length === 0 ? 'Processed Instantly' : 'Analyzed by foundation-sec-8b'
    };
}
