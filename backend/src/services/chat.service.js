import { runAgentWorkflow } from '../agent/runtime.js';
import { GREETINGS, CONVERSATIONAL_PATTERNS, hasSecurityKeyword } from '../utils/parser.util.js';

/**
 * Handles incoming chat messages by routing them to the AI Agent Runtime.
 * Preserves the zero-latency conversational fast-path for simple greetings.
 */
export async function processChatQuery(text, sources, history = [], userId = 'default_user_1') {
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
    // DELEGATE TO AI AGENT RUNTIME
    // ==========================================
    return await runAgentWorkflow(text, history, userId);
}
