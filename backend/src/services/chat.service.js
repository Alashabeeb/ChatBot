import { runAgentWorkflow } from '../agent/runtime.js';
import { hasSecurityKeyword } from '../utils/parser.util.js';
import { askFoundation } from '../llm/foundation.js';
import { SYSTEM_PROMPTS } from '../llm/prompts.js';

/**
 * Routes ordinary conversation to the Foundation model and security requests to
 * the agent runtime. This keeps the browser and direct backend prompts on the
 * same model-backed path instead of returning a canned greeting from the API.
 */
export async function processChatQuery(text, sources, history = [], userId = 'default_user_1') {
    const normalizedText = typeof text === 'string' ? text.trim() : '';
    if (!normalizedText) {
        return {
            type: 'text',
            text: 'Please enter a message so I can help.'
        };
    }

    const lowerText = normalizedText.toLowerCase();
    const isSecurityQuery = hasSecurityKeyword(lowerText);
    // General questions never need SIEM planning or data retrieval. A single,
    // short Foundation request keeps ordinary conversation responsive.
    if (!isSecurityQuery) {
        const response = await askFoundation(
            normalizedText,
            SYSTEM_PROMPTS.CONVERSATIONAL_ASSISTANT,
            Array.isArray(history) ? history.slice(-6) : [],
            { maxTokens: 160, timeout: 10_000 }
        );

        if (!response) {
            const error = new Error('The AI service did not return a response.');
            error.statusCode = 503;
            throw error;
        }

        return {
            type: 'text',
            text: response
        };
    }

    const hasSecuritySource = Array.isArray(sources)
        && (sources.includes('wazuh') || sources.includes('firewall') || sources.includes('all'));
    if (!hasSecuritySource) {
        return {
            type: 'text',
            text: 'Please select Wazuh or Firewall from the Agents dropdown to query security data.'
        };
    }

    // ==========================================
    // DELEGATE TO AI AGENT RUNTIME
    // ==========================================
    return await runAgentWorkflow(normalizedText, history, userId, sources);
}
