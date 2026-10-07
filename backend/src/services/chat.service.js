import { runAgentWorkflow } from '../agent/runtime.js';
import { GREETINGS, CONVERSATIONAL_PATTERNS, hasSecurityKeyword } from '../utils/parser.util.js';
import { askFoundation } from '../llm/foundation.js';
import { SYSTEM_PROMPTS } from '../llm/prompts.js';

/**
 * Only clearly conversational messages (greetings, "what can you do", "explain ...") without any
 * security keyword go to the Foundation model as plain conversation. Everything else goes to the
 * agent runtime, which searches Wazuh and firewall data. Defaulting to the runtime matters:
 * hasSecurityKeyword() matches whole words only, so "failed logons" or "top alerts" carry no
 * keyword, and routing on the keyword alone would answer them without searching anything.
 */
export function isConversational(lowerText) {
    if (hasSecurityKeyword(lowerText)) return false;
    return GREETINGS.includes(lowerText)
        || (GREETINGS.some(g => lowerText.startsWith(g)) && lowerText.length < 20)
        || CONVERSATIONAL_PATTERNS.some(p => lowerText.includes(p));
}

export async function processChatQuery(text, history = [], userId = 'default_user_1') {
    const normalizedText = typeof text === 'string' ? text.trim() : '';
    if (!normalizedText) {
        return {
            type: 'text',
            text: 'Please enter a message so I can help.'
        };
    }

    const lowerText = normalizedText.toLowerCase();
    if (isConversational(lowerText)) {
        // A single, short Foundation request keeps ordinary conversation responsive.
        const response = await askFoundation(
            normalizedText,
            SYSTEM_PROMPTS.CONVERSATIONAL_ASSISTANT,
            Array.isArray(history) ? history.slice(-6) : []
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

    // ==========================================
    // DELEGATE TO THE WAZUH + FIREWALL AGENT RUNTIME
    // ==========================================
    return await runAgentWorkflow(normalizedText, history, userId);
}
