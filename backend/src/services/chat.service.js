import { runAgentWorkflow } from '../agent/runtime.js';
import { GREETINGS, CONVERSATIONAL_PATTERNS, hasSecurityKeyword } from '../utils/parser.util.js';
import { askFoundation } from '../llm/foundation.js';
import { SYSTEM_PROMPTS } from '../llm/prompts.js';
import { LLM_CONVERSATION_TIMEOUT_MS } from '../config/env.js';
import { sanitizeChatHistory } from '../utils/history.util.js';
import { followUpEvidence } from '../agent/followUp.js';
import { priorClarification } from '../agent/clarify.js';

export const CONVERSATION_UNAVAILABLE_TEXT = 'The AI model is unavailable right now, so I can\'t answer that. Please try again in a moment.';

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

/**
 * options.followUpOf: request_id of the previous Search Wazuh answer in this conversation. When the
 * question is a follow-up to it (followUp.js), it is answered from that evidence without searching again.
 * options.emit / options.signal: stream the search (see handleSearchStream) and let the client stop it.
 */
export async function processChatQuery(text, history = [], userId = 'default_user_1', options = {}) {
    const normalizedText = typeof text === 'string' ? text.trim() : '';
    if (!normalizedText) {
        return {
            type: 'text',
            text: 'Please enter a message so I can help.'
        };
    }

    if (options.followUpOf) {
        const decision = followUpEvidence(normalizedText, options.followUpOf, userId);
        console.log(`[Chat] Follow-up of ${options.followUpOf}: ${decision.reuse ? 'reusing its evidence' : 'searching again'} (${decision.reason}).`);
        if (decision.reuse) return await runAgentWorkflow(normalizedText, history, userId, { followUp: decision.entry, emit: options.emit, signal: options.signal });
    }

    const lowerText = normalizedText.toLowerCase();
    // A reply to a clarifying question ("yes", "the main one") belongs to that search, not to small talk.
    if (!priorClarification(history) && isConversational(lowerText)) {
        // A single, short Foundation request keeps ordinary conversation responsive.
        // Sanitized here too, not only in the controller: scripts call this function directly.
        const { history: safeHistory } = sanitizeChatHistory(history);
        const response = await askFoundation(
            normalizedText,
            SYSTEM_PROMPTS.CONVERSATIONAL_ASSISTANT,
            safeHistory.slice(-6),
            { timeout: LLM_CONVERSATION_TIMEOUT_MS }
        );

        // Model down or timed out: an honest answer, not an HTTP error.
        if (!response) {
            return { type: 'text', text: CONVERSATION_UNAVAILABLE_TEXT, model_generated: false };
        }

        return { type: 'text', text: response, model_generated: true };
    }

    // ==========================================
    // DELEGATE TO THE WAZUH + FIREWALL AGENT RUNTIME
    // ==========================================
    return await runAgentWorkflow(normalizedText, history, userId, { emit: options.emit, signal: options.signal });
}
