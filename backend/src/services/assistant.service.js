import { generalAssistantPrompt } from '../llm/prompts.js';

/**
 * Builds the messages for one general-chat request: the system prompt (with today's date), as much
 * recent history as fits in `historyCharBudget`, and the new user message.
 * History must already be sanitized (user/assistant turns with string content only). The oldest turns
 * are dropped first; the new message is always sent.
 */
export function buildChatMessages({ text, history = [], now = new Date(), historyCharBudget }) {
    const kept = [];
    let used = 0;
    for (let i = history.length - 1; i >= 0; i--) {
        const cost = history[i].content.length + 16; // + role/framing overhead
        if (used + cost > historyCharBudget) break;
        used += cost;
        kept.unshift(history[i]);
    }
    // A conversation sent to the model should start with a user turn.
    while (kept.length > 0 && kept[0].role !== 'user') kept.shift();

    return [
        { role: 'system', content: generalAssistantPrompt(now) },
        ...kept,
        { role: 'user', content: text }
    ];
}

// Security data a question can be about (plurals and inflections included, unlike hasSecurityKeyword).
const DATA_TERMS = /\b(alerts?|logs?|log-?ons?|log-?ins?|sign-?ins?|events?|agents?|endpoints?|hosts?|servers?|vulnerabilit(?:y|ies)|cves?|attacks?|brute[- ]?force|incidents?|intrusions?|malware|suspicious|unusual|anomal\w*|firewall|traffic|blocked|failed|failures?|wazuh|siem|detections?)\b/i;
// Cues that the user means *their* data as it is now, rather than a general question.
const LIVE_CUES = /\b(show|list|find|check|count|how many|any(thing)?|top|today|tonight|yesterday|this (?:morning|week|month)|right now|currently|last|past|recent(?:ly)?|latest|our|my|we|happening|going on)\b/i;
const IPV4 = /\b\d{1,3}(?:\.\d{1,3}){3}\b/;

/**
 * True when a general-chat question looks like it needs the organisation's live security data.
 * Used only to offer a "Search Wazuh for this" button; it never changes what the model is asked.
 */
export function looksLikeDataQuestion(text) {
    if (IPV4.test(text)) return true;
    return DATA_TERMS.test(text) && LIVE_CUES.test(text);
}
