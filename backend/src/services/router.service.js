import { askFoundation } from '../llm/foundation.js';
import { looksLikeDataQuestion } from './assistant.service.js';
import { GREETINGS, CONVERSATIONAL_PATTERNS, hasSecurityKeyword } from '../utils/parser.util.js';
import { listingRequest } from '../agent/listing.js';
import { priorClarification } from '../agent/clarify.js';
import { followUpEvidence } from '../agent/followUp.js';

/**
 * Decides, per message, whether answering needs the organisation's own security data (search: the
 * Wazuh pipeline) or not (chat: the general assistant). Replaces the manual "Search Wazuh" toggle.
 *
 * Clear cases are decided by rules, instantly and without a model call. Only messages that mention
 * security but don't say whether they mean "our data" go to the model, as a one-word question with a
 * short time limit. If the model can't answer, a safe default applies: search when the message
 * mentions security terms (a data answer is still useful without the model), chat otherwise.
 *
 * Returns { route: 'search' | 'chat', by: 'user' | 'rule' | 'model' | 'fallback', reason }.
 */

const IPV4 = /\b\d{1,3}(?:\.\d{1,3}){3}\b/;
const HOST = /(?<![\w.-])(?:[A-Za-z][A-Za-z0-9]*[-_][A-Za-z0-9_-]*\d[A-Za-z0-9]*|[A-Z]{2,}\d+[A-Z0-9]*)(?![\w-])/;
const LIVE = /\b(?:today|tonight|yesterday|this (?:morning|week|month)|right now|currently|last|past|recent(?:ly)?|latest|our|my|we|us)\b/i;
const HAPPENING = /\b(?:what(?:'s| is| was| has been)?|anything|something)\s+(?:been\s+)?(?:going on|happening|happened|changed)\b/i;
const DATA_TERMS = /\b(?:alerts?|logs?|log-?ons?|log-?ins?|events?|agents?|endpoints?|hosts?|servers?|vulnerabilit(?:y|ies)|cves?|attacks?|brute[- ]?force|incidents?|intrusions?|malware|suspicious|unusual|anomal\w*|firewall|traffic|blocked|failed|failures?|wazuh|siem|detections?)\b/i;
const KNOWLEDGE_OR_WRITING = /^\s*(?:please\s+|can you\s+|could you\s+)?(?:write|draft|compose|rewrite|translate|summari[sz]e|explain|define|teach|describe|give me (?:an? |some )?(?:example|template|checklist|list of|overview)|what (?:is|are|does)|how (?:does|do|to|can)|why (?:is|are|do|does|would)|who (?:is|was|won|made)|when (?:is|was|did)|tell me about|help me (?:write|draft|understand))\b/i;
const ROUTER_PROMPT = `You route messages for a security operations assistant connected to the organisation's Wazuh SIEM (alerts, firewall events, agent status, vulnerabilities).
Decide whether answering the message requires looking at the organisation's own security data.
Reply with exactly one word: SEARCH if it needs their data (counts, events, hosts, IPs, users, what happened, current state), or CHAT if it can be answered from general knowledge or is a writing or conversation task.
Answer SEARCH or CHAT, nothing else.`;

/** The rule-based decision, or null when the message is unclear. Pure: no model, no data. */
export function routeByRules(text, history = []) {
    const message = String(text ?? '').trim();
    const lower = message.toLowerCase();
    if (priorClarification(history)) return { route: 'search', by: 'rule', reason: 'reply to a clarifying question' };
    if (listingRequest(message)) return { route: 'search', by: 'rule', reason: 'asks for recent records' };
    if (looksLikeDataQuestion(message)) return { route: 'search', by: 'rule', reason: 'asks about security data' };
    if (HAPPENING.test(message) && (LIVE.test(message) || HOST.test(message) || message.split(/\s+/).length <= 6)) {
        return { route: 'search', by: 'rule', reason: 'asks what is happening' };
    }
    if (HOST.test(message) && (LIVE.test(message) || DATA_TERMS.test(message))) return { route: 'search', by: 'rule', reason: 'asks about a host' };

    const greeting = GREETINGS.includes(lower.replace(/[!.?]+$/, '')) || (GREETINGS.some(g => lower.startsWith(g)) && lower.length < 20)
        || CONVERSATIONAL_PATTERNS.some(p => lower.startsWith(p) && !hasSecurityKeyword(lower));
    if (greeting) return { route: 'chat', by: 'rule', reason: 'conversation' };
    if (KNOWLEDGE_OR_WRITING.test(message) && !IPV4.test(message) && !HOST.test(message) && !LIVE.test(message)) {
        return { route: 'chat', by: 'rule', reason: 'general knowledge or writing' };
    }
    if (!DATA_TERMS.test(message) && !hasSecurityKeyword(lower) && !IPV4.test(message) && !HOST.test(message)) {
        return { route: 'chat', by: 'rule', reason: 'no security subject' };
    }
    return null;
}

const timeoutMs = () => {
    const value = Number(process.env.ROUTER_TIMEOUT_MS);
    return Number.isFinite(value) && value > 0 ? value : 8000;
};

export async function routeMessage(text, history = [], { userId, followUpOf = null, forceRoute = null } = {}) {
    if (forceRoute === 'search' || forceRoute === 'chat') return { route: forceRoute, by: 'user', reason: 'chosen by the analyst' };
    if (followUpOf && followUpEvidence(text, followUpOf, userId).reuse) return { route: 'search', by: 'rule', reason: 'follow-up to the previous search' };
    const rule = routeByRules(text, history);
    if (rule) return rule;

    const reply = await askFoundation(String(text), ROUTER_PROMPT, [], { timeout: timeoutMs(), role: 'planner', maxTokens: 3 });
    const word = /\b(search|chat)\b/i.exec(reply ?? '')?.[1]?.toLowerCase();
    if (word) return { route: word, by: 'model', reason: `the model chose ${word}` };
    const fallback = DATA_TERMS.test(text) || hasSecurityKeyword(String(text).toLowerCase()) ? 'search' : 'chat';
    return { route: fallback, by: 'fallback', reason: reply ? 'unclear model reply' : 'model unavailable' };
}
