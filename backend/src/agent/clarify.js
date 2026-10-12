import { IPV4 } from './evidenceIndex.js';

/**
 * One short clarifying question instead of a guess (Phase 7). Asked only when a Search Wazuh request
 * can't be answered without a detail it doesn't give, and at most once: the reply to a clarification
 * always proceeds, combined with the original question.
 *
 * The rules here catch the clear cases without a model call; the planner may also ask (planner.js),
 * under the same one-question limit.
 */
export const CLARIFICATION_LEAD = 'Quick question before I search:';

const NOUN_QUESTIONS = {
    ip: 'Which IP address do you mean?',
    address: 'Which IP address do you mean?',
    host: 'Which host do you mean? Give me its name or agent ID.',
    server: 'Which server do you mean? Give me its name or agent ID.',
    machine: 'Which machine do you mean? Give me its name or agent ID.',
    endpoint: 'Which endpoint do you mean? Give me its name or agent ID.',
    agent: 'Which agent do you mean? Give me its name or ID.',
    user: 'Which user do you mean? Give me the username.',
    account: 'Which account do you mean? Give me the username.',
    alert: 'Which alert do you mean? Give me the rule ID or describe it.',
    rule: 'Which rule do you mean? Give me the rule ID.',
    attacker: 'Which attacker do you mean? Give me the source IP.'
};
// "that IP", "the server", "this user": a single, specific thing the request never names. Plurals
// ("the servers") are a scope, not a reference, so they don't match.
const REFERENCE = new RegExp(`\\b(?:that|this|the)\\s+(${Object.keys(NOUN_QUESTIONS).join('|')})\\b`, 'i');
const NAMES_SOMETHING = [
    IPV4,
    /\brules?\s*(?:id\s*)?#?\s*\d{2,6}\b/i,
    /\bCVE-\d{4}-\d{4,}\b/i,
    /(?<![\w.-])[A-Za-z][A-Za-z0-9]*[-_]?\d+[A-Za-z0-9]*(?![\w-])/,   // web-01, DC01, srv_02
    /\bagent\s+#?\d{3,}\b/i,
    /["'“‘][^"'”’]{2,}["'”’]/,                                       // a quoted name
    /\b(?:user|account|username)\s+(?!(?:log|logs|logged|login|logon|is|was|has|had|did|do|does|in|on|at|to|from|for|with)\b)[A-Za-z0-9._$\\-]{2,}/i
];
const VAGUE_WORDS = new Set(['check', 'investigate', 'look', 'scan', 'analyse', 'analyze', 'review', 'logs', 'log', 'data', 'stuff', 'it',
    'this', 'that', 'something', 'anything', 'please', 'can', 'you', 'the', 'a', 'show', 'me', 'run', 'at', 'into', 'on', 'help', 'find', 'out']);

/** The question to ask, without the lead, or null when the request is clear enough to search. */
export function clarificationFor(text) {
    const question = String(text ?? '').trim();
    if (!question) return null;
    const words = question.toLowerCase().match(/[a-z0-9._-]+/g) ?? [];
    if (words.length > 0 && words.length <= 4 && words.every(w => VAGUE_WORDS.has(w))) {
        return 'What should I look at? For example failed logons today, alerts on a specific host, or activity from an IP.';
    }
    const reference = REFERENCE.exec(question);
    if (reference && !NAMES_SOMETHING.some(pattern => new RegExp(pattern.source, pattern.flags.replace('g', '')).test(question))) {
        return NOUN_QUESTIONS[reference[1].toLowerCase()];
    }
    return null;
}

/** A planner-proposed clarification, accepted only if it is one short question. */
export function acceptableClarification(value) {
    if (typeof value !== 'string') return null;
    const q = value.trim().replace(/\s+/g, ' ');
    if (!q || q.length > 200 || !q.endsWith('?') || (q.match(/\?/g) || []).length !== 1) return null;
    return q;
}

/**
 * If the last assistant turn was a clarification, the user question it asked about (so the reply can
 * be combined with it), else null.
 */
export function priorClarification(history = []) {
    const turns = Array.isArray(history) ? history : [];
    const lastAssistant = turns.map((t, i) => [t, i]).filter(([t]) => t?.role === 'assistant').at(-1);
    if (!lastAssistant || typeof lastAssistant[0].content !== 'string' || !lastAssistant[0].content.startsWith(CLARIFICATION_LEAD)) return null;
    const asked = turns.slice(0, lastAssistant[1]).filter(t => t?.role === 'user').at(-1);
    return typeof asked?.content === 'string' ? asked.content : null;
}
