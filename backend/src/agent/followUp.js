import { getEvidence } from './evidenceCache.js';
import { buildEvidenceIndex, IPV4 } from './evidenceIndex.js';

/**
 * Decides whether a question is a follow-up that the previous search's evidence can answer (Phase 7).
 * Conservative: anything that asks for new or fresh data, or names a time window, searches again.
 * Otherwise the evidence is reused when the question refers back to the previous answer ("that IP",
 * "tell me more", "which one") or names something that is in that evidence (a rule ID, agent, IP or user).
 */
const NEW_SEARCH = /\b(?:search again|search for|re-?run|refresh|latest|new search|look again|check again|fresh|update(?:d)?|now|today|yesterday|tonight|this (?:morning|week|month|year)|last|past|previous (?:hour|day|week|month)|since|between|before|after|hours?|days?|weeks?|months?|minutes?)\b/i;
const REFERS_BACK = /\b(?:that|those|these|this|it|its|them|they|their|which (?:one|ones|ip|ips|agent|agents|rule|rules|user|users|host|hosts)|more (?:about|detail|details|on)|details?|explain|why|who|what about|tell me more|break (?:it|that|this) down|summari[sz]e|elaborate|the same)\b/i;

export function followUpEvidence(text, followUpOf, userId) {
    if (!followUpOf) return { reuse: false, reason: 'no previous search given' };
    const entry = getEvidence(String(followUpOf), userId);
    if (!entry) return { reuse: false, reason: 'previous evidence unavailable (expired, unknown, or another user\'s)' };
    const question = String(text ?? '');
    if (NEW_SEARCH.test(question)) return { reuse: false, reason: 'the question asks for new data or a time window' };

    const index = buildEvidenceIndex(entry.results);
    const lower = question.toLowerCase();
    const mentions = [
        ...[...lower.matchAll(/\brules?\s*(?:id\s*)?#?\s*(\d{2,6})\b/g)].map(m => m[1]).filter(id => index.rules.has(id)),
        ...(question.match(IPV4) ?? []).filter(ip => index.ips.has(ip)),
        ...[...index.agentNames, ...index.users].filter(name => name.length > 2 && new RegExp(`(?<![\\w.-])${name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}(?![\\w-])`, 'i').test(question))
    ];
    if (mentions.length || REFERS_BACK.test(question)) {
        return { reuse: true, entry, reason: mentions.length ? `names ${mentions.slice(0, 3).join(', ')} from the previous evidence` : 'refers back to the previous answer' };
    }
    return { reuse: false, reason: 'not a follow-up to the previous answer' };
}
