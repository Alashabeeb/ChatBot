/**
 * Whether a question asks for a comparison with an earlier period.
 *
 * Every search also counts the same window one week earlier (one aggregation request, so the shape of
 * the request never depends on the wording). That comparison is shown, and sent to the report model,
 * only when the analyst asks for it: an explicit comparison ("compare", "vs", "than last week"), a
 * trend or change ("increase", "drop", "spike", "trend", "what changed"), or what is unusual or new
 * ("unusual", "more than usual", "new rules"), which can only be judged against an earlier period.
 * A time range alone ("the past 24 hours", "last week's alerts") is not a request to compare.
 */
const COMPARISON = [
    /\b(?:compar(?:e|ed|es|ing|ison)|vs\.?|versus|against (?:last|the previous|yesterday|before))\b/i,
    /\b(?:more|fewer|less|higher|lower|bigger|smaller|worse|better)\b[\w\s]{0,30}\bthan\b/i,
    /\b(?:increas|decreas|ris(?:e|es|ing)\b|rose\b|dropp?|declin|grow|grew|spik|surg|jump|fell\b|fall(?:s|ing)?\b)/i,
    /\b(?:trend(?:s|ing)?|week[- ](?:over|on)[- ]week|day[- ](?:over|on)[- ]day|baseline)\b/i,
    /\bwhat(?:'s| has| have)? changed\b|\bchange[sd]? (?:since|from)\b|\bdifferent from\b/i,
    /\b(?:unusual|abnormal|anomal\w*|out of the ordinary|than usual|than normal)\b/i,
    /\bnew (?:rules?|alerts?|activity|ips?|agents?)\b/i
];

export function wantsComparison(text) {
    const question = String(text ?? '');
    return COMPARISON.some(pattern => pattern.test(question));
}
