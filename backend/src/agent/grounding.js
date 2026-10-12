import { IPV4, topCounts } from './evidenceIndex.js';
import { listingTable, mostRecentRecords } from './listing.js';

/**
 * Grounded reports (Phase 4). The report model returns claims, each with citations into the evidence;
 * this module checks every claim in code and renders only the ones that hold up. A claim is dropped,
 * logged and never shown when:
 *  - it has no citation, or a citation doesn't resolve to the evidence (unknown rule ID, agent, IP,
 *    user, technique, CVE, total or field), or a cited count is outside what the evidence supports;
 *  - its text names a rule ID, IP, MITRE technique, CVE or host that isn't in the evidence
 *    (techniques only count when they appear in rule.mitre.id);
 *  - its text contains a number not backed by a cited count (time windows, dates and IDs aside);
 *  - it gives a confidence, risk or threat score (none is defined), or claims an action was taken.
 * The sources and time window that open every report are written by the code, not the model.
 */

export const SECTIONS = ['answer', 'findings', 'assessment', 'next_steps'];
const SECTION_TITLES = { findings: 'Findings', assessment: 'Assessment', next_steps: 'Next steps' };

const MITRE = /\bT\d{4}(?:\.\d{3})?\b/g;
const CVE = /\bCVE-\d{4}-\d{4,}\b/gi;
const RULE_LIST = /\brules?(?:[\s_-]*ids?)?\s*[:#]?\s*((?:\d{2,6})(?:\s*(?:,|\/|&|\band\b|\bor\b)\s*\d{2,6})*)\b/gi;
const HOST = /(?<![\w.-])(?:[A-Za-z][A-Za-z0-9]*[-_][A-Za-z0-9_-]*\d[A-Za-z0-9]*|[A-Z]{2,}\d+[A-Z0-9]*)(?![\w-])/g;
const HOST_IGNORE = /^(?:T\d{4}|CVE-\d{4}-\d+|SHA\d+|MD\d|AES\d+|HTTP\d|TLS\d.*|IPV\d|X\d+|UTF-?\d+|WIN\d+|W\d+|ISO-?\d+|RFC\d+|SMBV?\d|NTLMV?\d|E\d+)$/i;
const DATE_TIME = /\b\d{4}-\d{2}-\d{2}(?:[T ]\d{2}:\d{2}(?::\d{2}(?:\.\d+)?)?Z?)?\b|\b\d{1,2}:\d{2}(?::\d{2})?\b/g;
const WINDOW_NUMBER = /\b\d+\s*(?:seconds?|secs?|minutes?|mins?|hours?|hrs?|days?|weeks?|months?|years?)\b/gi;
const TOP_N = /\btop\s+\d+\b/gi;
const LEVEL = /\b(?:rule\s+)?level\s+(\d{1,2})\b/gi;
const AGENT_ID = /\bagents?\s+(?:id\s+)?#?(\d{3,})\b/gi;
const SCORE = /\b(?:confiden(?:ce|t)|certainty|risk score|threat score|likelihood)\b[^.\n]{0,40}?\d|\b\d{1,3}\s*%|\b\d+(?:\.\d+)?\s*\/\s*10\b/i;
const ACTION_CLAIM = /\b(?:IP|address|host|account|user)\b[^\n]{0,40}?\b(?:has been|was|is now|have been)\s+(?:successfully\s+)?(?:blocked|isolated|quarantined|disabled|contained)\b|\bIP_BLOCKED\b|\bunknown_miner\b|successfully added\b[^\n]{0,60}?\bblocklist/i;

/** Parses the report model's output. Returns { ok, claims: {answer, findings, ...}, insufficient } or { ok: false, error }. */
export function parseClaims(raw) {
    if (typeof raw !== 'string' || !raw.trim()) return { ok: false, error: 'empty output' };
    const unfenced = raw.replace(/```(?:json)?/gi, '');
    const start = unfenced.indexOf('{');
    const end = unfenced.lastIndexOf('}');
    if (start === -1 || end <= start) return { ok: false, error: 'no JSON object in the output' };
    let parsed;
    try {
        parsed = JSON.parse(unfenced.slice(start, end + 1));
    } catch (error) {
        return { ok: false, error: `invalid JSON: ${error.message}` };
    }
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return { ok: false, error: 'output is not a JSON object' };
    const claims = {};
    for (const section of SECTIONS) {
        const items = parsed[section] ?? [];
        claims[section] = Array.isArray(items) ? items : [];
    }
    return { ok: true, claims, insufficient: parsed.insufficient_evidence === true };
}

function resolvePath(root, path) {
    const parts = String(path).replace(/\[(\d+)\]/g, '.$1').split('.').filter(Boolean);
    let value = root;
    for (const part of parts) {
        if (value === null || typeof value !== 'object' || !(part in value)) return { found: false };
        value = value[part];
    }
    return { found: true, value };
}

const withinBounds = (bounds, count) => bounds && Number.isInteger(count) && count >= bounds.min && count <= bounds.max;
const describeBounds = b => (b.min === b.max ? String(b.min) : `${b.min}–${b.max}`);
const ciHas = (set, value) => [...set].some(v => String(v).toLowerCase() === String(value).toLowerCase());

/** Checks one citation. Returns null when it resolves, or the reason it doesn't. */
function citationProblem(cite, index, modelEvidence) {
    if (!cite || typeof cite !== 'object') return 'citation is not an object';
    const kind = String(cite.kind ?? '').toLowerCase();
    const ref = cite.ref ?? cite.value;
    if (ref === undefined || ref === null || ref === '') return `${kind || 'citation'} has no ref`;
    const hasCount = cite.count !== undefined && cite.count !== null;
    const count = hasCount ? Number(cite.count) : null;
    if (hasCount && !Number.isInteger(count)) return `count "${cite.count}" is not a whole number`;
    const checkCount = (bounds, what) => {
        if (!hasCount) return null;
        if (!bounds) return `no count is known for ${what}`;
        return withinBounds(bounds, count) ? null : `${what}: cited count ${count}, evidence ${describeBounds(bounds)}`;
    };

    switch (kind) {
        case 'rule':
            if (!index.rules.has(String(ref))) return `rule ${ref} is not in the evidence`;
            return checkCount(index.rules.get(String(ref)), `rule ${ref}`);
        case 'agent': {
            const byName = [...index.agentCounts.keys()].find(k => k.toLowerCase() === String(ref).toLowerCase());
            if (!ciHas(index.agentNames, ref) && !index.agentIds.has(String(ref))) return `agent ${ref} is not in the evidence`;
            return checkCount(byName ? index.agentCounts.get(byName) : null, `agent ${ref}`);
        }
        case 'ip':
            if (!index.ips.has(String(ref))) return `IP ${ref} is not in the evidence`;
            return checkCount(index.ipCounts.get(String(ref)), `IP ${ref}`);
        case 'user':
            if (!ciHas(index.users, ref)) return `user ${ref} is not in the evidence`;
            return hasCount ? `no count is known for user ${ref}` : null;
        case 'mitre':
            if (!index.mitre.has(String(ref))) return `technique ${ref} is not in any rule.mitre.id`;
            return hasCount ? `no count is known for technique ${ref}` : null;
        case 'cve':
            if (!ciHas(index.cves, ref)) return `${ref} is not in the evidence`;
            return hasCount ? `no count is known for ${ref}` : null;
        case 'total': {
            if (!index.totals.has(String(ref))) return `no source "${ref}" was searched`;
            if (hasCount && count !== index.totals.get(String(ref))) return `${ref}: cited total ${count}, evidence ${index.totals.get(String(ref))}`;
            return null;
        }
        case 'previous': {
            // The same window one week earlier: a search key for its total, or a rule ID for that rule's count.
            if (!index.comparison) return 'no week-earlier comparison is available';
            if (index.comparison.previousTotals.has(String(ref))) {
                const total = index.comparison.previousTotals.get(String(ref));
                return hasCount && count !== total ? `${ref} a week earlier: cited ${count}, evidence ${total}` : null;
            }
            const entry = index.comparison.byRule.get(String(ref));
            if (!entry) return `rule ${ref} has no week-earlier count`;
            return checkCount(entry.previous, `rule ${ref} a week earlier`);
        }
        case 'memory':
            if (!index.memories.some(m => m.ref === String(ref))) return `${ref} is not a past investigation in the evidence`;
            return hasCount ? 'counts cannot be cited from a past investigation' : null;
        case 'field': {
            const { found, value } = resolvePath(modelEvidence, ref);
            if (!found) return `field ${ref} is not in the evidence`;
            if (hasCount && Number(value) !== count) return `field ${ref}: cited ${count}, evidence ${JSON.stringify(value)}`;
            return null;
        }
        default:
            return `unknown citation kind "${cite.kind}"`;
    }
}

/** Checks the entities and numbers in a claim's text. Returns null, or the reason it can't be shown. */
function textProblem(text, cites, index) {
    if (SCORE.test(text)) return 'gives a confidence, risk or percentage score, which is not defined from the evidence';
    if (ACTION_CLAIM.test(text)) return 'claims an action was taken; no action tool ran';

    for (const ip of text.match(IPV4) ?? []) if (!index.ips.has(ip)) return `IP ${ip} is not in the evidence`;
    for (const t of text.match(MITRE) ?? []) if (!index.mitre.has(t)) return `technique ${t} is not in any rule.mitre.id`;
    for (const c of text.match(CVE) ?? []) if (!ciHas(index.cves, c)) return `${c} is not in the evidence`;
    for (const m of text.matchAll(RULE_LIST)) {
        for (const id of m[1].match(/\d{2,6}/g)) if (!index.rules.has(id)) return `rule ${id} is not in the evidence`;
    }
    for (const m of text.matchAll(AGENT_ID)) if (!index.agentIds.has(m[1])) return `agent ${m[1]} is not in the evidence`;
    for (const m of text.matchAll(LEVEL)) if (!index.levels.has(Number(m[1]))) return `no record has level ${m[1]}`;
    for (const h of text.match(HOST) ?? []) {
        if (HOST_IGNORE.test(h) || /^T\d{4}/.test(h) || /^CVE-/i.test(h)) continue;
        if (!index.mentions(h)) return `${h} is not in the evidence`;
    }

    // Every remaining number must be a count this claim cites. A rule description quoted verbatim from
    // the evidence ("Multiple web server 400 error codes ...") is evidence text, not a claimed count.
    const cited = new Set(cites.map(c => c?.count).filter(c => c !== undefined && c !== null).map(Number));
    let unquoted = text;
    for (const description of index.ruleDescriptions.values()) {
        if (!description || !/\d/.test(description)) continue;
        const at = unquoted.toLowerCase().indexOf(description.toLowerCase());
        if (at !== -1) unquoted = `${unquoted.slice(0, at)} ${unquoted.slice(at + description.length)}`;
    }
    const stripped = unquoted
        .replace(IPV4, ' ').replace(MITRE, ' ').replace(CVE, ' ').replace(DATE_TIME, ' ')
        .replace(RULE_LIST, ' ').replace(AGENT_ID, ' ').replace(LEVEL, ' ').replace(HOST, ' ')
        .replace(WINDOW_NUMBER, ' ').replace(TOP_N, ' ');
    for (const n of stripped.match(/\d[\d,]*(?:\.\d+)?/g) ?? []) {
        const value = Number(n.replace(/,/g, ''));
        if (!cited.has(value)) return `the number ${n} is not backed by a cited count`;
    }
    return null;
}

/**
 * Verifies every claim. Returns { kept: {answer: [...], ...}, dropped: [{section, text, reason}], total }.
 */
export function verifyClaims(claims, index, modelEvidence) {
    const kept = Object.fromEntries(SECTIONS.map(s => [s, []]));
    const dropped = [];
    let total = 0;
    for (const section of SECTIONS) {
        for (const claim of claims[section] ?? []) {
            total++;
            const text = typeof claim?.text === 'string' ? claim.text.replace(/\s+/g, ' ').trim() : '';
            const cites = Array.isArray(claim?.cite) ? claim.cite : Array.isArray(claim?.citations) ? claim.citations : [];
            let reason = null;
            if (!text) reason = 'no text';
            else if (cites.length === 0) reason = 'no citation';
            else {
                for (const cite of cites) {
                    reason = citationProblem(cite, index, modelEvidence);
                    if (reason) break;
                }
                reason = reason ?? textProblem(text, cites, index);
            }
            if (reason) dropped.push({ section, text: text.slice(0, 500), reason });
            else kept[section].push({ text, fromMemory: cites.every(c => String(c.kind).toLowerCase() === 'memory') });
        }
    }
    return { kept, dropped, total };
}

const plural = (n, one, many = `${one}s`) => `${n.toLocaleString('en-US')} ${n === 1 ? one : many}`;

/** The opening lines of every report, written by the code: what was searched, over which window, and what wasn't available. */
export function renderHeader(index) {
    const lines = [];
    const byWindow = new Map();
    for (const s of index.searches.filter(x => !x.failed)) {
        if (!byWindow.has(s.window.text)) byWindow.set(s.window.text, []);
        byWindow.get(s.window.text).push(`${s.label} (${plural(s.total, 'match', 'matches')})`);
    }
    const parts = [...byWindow.entries()].map(([window, sources]) => `${sources.join(' and ')} for ${window}`);
    if (index.totals.has('getEndpointStatus')) parts.push(`Wazuh agent status (${plural(index.totals.get('getEndpointStatus'), 'agent')})`);
    if (index.memories.length) parts.push(`past investigations (${plural(index.memories.length, 'match', 'matches')})`);
    lines.push(parts.length ? `**Searched:** ${parts.join('; ')}.` : '**Searched:** no data source returned results for this question.');
    if (index.comparison) {
        const { total, window } = index.comparison;
        lines.push(`**Compared with** ${window}: ${plural(total.current, 'match', 'matches')}, against ${total.previous.toLocaleString('en-US')}.`);
    } else if (!index.countsExact && index.totalMatches > 0) {
        lines.push(`**Counts** come from the records retrieved (the most recent, up to 200 per search), not from every match${index.comparisonRequested ? ', and there is no week-earlier comparison' : ''}.`);
    }
    const failed = index.unavailable.filter(u => !['threat intelligence', 'process inspection'].includes(u.source));
    if (failed.length) lines.push(`**Not available:** ${failed.map(u => `${u.source}: ${u.reason}`).join('; ')}. Anything that source would have shown is missing from this answer.`);
    return lines.join('\n');
}

/**
 * "Summary of the results": what the search found, written by the code from the counts (used whenever
 * no verified AI analysis is shown). Counts only, nothing inferred. Aggregated counts cover every
 * match ("about" when OpenSearch reports them as approximate); without aggregations, counts come from
 * the records returned, and the summary says so.
 */
export function renderEvidenceSummary(index) {
    const n = value => value.toLocaleString('en-US');
    const fmt = bounds => (bounds.min === bounds.max ? n(bounds.min) : `${index.allAggregated ? 'about' : 'at least'} ${n(bounds.min)}`);
    const lines = [];

    if (index.comparison) {
        const { current, previous } = index.comparison.total;
        const window = index.comparison.window;
        if (previous === 0) lines.push(`- **Change:** no matches in ${window}; ${n(current)} now.`);
        else if (current === previous) lines.push(`- **Change:** the same number of matches as ${window} (${n(current)}).`);
        else {
            const pct = Math.round((Math.abs(current - previous) / previous) * 100);
            lines.push(`- **Change:** ${pct}% ${current < previous ? 'fewer' : 'more'} matches than ${window}.`);
        }
    }
    const rules = topCounts(index.rules, 3);
    if (rules.length) lines.push(`- **Most frequent rules:** ${rules.map(([id, b]) => `${id}${index.ruleDescriptions.get(id) ? ` ${index.ruleDescriptions.get(id).trim()}` : ''} (${fmt(b)})`).join('; ')}.`);
    const agents = topCounts(index.agentCounts, 3);
    if (agents.length) lines.push(`- **Most active agents:** ${agents.map(([name, b]) => `${name} (${fmt(b)})`).join('; ')}.`);
    const ips = topCounts(index.ipCounts, 3);
    if (ips.length) lines.push(`- **Top source IPs:** ${ips.map(([ip, b]) => `${ip} (${fmt(b)})`).join('; ')}.`);
    const levels = [...index.severityCounts.entries()].filter(([, count]) => count > 0).sort((a, b) => b[0] - a[0]);
    if (levels.length) lines.push(`- **Highest severity:** level ${levels[0][0]} (${plural(levels[0][1], 'match', 'matches')}).`);
    if (index.comparison) {
        const fresh = [...index.comparison.byRule.entries()].filter(([, c]) => c.previous.max === 0 && c.current.min > 0)
            .sort((a, b) => b[1].current.min - a[1].current.min).slice(0, 5).map(([id]) => id);
        if (fresh.length) lines.push(`- **New this period:** rule${fresh.length > 1 ? 's' : ''} ${fresh.join(', ')} (not seen in ${index.comparison.window}).`);
    }
    if (index.agents.length) {
        const statuses = new Map();
        for (const a of index.agents) statuses.set(a.status ?? 'unknown', (statuses.get(a.status ?? 'unknown') || 0) + 1);
        lines.push(`- **Agent status:** ${[...statuses.entries()].map(([status, count]) => `${status} ${count}`).join('; ')}.`);
    }
    if (!index.allAggregated && index.searches.some(s => !s.failed && !s.complete)) {
        lines.push('- **Counts** are from the most recent records retrieved, not from every match.');
    }
    return lines.length ? `**Summary of the results**\n${lines.join('\n')}` : '';
}

/** Renders verified claims under the code-written header. */
export function renderGroundedReport(index, kept) {
    const out = [renderHeader(index)];
    const line = c => `${c.text}${c.fromMemory ? ' _(from a past investigation)_' : ''}`;
    if (kept.answer.length) out.push(kept.answer.map(line).join(' '));
    for (const section of ['findings', 'assessment', 'next_steps']) {
        if (kept[section].length) out.push(`**${SECTION_TITLES[section]}**\n${kept[section].map(c => `- ${line(c)}`).join('\n')}`);
    }
    return out.join('\n\n');
}

/** The answer when there is no basis for an analysis: the header, a plain statement, and the raw counts. */
/** Lines that close an answer without verified AI analysis: say so plainly, once, at the end. */
export const SUMMARY_NOTES = {
    modelUnavailable: '_AI analysis is not included: the analysis model could not be reached. This summary is calculated directly from the search results._',
    withheld: "_AI analysis is not included: the model's response could not be verified against the search results and was withheld. This summary is calculated directly from the search results._",
    calculated: '_This summary is calculated directly from the search results._'
};

/** An answer without AI analysis: the header, an optional lead statement, the results summary, and the closing note. */
export function renderInsufficient(index, statement, note = SUMMARY_NOTES.calculated) {
    return [renderHeader(index), statement, renderEvidenceSummary(index), note].filter(Boolean).join('\n\n');
}

export function renderNoResults(index) {
    const windows = [...new Set(index.searches.filter(s => !s.failed).map(s => s.window.text))];
    const statement = index.anySearchSucceeded
        ? `**No matching records** for ${windows.join(' or ')}. Nothing in the data searched answers this question.`
        : 'I found no data for your query.';
    return [renderHeader(index), statement].join('\n\n');
}

export function renderSearchFailed(index) {
    return [renderHeader(index), '**The search could not be completed**, so nothing can be concluded about this question. Try again, or check the connection to OpenSearch and Wazuh.'].join('\n\n');
}

/** "The 20 most recent logs": the header, then exactly those records, newest first (F-68). No model. */
export function renderRecentRecords(index, count) {
    const { records, retrieved } = mostRecentRecords(index, count);
    const total = index.totalMatches;
    const lead = records.length < count && total <= retrieved
        ? `**Only ${plural(records.length, 'record')} matched**, newest first:`
        : count === 1
            ? `**The most recent record** of ${plural(total, 'match', 'matches')}:`
            : `**The ${count} most recent records** of ${plural(total, 'match', 'matches')}, newest first:`;
    const more = retrieved > records.length ? `\n\nAll ${retrieved.toLocaleString('en-US')} records retrieved are under View Full Details.` : '';
    return `${renderHeader(index)}\n\n${lead}\n\n${listingTable(records)}${more}`;
}
