/**
 * Everything the report is allowed to say, indexed from the tool results of one run (Phase 4).
 *
 * Built once per run from the executor's results, and used three ways:
 *  - the evidence sent to the report model (counts, entities and techniques it may cite),
 *  - verifying every citation and every entity in the model's claims (grounding.js),
 *  - the parts of the report the code writes itself (sources, time window, evidence summary).
 *
 * Counts are taken from the records each search returned (at most 200, newest first) plus the exact
 * total OpenSearch reports. When a search matched more than it returned, the true count for a rule,
 * agent or IP is only known to lie between its count in the returned records and that count plus the
 * records not returned. Those bounds are what a cited count is checked against.
 */

export const IPV4 = /(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?![\d.]*\d)/g;

const SOURCE_LABELS = {
    non_firewall: 'Wazuh alerts',
    all: 'Wazuh alerts',
    firewall: 'firewall events from Wazuh'
};

const get = (obj, path) => path.reduce((value, key) => (value && typeof value === 'object' ? value[key] : undefined), obj);
const asList = value => (value === undefined || value === null ? [] : Array.isArray(value) ? value : [value]);

const SRC_IP_PATHS = [['data', 'srcip'], ['data', 'src_ip'], ['data', 'win', 'eventdata', 'ipAddress'], ['srcip']];
const USER_PATHS = [['data', 'srcuser'], ['data', 'dstuser'], ['data', 'user'], ['data', 'win', 'eventdata', 'targetUserName']];

function stringsIn(value, out = []) {
    if (typeof value === 'string') out.push(value);
    else if (typeof value === 'number' && Number.isFinite(value)) out.push(String(value));
    else if (Array.isArray(value)) value.forEach(v => stringsIn(v, out));
    else if (value && typeof value === 'object') Object.values(value).forEach(v => stringsIn(v, out));
    return out;
}

function countBy(records, pick) {
    const counts = new Map();
    for (const record of records) {
        const key = pick(record);
        if (key === undefined || key === null || key === '') continue;
        counts.set(String(key), (counts.get(String(key)) || 0) + 1);
    }
    return counts;
}

const UNIT_WORDS = { s: 'second', m: 'minute', h: 'hour', H: 'hour', d: 'day', w: 'week', M: 'month', y: 'year' };

/** "the last 24 hours" for now-24h, "the last 7 days" for now-7d, "the last hour" for now-1h, or the explicit range. */
export function describeWindow(gte, lte) {
    if (!gte) return 'all time';
    const match = /^now-(\d+)([smhHdwMy])$/.exec(String(gte));
    if (match && !lte) {
        const n = Number(match[1]);
        const unit = UNIT_WORDS[match[2]];
        return n === 1 ? `the last ${unit}` : `the last ${n} ${unit}s`;
    }
    if (String(gte) === 'now/d' && !lte) return 'today';
    return `${gte} to ${lte || 'now'}`;
}

/**
 * results: the executor's tool results ({ tool, parameters, success, data, error }), in plan order.
 */
export function buildEvidenceIndex(results) {
    const searches = [];
    const agents = [];
    const memories = [];
    const unavailable = [];
    const searchCounters = {};

    for (const result of results) {
        if (result.tool === 'searchSecurityLogs') {
            const scope = result.data?.sourceScope ?? result.parameters?.sourceScope ?? 'all';
            const base = scope === 'firewall' ? 'firewallLogs' : 'searchSecurityLogs';
            searchCounters[base] = (searchCounters[base] || 0) + 1;
            const key = searchCounters[base] === 1 ? base : `${base}#${searchCounters[base]}`;
            const gte = result.parameters?.timeRange ?? null;
            const lte = result.parameters?.lteTime ?? null;
            const search = {
                key,
                scope,
                label: SOURCE_LABELS[scope] ?? 'Wazuh alerts',
                window: { gte, lte, text: describeWindow(gte, lte) },
                failed: !result.success,
                error: result.success ? null : (result.error || 'the search failed'),
                total: result.success ? (result.data?.totalHits ?? 0) : 0,
                records: result.success ? (result.data?.rawData ?? []) : []
            };
            search.returned = search.records.length;
            search.complete = search.total <= search.returned;
            searches.push(search);
            if (search.failed) unavailable.push({ source: search.label, reason: `the search failed (${search.error})` });
        } else if (result.tool === 'getEndpointStatus') {
            if (result.success) agents.push(...(result.data?.data ?? []));
            else unavailable.push({ source: 'Wazuh agent status', reason: `the request failed (${result.error || 'error'})` });
        } else if (result.tool === 'searchMemory' && result.success) {
            for (const content of asList(result.data)) memories.push({ ref: `memory#${memories.length + 1}`, content });
        } else if (result.success && result.data?.available === false) {
            const source = { lookupThreatIntel: 'threat intelligence', checkProcessList: 'process inspection' }[result.tool] ?? result.tool;
            unavailable.push({ source, reason: result.data.reason || 'not available' });
        }
    }

    const okSearches = searches.filter(s => !s.failed);
    const records = okSearches.flatMap(s => s.records);

    // Per-entity counts and bounds across all successful searches.
    const bounded = pick => {
        const out = new Map();
        for (const search of okSearches) {
            const missing = search.total - search.returned;
            for (const [key, n] of countBy(search.records, pick)) {
                const current = out.get(key) || { returned: 0, min: 0, max: 0 };
                current.returned += n;
                current.min += n;
                current.max += n + Math.max(missing, 0);
                out.set(key, current);
            }
        }
        return out;
    };
    const firstIp = record => SRC_IP_PATHS.map(p => get(record, p)).find(v => typeof v === 'string' && new RegExp(`^${IPV4.source}$`).test(v));

    const rules = bounded(r => get(r, ['rule', 'id']));
    const ruleDescriptions = new Map();
    for (const r of records) {
        const id = get(r, ['rule', 'id']);
        if (id !== undefined && !ruleDescriptions.has(String(id))) ruleDescriptions.set(String(id), get(r, ['rule', 'description']) ?? null);
    }
    const agentCounts = bounded(r => get(r, ['agent', 'name']));
    const ipCounts = bounded(firstIp);
    const mitre = new Set(records.flatMap(r => asList(get(r, ['rule', 'mitre', 'id']))).map(String));
    const levels = new Set(records.map(r => get(r, ['rule', 'level'])).filter(l => typeof l === 'number'));
    const cves = new Set(records.map(r => get(r, ['vulnerability', 'id'])).filter(Boolean).map(String));

    const agentNames = new Set([...records.map(r => get(r, ['agent', 'name'])), ...agents.map(a => a.name)].filter(Boolean).map(String));
    const agentIds = new Set([...records.map(r => get(r, ['agent', 'id'])), ...agents.map(a => a.id)].filter(Boolean).map(String));
    const users = new Set(records.flatMap(r => USER_PATHS.map(p => get(r, p))).filter(v => typeof v === 'string' && v && v !== 'N/A'));

    // Past investigations count as citable text, but claims citing them are labelled as such.
    const text = stringsIn([records, agents, memories.map(m => m.content)]).join('\n').toLowerCase();
    const ips = new Set(text.match(IPV4) ?? []);

    const totals = new Map(okSearches.map(s => [s.key, s.total]));
    if (agents.length || results.some(r => r.tool === 'getEndpointStatus' && r.success)) {
        const endpoint = results.find(r => r.tool === 'getEndpointStatus' && r.success);
        totals.set('getEndpointStatus', endpoint?.data?.total ?? agents.length);
    }
    const totalMatches = okSearches.reduce((sum, s) => sum + s.total, 0);

    return {
        searches,
        agents,
        memories,
        unavailable,
        totals,
        totalMatches,
        anySearchSucceeded: okSearches.length > 0,
        anySearchRan: searches.length > 0,
        rules,
        ruleDescriptions,
        agentCounts,
        ipCounts,
        mitre,
        levels,
        cves,
        agentNames,
        agentIds,
        users,
        ips,
        /** True when the token appears in the evidence as a whole word (case-insensitive). */
        mentions(token) {
            const escaped = String(token).toLowerCase().replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
            return new RegExp(`(?<![\\w.-])${escaped}(?![\\w-]|\\.\\d)`).test(text);
        }
    };
}

const top = (counts, n) => [...counts.entries()].sort((a, b) => b[1].returned - a[1].returned || a[0].localeCompare(b[0], 'en', { numeric: true })).slice(0, n);

/** Evidence for the report model: totals, counts it may cite, and a bounded sample of records. */
export function evidenceForModel(index, { sampleSize = 30 } = {}) {
    const searches = index.searches.map(s => {
        if (s.failed) return { key: s.key, source: s.label, window: s.window.text, failed: true, error: s.error };
        return {
            key: s.key,
            source: s.label,
            window: s.window.text,
            totalMatches: s.total,
            recordsRetrieved: s.returned,
            countsCover: s.complete ? 'all matches' : `the ${s.returned} most recent of ${s.total} matches`,
            sampleLogs: s.records.slice(0, sampleSize).map(log => ({
                time: log['@timestamp'] || log.vulnerability?.detected_at || null,
                ruleId: log.rule?.id ?? null,
                level: typeof log.rule?.level === 'number' ? log.rule.level : log.vulnerability?.severity ?? null,
                desc: log.rule?.description || log.vulnerability?.description || null,
                mitre: asList(log.rule?.mitre?.id),
                srcip: SRC_IP_PATHS.map(p => get(log, p)).find(Boolean) ?? null,
                user: USER_PATHS.map(p => get(log, p)).find(Boolean) ?? null,
                agent: log.agent?.name || log.agent?.id || null,
                cve: log.vulnerability?.id ?? null
            }))
        };
    });
    const asCounts = (counts, n, label) => top(counts, n).map(([value, c]) => ({ [label]: value, count: c.min === c.max ? c.min : { atLeast: c.min, atMost: c.max } }));
    return {
        searches,
        counts: {
            byRule: top(index.rules, 15).map(([id, c]) => ({ ruleId: id, description: index.ruleDescriptions.get(id), count: c.min === c.max ? c.min : { atLeast: c.min, atMost: c.max } })),
            byAgent: asCounts(index.agentCounts, 10, 'agent'),
            bySourceIp: asCounts(index.ipCounts, 10, 'ip')
        },
        mitreTechniques: [...index.mitre].sort(),
        agents: index.agents.slice(0, 100).map(a => ({ id: a.id, name: a.name, status: a.status, ip: a.ip })),
        agentsTotal: index.totals.get('getEndpointStatus') ?? null,
        pastInvestigations: index.memories.map(m => ({ ref: m.ref, content: m.content })),
        unavailableSources: index.unavailable
    };
}

export { top as topCounts };
