/**
 * Everything the report is allowed to say, indexed from the tool results of one run (Phase 4).
 *
 * Built once per run from the executor's results, and used three ways:
 *  - the evidence sent to the report model (counts, entities and techniques it may cite),
 *  - verifying every citation and every entity in the model's claims (grounding.js),
 *  - the parts of the report the code writes itself (sources, time window, evidence summary).
 *
 * Counts come from each search's aggregation request (Phase 5): exact over every match, for this
 * window and the same window a week earlier. When that request isn't available (it failed, or a
 * fixture recorded before Phase 5 is replayed), counts fall back to the records the search returned
 * (at most 200, newest first): the true count is then only known to lie between its count in those
 * records and that count plus the records not returned. Either way, each count is held as bounds
 * { min, max } (equal when exact) and a cited count is checked against them.
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
    const start = /^(\d{4}-\d{2}-\d{2})T(\d{2}:\d{2})/.exec(String(gte));
    if (start && !lte) return `since ${start[1]} ${start[2]} UTC`;
    return `${gte} to ${lte || 'now'}`;
}

/** "the same 24 hours one week earlier", or the shifted range when the window isn't relative. */
export function describePreviousWindow(gte, lte, previous) {
    const current = describeWindow(gte, lte);
    if (current.startsWith('the last ')) return `the same ${current.slice('the last '.length)} one week earlier`;
    if (current === 'today') return 'the same day one week earlier';
    if (!lte) return 'the same period one week earlier';
    return previous ? `${previous.gte} to ${previous.lte} (one week earlier)` : 'one week earlier';
}

/**
 * results: the executor's tool results ({ tool, parameters, success, data, error }), in plan order.
 */
/** options.compare: include the week-earlier comparison (only when the question asks for one; see comparison.js). */
export function buildEvidenceIndex(results, { compare = true } = {}) {
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
            const minSeverity = result.parameters?.minSeverity ?? null;
            const aggs = result.success ? result.data?.aggregations ?? null : null;
            const search = {
                key,
                scope,
                minSeverity,
                label: `${SOURCE_LABELS[scope] ?? 'Wazuh alerts'}${minSeverity ? ` at level ${minSeverity} and above` : ''}`,
                aggs: aggs?.available && aggs.current ? aggs : null,
                aggError: aggs && !aggs.available ? aggs.error : null,
                window: { gte, lte, text: describeWindow(gte, lte), previousText: describePreviousWindow(gte, lte, aggs?.previousWindow) },
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

    // Per-entity counts and bounds across all successful searches: exact from the aggregation where a
    // search has one (plus OpenSearch's own error bound), otherwise bounded by the records returned.
    const bounded = (pick, aggPick) => {
        const out = new Map();
        const add = (key, returned, min, max) => {
            const current = out.get(key) || { returned: 0, min: 0, max: 0 };
            current.returned += returned;
            current.min += min;
            current.max += max;
            out.set(key, current);
        };
        for (const search of okSearches) {
            const sample = countBy(search.records, pick);
            const agg = search.aggs ? aggPick(search.aggs.current) : null;
            if (agg) {
                for (const b of agg.buckets) add(b.key, sample.get(b.key) || 0, b.count, b.count + b.error);
                // In the sample but outside the aggregation's top buckets: at least its sample count, at most everything else.
                for (const [key, n] of sample) if (!agg.buckets.some(b => b.key === key)) add(key, n, n, Math.max(agg.otherCount, n));
            } else {
                const missing = Math.max(search.total - search.returned, 0);
                for (const [key, n] of sample) add(key, n, n, n + missing);
            }
        }
        return out;
    };
    const exactSearches = okSearches.filter(s => s.aggs);
    const countsExact = okSearches.length > 0 && exactSearches.length === okSearches.length
        && exactSearches.every(s => [...s.aggs.current.byRule, ...s.aggs.current.byAgent].every(b => b.error === 0));
    const firstIp = record => SRC_IP_PATHS.map(p => get(record, p)).find(v => typeof v === 'string' && new RegExp(`^${IPV4.source}$`).test(v));

    const rules = bounded(r => get(r, ['rule', 'id']), w => ({ buckets: w.byRule, otherCount: w.meta.rule.otherCount }));
    const ruleDescriptions = new Map();
    for (const s of exactSearches) for (const b of s.aggs.current.byRule) if (b.description && !ruleDescriptions.has(b.key)) ruleDescriptions.set(b.key, b.description);
    for (const r of records) {
        const id = get(r, ['rule', 'id']);
        if (id !== undefined && !ruleDescriptions.has(String(id))) ruleDescriptions.set(String(id), get(r, ['rule', 'description']) ?? null);
    }
    const agentCounts = bounded(r => get(r, ['agent', 'name']), w => ({ buckets: w.byAgent, otherCount: w.meta.agent.otherCount }));
    const ipCounts = bounded(firstIp, w => ({ buckets: w.bySourceIp, otherCount: w.meta.srcip.otherCount + w.meta.winIp.otherCount }));
    const aggKeys = name => exactSearches.flatMap(s => s.aggs.current[name].map(b => b.key));
    const mitre = new Set([...records.flatMap(r => asList(get(r, ['rule', 'mitre', 'id']))), ...aggKeys('byMitre')].map(String));
    const levels = new Set([...records.map(r => get(r, ['rule', 'level'])), ...aggKeys('byLevel')].filter(l => typeof l === 'number'));
    const severityCounts = new Map();
    // Level counts from the aggregation cover every match, even when other counts are approximate.
    if (okSearches.length > 0 && exactSearches.length === okSearches.length) {
        for (const s of exactSearches) for (const b of s.aggs.current.byLevel) severityCounts.set(b.key, (severityCounts.get(b.key) || 0) + b.count);
    } else {
        for (const [level, n] of countBy(records, r => get(r, ['rule', 'level']))) severityCounts.set(Number(level), n);
    }

    // Week-on-week comparison, when asked for and every successful search has both windows aggregated.
    let comparison = null;
    if (compare && okSearches.length > 0 && okSearches.every(s => s.aggs?.previous)) {
        const byRule = new Map();
        for (const s of okSearches) {
            for (const [period, win] of [['current', s.aggs.current], ['previous', s.aggs.previous]]) {
                for (const b of win.byRule) {
                    const entry = byRule.get(b.key) || { current: { min: 0, max: 0 }, previous: { min: 0, max: 0 } };
                    entry[period].min += b.count;
                    entry[period].max += b.count + b.error;
                    byRule.set(b.key, entry);
                }
            }
        }
        // A rule absent from a window's buckets: 0 if that window had nothing else, otherwise up to the rest.
        for (const entry of byRule.values()) {
            for (const period of ['current', 'previous']) {
                if (entry[period].max === 0) entry[period].max = okSearches.reduce((n, s) => n + s.aggs[period].meta.rule.otherCount, 0);
            }
        }
        comparison = {
            window: okSearches[0].window.previousText,
            total: {
                current: okSearches.reduce((n, s) => n + s.aggs.current.total, 0),
                previous: okSearches.reduce((n, s) => n + s.aggs.previous.total, 0)
            },
            previousTotals: new Map(okSearches.map(s => [s.key, s.aggs.previous.total])),
            byRule
        };
        for (const s of okSearches) for (const b of s.aggs.previous.byRule) if (b.description && !ruleDescriptions.has(b.key)) ruleDescriptions.set(b.key, b.description);
    }
    const cves = new Set(records.map(r => get(r, ['vulnerability', 'id'])).filter(Boolean).map(String));

    const agentNames = new Set([...records.map(r => get(r, ['agent', 'name'])), ...agents.map(a => a.name), ...aggKeys('byAgent')].filter(Boolean).map(String));
    const agentIds = new Set([...records.map(r => get(r, ['agent', 'id'])), ...agents.map(a => a.id)].filter(Boolean).map(String));
    const users = new Set(records.flatMap(r => USER_PATHS.map(p => get(r, p))).filter(v => typeof v === 'string' && v && v !== 'N/A'));

    // Past investigations count as citable text, but claims citing them are labelled as such.
    const aggText = exactSearches.flatMap(s => [s.aggs.current, s.aggs.previous].filter(Boolean)
        .flatMap(w => [...w.byRule, ...w.byAgent, ...w.bySourceIp, ...w.byMitre].flatMap(b => [b.key, b.description ?? ''])));
    const text = stringsIn([records, agents, memories.map(m => m.content), aggText]).join('\n').toLowerCase();
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
        countsExact,
        // Every successful search has an aggregation: counts cover every match (maybe approximately).
        allAggregated: okSearches.length > 0 && exactSearches.length === okSearches.length,
        severityCounts,
        comparison,
        comparisonRequested: compare,
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

const exactOrBounds = b => (b.min === b.max ? b.min : { atLeast: b.min, atMost: b.max });

const top = (counts, n) => [...counts.entries()].sort((a, b) => b[1].min - a[1].min || b[1].returned - a[1].returned || a[0].localeCompare(b[0], 'en', { numeric: true })).slice(0, n);

/** Evidence for the report model: totals, counts it may cite, and a bounded sample of records. */
// Aggregated counts cover every match even when OpenSearch marks them approximate, so a few example
// records are enough; only without aggregations do more examples help (F-67 follow-up: this used to
// send 30 per search whenever counts were approximate, tripling the request).
export function evidenceForModel(index, { sampleSize = index.allAggregated ? 10 : 30 } = {}) {
    const searches = index.searches.map(s => {
        if (s.failed) return { key: s.key, source: s.label, window: s.window.text, failed: true, error: s.error };
        return {
            key: s.key,
            source: s.label,
            window: s.window.text,
            totalMatches: s.total,
            recordsRetrieved: s.returned,
            countsCover: s.aggs ? 'all matches (aggregated)' : s.complete ? 'all matches' : `the ${s.returned} most recent of ${s.total} matches`,
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
    const comparison = index.comparison && {
        previousWindow: index.comparison.window,
        total: index.comparison.total,
        previousTotals: Object.fromEntries(index.comparison.previousTotals),
        byRule: [...index.comparison.byRule.entries()]
            .sort((a, b) => b[1].current.min - a[1].current.min || b[1].previous.min - a[1].previous.min)
            .slice(0, 15)
            .map(([ruleId, c]) => ({ ruleId, current: exactOrBounds(c.current), previous: exactOrBounds(c.previous) })),
        newThisWindow: [...index.comparison.byRule.entries()].filter(([, c]) => c.previous.max === 0 && c.current.min > 0).map(([id]) => id),
        notSeenThisWindow: [...index.comparison.byRule.entries()].filter(([, c]) => c.current.max === 0 && c.previous.min > 0).map(([id]) => id)
    };
    return {
        searches,
        countsExact: index.countsExact,
        countsCoverAllMatches: index.allAggregated,
        counts: {
            byRule: top(index.rules, 15).map(([id, c]) => ({ ruleId: id, description: index.ruleDescriptions.get(id), count: c.min === c.max ? c.min : { atLeast: c.min, atMost: c.max } })),
            byAgent: asCounts(index.agentCounts, 10, 'agent'),
            bySourceIp: asCounts(index.ipCounts, 10, 'ip'),
            bySeverity: [...index.severityCounts.entries()].sort((a, b) => a[0] - b[0]).map(([level, count]) => ({ level, count }))
        },
        comparison: comparison || null,
        mitreTechniques: [...index.mitre].sort(),
        agents: index.agents.slice(0, 100).map(a => ({ id: a.id, name: a.name, status: a.status, ip: a.ip })),
        agentsTotal: index.totals.get('getEndpointStatus') ?? null,
        pastInvestigations: index.memories.map(m => ({ ref: m.ref, content: m.content })),
        unavailableSources: index.unavailable
    };
}

export { top as topCounts };

/**
 * Shrinks the model's evidence until its compact JSON fits maxChars (fix 3): example records first,
 * then the lists, longest first. Returns { evidence, trimmed } where trimmed names each step taken;
 * the evidence carries the same list so the model knows what it isn't seeing. Verification always
 * uses the full index, so nothing true becomes unverifiable by being trimmed here.
 */
export function fitEvidenceToBudget(evidence, maxChars) {
    const ev = structuredClone(evidence);
    const trimmed = [];
    const size = () => JSON.stringify({ ...ev, trimmed }).length;
    const cut = (list, n) => (Array.isArray(list) && list.length > n ? list.slice(0, n) : list);
    const steps = [
        ['example records cut to 5 per search', () => ev.searches.forEach(s => { if (s.sampleLogs) s.sampleLogs = cut(s.sampleLogs, 5); })],
        ['example records left out', () => ev.searches.forEach(s => { if (s.sampleLogs) s.sampleLogs = []; })],
        ['agent list cut to 20', () => { ev.agents = cut(ev.agents, 20); }],
        ['week-earlier comparison cut to the top 5 rules', () => { if (ev.comparison) ev.comparison.byRule = cut(ev.comparison.byRule, 5); }],
        ['counts cut to the top 8 rules, 5 agents and 5 IPs', () => { ev.counts.byRule = cut(ev.counts.byRule, 8); ev.counts.byAgent = cut(ev.counts.byAgent, 5); ev.counts.bySourceIp = cut(ev.counts.bySourceIp, 5); }],
        ['past investigations cut to 1', () => { ev.pastInvestigations = cut(ev.pastInvestigations, 1); }],
        ['agent list left out', () => { ev.agents = []; }],
        ['rule descriptions shortened', () => ev.counts.byRule.forEach(r => { if (typeof r.description === 'string') r.description = r.description.slice(0, 40); })],
        ['counts cut to the top 3 rules, 3 agents and 3 IPs', () => { ev.counts.byRule = cut(ev.counts.byRule, 3); ev.counts.byAgent = cut(ev.counts.byAgent, 3); ev.counts.bySourceIp = cut(ev.counts.bySourceIp, 3); }],
        ['week-earlier comparison left out of the rule list', () => { if (ev.comparison) { ev.comparison.byRule = []; ev.comparison.notSeenThisWindow = []; } }],
        ['severity breakdown and technique list left out', () => { ev.counts.bySeverity = []; ev.mitreTechniques = []; }]
    ];
    for (const [label, apply] of steps) {
        if (size() <= maxChars) break;
        apply();
        trimmed.push(label);
    }
    if (trimmed.length) ev.trimmed = trimmed;
    return { evidence: ev, trimmed };
}
