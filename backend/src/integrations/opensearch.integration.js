import axios from 'axios';
import { OPENSEARCH_URL, WAZUH_USER, WAZUH_PASSWORD } from '../config/env.js';
import { httpsAgent } from '../config/https.js';
import { fixturesEnabled, replayHttp } from '../recording/replay.js';
import { pathFromBase } from '../recording/common.js';
import { runLog } from '../observability/runContext.js';

const UNIT_SECONDS = { s: 1, m: 60, h: 3600, H: 3600, d: 86400, w: 604800, M: 2592000, y: 31536000 };
const WEEK_SECONDS = 604800;

const dateMathSeconds = value => {
    const match = /^now-(\d+)([smhHdwMy])$/.exec(String(value));
    return match ? Number(match[1]) * UNIT_SECONDS[match[2]] : null;
};
const asDateMath = seconds => (seconds % 3600 === 0 ? `now-${seconds / 3600}h` : seconds % 60 === 0 ? `now-${seconds / 60}m` : `now-${seconds}s`);

/**
 * The same window shifted one week earlier, for the week-on-week comparison (Phase 5).
 * now-24h -> now-192h..now-168h; ISO ranges are shifted by 7 days. Returns null if it can't be computed.
 * Months and years in date maths are taken as 30 and 365 days.
 */
export function previousWindow(gte, lte) {
    const start = dateMathSeconds(gte);
    if (start !== null) {
        const end = lte ? dateMathSeconds(lte) : 0;
        if (end === null) return null;
        return { gte: asDateMath(start + WEEK_SECONDS), lte: asDateMath(end + WEEK_SECONDS) };
    }
    const from = Date.parse(gte);
    if (Number.isNaN(from)) return null;
    const shift = iso => new Date(Date.parse(iso) - WEEK_SECONDS * 1000).toISOString();
    if (!lte) return { gte: shift(gte), lte: asDateMath(WEEK_SECONDS) };
    return Number.isNaN(Date.parse(lte)) ? null : { gte: shift(gte), lte: shift(lte) };
}

const termsAgg = (field, size, extra = {}) => ({ terms: { field, size, show_term_doc_count_error: true, ...extra } });
const WINDOW_AGGS = {
    by_rule: { ...termsAgg('rule.id', 50), aggs: { description: { terms: { field: 'rule.description', size: 1 } } } },
    by_agent: termsAgg('agent.name', 20),
    by_srcip: termsAgg('data.srcip', 20),
    by_win_ip: termsAgg('data.win.eventdata.ipAddress', 20),
    by_level: termsAgg('rule.level', 20),
    by_mitre: termsAgg('rule.mitre.id', 30)
};

/**
 * One size-0 request with exact counts over every match, for this window and the week before.
 * Same matching conditions as the record search; only the time filter differs. Sent separately so the
 * record search stays byte-identical to what fixtures recorded before Phase 5.
 */
export function buildAggregationQuery(esQuery, current, previous) {
    const windowFilters = [{ range: { '@timestamp': current } }];
    if (previous) windowFilters.push({ range: { '@timestamp': previous } });
    const otherFilters = esQuery.query.bool.filter.filter(f => !f.range?.['@timestamp']);
    const aggs = { current: { filter: { range: { '@timestamp': current } }, aggs: WINDOW_AGGS } };
    if (previous) aggs.previous = { filter: { range: { '@timestamp': previous } }, aggs: WINDOW_AGGS };
    return {
        size: 0,
        track_total_hits: true,
        query: {
            bool: {
                ...esQuery.query.bool,
                filter: [...otherFilters, { bool: { should: windowFilters, minimum_should_match: 1 } }]
            }
        },
        aggs
    };
}

const bucketsOf = agg => (agg?.buckets ?? []).map(b => ({ key: String(b.key), count: b.doc_count, error: b.doc_count_error_upper_bound ?? 0, description: b.description?.buckets?.[0]?.key ?? null }));
const aggMeta = agg => ({ otherCount: agg?.sum_other_doc_count ?? 0, error: agg?.doc_count_error_upper_bound ?? 0 });

function parseWindow(win) {
    if (!win) return null;
    const ips = new Map();
    for (const b of [...bucketsOf(win.by_srcip), ...bucketsOf(win.by_win_ip)]) {
        const current = ips.get(b.key) ?? { key: b.key, count: 0, error: 0 };
        current.count += b.count;
        current.error += b.error;
        ips.set(b.key, current);
    }
    return {
        total: win.doc_count,
        byRule: bucketsOf(win.by_rule),
        byAgent: bucketsOf(win.by_agent),
        bySourceIp: [...ips.values()].sort((a, b) => b.count - a.count),
        byLevel: bucketsOf(win.by_level).map(b => ({ ...b, key: Number(b.key) })),
        byMitre: bucketsOf(win.by_mitre),
        meta: { rule: aggMeta(win.by_rule), agent: aggMeta(win.by_agent), srcip: aggMeta(win.by_srcip), winIp: aggMeta(win.by_win_ip) }
    };
}

/**
 * Capability: searchSecurityLogs
 * Searches underlying data lakes or SIEM indexes for security logs matching specific criteria.
 */
export async function searchSecurityLogs(params) {
    const { timeRange, lteTime, minSeverity, extractedIPs, intent, cleanedSearchText, sourceScope = 'all' } = params;

    const timeFilter = { gte: timeRange };
    if (lteTime) timeFilter.lte = lteTime;

    let esQuery = {
        query: {
            bool: {
                must: [],
                filter: [
                    { range: { "@timestamp": timeFilter } }
                ]
            }
        },
        sort: [{ "@timestamp": { order: "desc" } }],
        // The exact total is obtained by track_total_hits. Returning a bounded
        // recent sample keeps the UI and reasoning pass responsive.
        size: 200,
        track_total_hits: true
    };

    if (minSeverity !== null) {
        esQuery.query.bool.filter.push({ range: { "rule.level": { gte: minSeverity } } });
    }

    if (extractedIPs && extractedIPs.length > 0) {
        esQuery.query.bool.must.push({ multi_match: { query: extractedIPs[0], fields: ["*ip*", "*ip", "ip", "full_log", "agent.ip", "data.win.eventdata.ipAddress"], lenient: true } });
    }

    // Wazuh firewall integrations use different decoders and rule groups. This
    // map captures the common identifiers while keeping all matching records in
    // the normal wazuh-alerts index.
    const firewallSignals = {
        bool: {
            should: [
                'firewall', 'iptables', 'nftables', 'netfilter', 'ufw',
                'pfsense', 'fortigate', 'pan-os', 'palo alto', 'cisco asa'
            ].flatMap(signal => [
                { match: { 'rule.groups': signal } },
                { match_phrase: { 'rule.description': signal } },
                { match_phrase: { full_log: signal } },
                { match: { 'decoder.name': signal } }
            ]),
            minimum_should_match: 1
        }
    };

    if (sourceScope === 'firewall') {
        esQuery.query.bool.must.push(firewallSignals);
    } else if (sourceScope === 'non_firewall') {
        esQuery.query.bool.must_not = [firewallSignals];
    }

    if (intent === 'brute_force') {
        esQuery.query.bool.must.push({
            bool: {
                should: [
                    { match: { "rule.groups": "authentication_failed" } },
                    { match: { "rule.groups": "authentication_failures" } },
                    { match: { "rule.groups": "sshd" } },
                    { match_phrase: { "rule.description": "failed" } },
                    { match_phrase: { "rule.description": "failure" } }
                ],
                minimum_should_match: 1
            }
        });
    } else if (intent === 'vulnerabilities') {
        esQuery.query.bool.must.push({
            bool: {
                should: [
                    { match: { "rule.groups": "vulnerability-detector" } },
                    { match_phrase: { "rule.description": "vulnerability" } },
                    { match_phrase: { "rule.description": "cve" } }
                ],
                minimum_should_match: 1
            }
        });
    } else if (cleanedSearchText && cleanedSearchText.length > 2 && (!extractedIPs || extractedIPs.length === 0)) {
        esQuery.query.bool.must.push({ multi_match: { query: cleanedSearchText, fields: ["rule.description", "full_log"], lenient: true } });
    }

    const authString = Buffer.from(`${WAZUH_USER}:${WAZUH_PASSWORD}`).toString('base64');
    
    let targetIndex = `${OPENSEARCH_URL}/wazuh-alerts-*/_search`;
    if (intent === 'vulnerabilities') {
        targetIndex = `${OPENSEARCH_URL}/wazuh-states-vulnerabilities-*,wazuh-alerts-*/_search`;
    }

    // FIXTURES=1: return the response recorded for this exact query instead of calling OpenSearch.
    const osResponse = fixturesEnabled()
        ? replayHttp('opensearch', pathFromBase(targetIndex, OPENSEARCH_URL), esQuery)
        : await axios.post(targetIndex, esQuery, {
            headers: { Authorization: `Basic ${authString}`, 'Content-Type': 'application/json' },
            httpsAgent
        });

    const rawData = osResponse.data.hits.hits.map(hit => hit._source);
    const totalHits = osResponse.data.hits.total.value || rawData.length;

    // Exact counts for this window and the week before (Phase 5). Not for vulnerability searches, whose
    // records have different fields. A failure here never fails the search: the report falls back to
    // counts from the records returned, and says so.
    let aggregations = null;
    let aggregationQuery = null;
    if (intent !== 'vulnerabilities') {
        const previous = previousWindow(timeRange, lteTime);
        aggregationQuery = buildAggregationQuery(esQuery, timeFilter, previous);
        try {
            const aggResponse = fixturesEnabled()
                ? replayHttp('opensearch', pathFromBase(targetIndex, OPENSEARCH_URL), aggregationQuery)
                : await axios.post(targetIndex, aggregationQuery, {
                    headers: { Authorization: `Basic ${authString}`, 'Content-Type': 'application/json' },
                    httpsAgent
                });
            const aggs = aggResponse.data.aggregations ?? {};
            aggregations = { available: true, current: parseWindow(aggs.current), previous: parseWindow(aggs.previous), previousWindow: previous };
        } catch (error) {
            // In replay, a fixture captured before Phase 5 has no aggregation request: same fallback.
            runLog.warn(`[OpenSearch] Aggregation request failed; using counts from the records returned: ${error.message}`);
            aggregations = { available: false, error: error.message, previousWindow: previous };
        }
    }

    return {
        rawData,
        totalHits,
        targetIndex,
        sourceScope,
        // The exact request body sent, for the run record. Not passed to the model.
        query: esQuery,
        aggregations,
        aggregationQuery
    };
}
