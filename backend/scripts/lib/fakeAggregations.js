/**
 * A tiny stand-in for OpenSearch aggregations, for tests and synthetic evals only. It answers the
 * aggregation request built by src/integrations/opensearch.integration.js (buildAggregationQuery):
 * filter aggregations named `current` and `previous`, each holding `terms` aggregations (with an
 * optional one-bucket `terms` sub-aggregation). Records are given per window, so no date maths is
 * needed: `current` is evaluated over `current`, `previous` over `previous`.
 */

const get = (obj, path) => path.split('.').reduce((v, k) => (v && typeof v === 'object' ? v[k] : undefined), obj);
const asList = v => (v === undefined || v === null ? [] : Array.isArray(v) ? v : [v]);

function terms(records, spec) {
    const { field, size = 10 } = spec.terms;
    const groups = new Map();
    for (const record of records) {
        for (const value of asList(get(record, field))) {
            const key = typeof value === 'number' ? value : String(value);
            if (!groups.has(key)) groups.set(key, []);
            groups.get(key).push(record);
        }
    }
    const sorted = [...groups.entries()].sort((a, b) => b[1].length - a[1].length || String(a[0]).localeCompare(String(b[0])));
    const kept = sorted.slice(0, size);
    return {
        doc_count_error_upper_bound: 0,
        sum_other_doc_count: sorted.slice(size).reduce((n, [, list]) => n + list.length, 0),
        buckets: kept.map(([key, list]) => {
            const bucket = { key, doc_count: list.length };
            for (const [name, sub] of Object.entries(spec.aggs ?? {})) bucket[name] = terms(list, sub);
            return bucket;
        })
    };
}

function window(records, spec) {
    const out = { doc_count: records.length };
    for (const [name, sub] of Object.entries(spec.aggs ?? {})) out[name] = terms(records, sub);
    return out;
}

export const isAggregationRequest = body => body?.size === 0 && Boolean(body?.aggs);

/** Returns an axios-shaped response for an aggregation request. */
export function fakeAggregationResponse(body, { current = [], previous = [] } = {}) {
    const aggregations = {};
    if (body.aggs.current) aggregations.current = window(current, body.aggs.current);
    if (body.aggs.previous) aggregations.previous = window(previous, body.aggs.previous);
    return { status: 200, data: { hits: { total: { value: current.length + previous.length }, hits: [] }, aggregations } };
}
