import { test } from 'node:test';
import assert from 'node:assert/strict';
import { setTestEnv } from './helpers.js';

setTestEnv();
const { buildEvidenceIndex } = await import('../src/agent/evidenceIndex.js');
const { renderEvidenceSummary } = await import('../src/agent/grounding.js');

const META = { rule: { otherCount: 0 }, agent: { otherCount: 0 }, srcip: { otherCount: 0 }, winIp: { otherCount: 0 } };
const rec = { '@timestamp': '2026-10-12T08:00:00Z', rule: { id: '60104', level: 5, description: 'Windows audit failure event' }, agent: { name: 'gbb_portal_02' }, data: { srcip: '10.128.52.36' } };
const search = aggregations => ({
    tool: 'searchSecurityLogs', success: true, parameters: { timeRange: 'now-24h', sourceScope: 'non_firewall' },
    data: { totalHits: 5708019, rawData: [rec, rec], sourceScope: 'non_firewall', aggregations }
});
const window = error => ({
    total: 5708019,
    byRule: [{ key: '60104', count: 1386641, error, description: 'Windows audit failure event' }],
    byAgent: [{ key: 'gbb_portal_02', count: 2360911, error }],
    bySourceIp: [{ key: '10.128.52.36', count: 1582391, error }],
    byLevel: [], byMitre: [], meta: META
});

test('counts from the aggregation are labelled as counted over every match, with thousands separators', () => {
    const summary = renderEvidenceSummary(buildEvidenceIndex([search({ available: true, current: window(0), previous: null })]));
    assert.match(summary, /\*\*Most frequent rules:\*\* rule 60104 \(Windows audit failure event\): 1,386,641\./);
    assert.match(summary, /gbb_portal_02: 2,360,911/);
    assert.match(summary, /10\.128\.52\.36: 1,582,391/);
    assert.doesNotMatch(summary, /most recent records retrieved|at least/);
});

test('approximate aggregation counts (OpenSearch error bound) say "about", never "in the records retrieved" or "at least"', () => {
    const summary = renderEvidenceSummary(buildEvidenceIndex([search({ available: true, current: window(12), previous: null })]));
    assert.match(summary, /\*\*Most frequent rules \(counted over every match; OpenSearch's counts are approximate\):\*\* rule 60104 \(Windows audit failure event\): about 1,386,641\./);
    assert.match(summary, /10\.128\.52\.36: about 1,582,391/);
    assert.doesNotMatch(summary, /most recent records retrieved|at least/);
});

test('without aggregations, sample counts keep saying where they come from', () => {
    const summary = renderEvidenceSummary(buildEvidenceIndex([search({ available: false, error: 'boom' })]));
    assert.match(summary, /\*\*Most frequent rules in the most recent records retrieved:\*\* rule 60104 \(Windows audit failure event\): at least 2\./);
});
