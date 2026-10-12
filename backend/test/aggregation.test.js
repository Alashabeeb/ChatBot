import { test } from 'node:test';
import assert from 'node:assert/strict';
import { setTestEnv, stubBackends, flushBackgroundWork, USER_ID, askFoundationArgs, isFirewallScopeQuery } from './helpers.js';

setTestEnv();
const { initDatabase } = await import('../src/config/db.js');
const { runAgentWorkflow } = await import('../src/agent/runtime.js');
const { RunModel } = await import('../src/models/Run.js');
const { previousWindow } = await import('../src/integrations/opensearch.integration.js');
const { applySeverityFloor } = await import('../src/agent/severityFloor.js');

initDatabase();

const quiet = t => { for (const level of ['log', 'warn', 'error']) t.mock.method(console, level, () => {}); };
const search = (extra = {}) => ({ tool: 'searchSecurityLogs', parameters: { timeRange: 'now-24h', intent: 'alerts', extractedIPs: [], minSeverity: null, cleanedSearchText: '', ...extra } });
const PLAN = { thought: 't', tools: [search()] };
const rec = (ruleId, agent = 'web-01', ip = '203.0.113.9', level = 5) => ({
    '@timestamp': '2026-10-12T08:00:00Z',
    rule: { id: ruleId, level, description: `rule ${ruleId} description`, mitre: { id: ['T1110'] } },
    agent: { name: agent },
    data: { srcip: ip }
});
const times = (n, make) => Array.from({ length: n }, (_, i) => make(i));
// 1,500 matches behind a sample of 5: the aggregation sees all of them.
const ALL = [...times(1200, () => rec('5710')), ...times(300, () => rec('550', 'web-02', '198.51.100.4', 7))];
const SAMPLE = ALL.slice(0, 3).concat(ALL.slice(1200, 1202));
const LAST_WEEK = times(10, () => rec('5710'));

const cite = (kind, ref, count) => (count === undefined ? { kind, ref } : { kind, ref, count });
const logsFor = (url, body) => (isFirewallScopeQuery(body) ? [] : SAMPLE);
// The search itself reports the true total, as OpenSearch does with track_total_hits.
const sampledLogs = { logs: logsFor, aggLogs: (url, body) => (isFirewallScopeQuery(body) ? [] : ALL), previousLogs: LAST_WEEK };

async function ask(t, { report = { answer: [] }, plan = PLAN, question = 'show me failed logons today', ...backends } = {}) {
    quiet(t);
    const stubs = stubBackends(t, { llm: { plan, report: JSON.stringify(report) }, ...backends });
    const response = await runAgentWorkflow(question, [], USER_ID);
    await flushBackgroundWork();
    return { response, stubs, run: RunModel.findById(response.request_id) };
}
const modelEvidence = stubs => {
    const call = stubs.llmCalls.find(m => m[0].content.includes('Reasoning Engine'));
    const { prompt } = askFoundationArgs(call);
    return JSON.parse(prompt.content.slice(prompt.content.indexOf('{')));
};

test('previous window: the same window shifted one week earlier', () => {
    assert.deepEqual(previousWindow('now-24h', null), { gte: 'now-192h', lte: 'now-168h' });
    assert.deepEqual(previousWindow('now-7d', null), { gte: 'now-336h', lte: 'now-168h' });
    assert.deepEqual(previousWindow('now-1h', null), { gte: 'now-169h', lte: 'now-168h' });
    assert.deepEqual(previousWindow('2026-10-05T00:00:00Z', '2026-10-06T00:00:00Z'), { gte: '2026-09-28T00:00:00.000Z', lte: '2026-09-29T00:00:00.000Z' });
    assert.equal(previousWindow('not a date', null), null);
});

test('each search sends one aggregation request for this window and the week before; the search query itself is unchanged', async (t) => {
    const { stubs } = await ask(t, { logs: [rec('5710')] });
    assert.equal(stubs.searchCalls.length, 2, 'the two record searches are unchanged');
    for (const call of stubs.searchCalls) {
        assert.equal(call.body.size, 200);
        assert.equal(call.body.aggs, undefined, 'the record search carries no aggregations (fixture replay depends on it)');
    }
    assert.equal(stubs.aggCalls.length, 2, 'one aggregation request per search');
    const agg = stubs.aggCalls.find(c => !isFirewallScopeQuery(c.body)).body;
    assert.equal(agg.size, 0);
    assert.deepEqual(agg.aggs.current.filter, { range: { '@timestamp': { gte: 'now-24h' } } });
    assert.deepEqual(agg.aggs.previous.filter, { range: { '@timestamp': { gte: 'now-192h', lte: 'now-168h' } } });
    for (const name of ['by_rule', 'by_agent', 'by_srcip', 'by_level', 'by_mitre']) assert.ok(agg.aggs.current.aggs[name], name);
    const matching = stubs.searchCalls.find(c => !isFirewallScopeQuery(c.body)).body;
    assert.deepEqual(agg.query.bool.must, matching.query.bool.must, 'same matching conditions as the search');
});

test('the model gets exact counts over every match, not counts from the sample', async (t) => {
    const { stubs } = await ask(t, sampledLogs);
    const evidence = modelEvidence(stubs);
    assert.deepEqual(evidence.counts.byRule.map(r => [r.ruleId, r.count]), [['5710', 1200], ['550', 300]]);
    assert.deepEqual(evidence.counts.byAgent.map(a => [a.agent, a.count]), [['web-01', 1200], ['web-02', 300]]);
    assert.deepEqual(evidence.counts.bySeverity, [{ level: 5, count: 1200 }, { level: 7, count: 300 }]);
    assert.equal(evidence.countsExact, true);
    assert.ok(evidence.searches[0].sampleLogs.length <= 10, 'raw records are only a short illustration now');
});

const COMPARE = 'how do failed logons today compare with last week';

test('asked to compare: the week-earlier comparison reaches the model and the code-written header', async (t) => {
    const { stubs, response } = await ask(t, { ...sampledLogs, question: COMPARE });
    const { comparison } = modelEvidence(stubs);
    assert.equal(comparison.previousWindow, 'the same 24 hours one week earlier');
    assert.deepEqual(comparison.total, { current: 1500, previous: 10 });
    assert.deepEqual(comparison.byRule.find(r => r.ruleId === '5710'), { ruleId: '5710', current: 1200, previous: 10 });
    assert.deepEqual(comparison.byRule.find(r => r.ruleId === '550'), { ruleId: '550', current: 300, previous: 0 });
    assert.deepEqual(comparison.newThisWindow, ['550']);
    assert.match(response.summary, /\*\*Compared with\*\* the same 24 hours one week earlier: 1,500 matches, against 10\./);
});

test('exact counts close F-63: an inflated count is now dropped, the true one kept', async (t) => {
    const truth = { text: 'Rule 5710 fired 1200 times.', cite: [cite('rule', '5710', 1200)] };
    const inflated = { text: 'Rule 5710 fired 1250 times.', cite: [cite('rule', '5710', 1250)] };
    const lastWeek = { text: 'A week earlier rule 5710 fired 10 times.', cite: [cite('previous', '5710', 10)] };
    const wrongLastWeek = { text: 'A week earlier rule 5710 fired 3 times.', cite: [cite('previous', '5710', 3)] };
    const prevTotal = { text: 'A week earlier there were 10 matches.', cite: [cite('previous', 'searchSecurityLogs', 10)] };
    const { response, run } = await ask(t, { ...sampledLogs, question: COMPARE, report: { findings: [truth, inflated, lastWeek, wrongLastWeek, prevTotal] } });
    assert.ok(response.summary.includes(truth.text));
    assert.ok(response.summary.includes(lastWeek.text));
    assert.ok(response.summary.includes(prevTotal.text));
    assert.ok(!response.summary.includes(inflated.text));
    assert.ok(!response.summary.includes(wrongLastWeek.text));
    assert.deepEqual(run.grounding.dropped.map(d => d.text).sort(), [inflated.text, wrongLastWeek.text].sort());
});

test('if the aggregation request fails, the run carries on with sample counts and says the counts are from a sample', async (t) => {
    const { response, stubs, run } = await ask(t, { logs: [rec('5710'), rec('5710')], aggregations: 'fail' });
    const evidence = modelEvidence(stubs);
    assert.equal(evidence.countsExact, false);
    assert.equal(evidence.comparison, null);
    assert.equal(run.status, 'completed');
    assert.match(response.summary, /\*\*Counts\*\* come from the records retrieved/);
    assert.doesNotMatch(response.summary, /week-earlier/, 'no comparison was asked for, so its absence is not mentioned');
    const compared = await ask(t, { logs: [rec('5710')], aggregations: 'fail', question: COMPARE });
    assert.match(compared.response.summary, /not from every match, and there is no week-earlier comparison\./);
    const search = run.tools.find(x => x.tool === 'searchSecurityLogs' && x.parameters.sourceScope === 'non_firewall');
    assert.equal(search.aggregations.available, false);
    assert.match(search.aggregations.error, /500/);
});

test('severity floor: a "right now" question searches level 7 and above unless a level was asked for', () => {
    const plan = [search(), search({ minSeverity: 3 })];
    assert.deepEqual(applySeverityFloor(plan, 'what is going on right now', 7).map(i => i.parameters.minSeverity), [7, 3]);
    assert.deepEqual(applySeverityFloor(plan, 'what is happening at the moment', 7).map(i => i.parameters.minSeverity), [7, 3]);
    assert.deepEqual(applySeverityFloor(plan, 'show me failed logons today', 7).map(i => i.parameters.minSeverity), [null, 3]);
    assert.deepEqual(applySeverityFloor(plan, 'what is going on right now', 0).map(i => i.parameters.minSeverity), [null, 3], '0 turns the floor off');
    assert.equal(plan[0].parameters.minSeverity, null, 'the plan is not mutated');
});

test('severity floor in a run: the query filters on rule.level, the header says so, and the run record notes it', async (t) => {
    const { response, stubs, run } = await ask(t, { question: 'what is going on right now', logs: [rec('550', 'web-02', '198.51.100.4', 7)] });
    for (const call of stubs.searchCalls) {
        assert.ok(call.body.query.bool.filter.some(f => f.range?.['rule.level']?.gte === 7), 'level floor in the query');
    }
    assert.match(response.summary, /^\*\*Searched:\*\* Wazuh alerts at level 7 and above \(1 match\)/);
    assert.deepEqual(run.planner.severityFloor, { level: 7, applied: true });
});

test('per-stage timings in every run record, including the model prompt size', async (t) => {
    const { run } = await ask(t, { logs: [rec('5710')] });
    for (const key of ['memoryRetrievalDuration', 'planningDuration', 'executionDuration', 'aggregationDuration', 'reasoningDuration', 'verificationDuration', 'totalDuration']) {
        assert.equal(typeof run.timings[key], 'number', key);
    }
    assert.ok(run.timings.reportPromptChars > 0);
    assert.equal(run.timings.tools.length, 2);
    for (const tool of run.timings.tools) {
        assert.equal(tool.tool, 'searchSecurityLogs');
        assert.equal(typeof tool.durationMs, 'number');
        assert.ok(['non_firewall', 'firewall'].includes(tool.scope));
    }
});

test('a run that never reaches the report still records the stages it did reach', async (t) => {
    const { run } = await ask(t, { plan: { thought: 'nothing to do', tools: [] }, question: 'hmm' });
    assert.equal(typeof run.timings.planningDuration, 'number');
    assert.equal(run.timings.reasoningDuration, null, 'a stage not reached is null, not 0');
    assert.equal(typeof run.timings.totalDuration, 'number');
});
