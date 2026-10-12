import { test } from 'node:test';
import assert from 'node:assert/strict';
import { setTestEnv, stubBackends, flushBackgroundWork, USER_ID, isFirewallScopeQuery } from './helpers.js';

setTestEnv();
const { initDatabase } = await import('../src/config/db.js');
const { runAgentWorkflow } = await import('../src/agent/runtime.js');
const { wantsComparison } = await import('../src/agent/comparison.js');
initDatabase();

// The week-earlier comparison is shown only when the analyst asks for one.

test('questions that ask for a comparison, a trend or what is unusual', () => {
    for (const q of [
        'compare the last 24 hours with last week', 'how does today compare to yesterday', 'alerts this week vs last week',
        'failed logons today versus the previous day', 'are there more alerts than last week?', 'is this higher than usual',
        'any increase in brute force attempts?', 'did failed logons drop since yesterday', 'show me the trend in alerts',
        'what changed since last week', 'week over week alert volume', 'anything unusual on the AD servers',
        'is there a spike in firewall denies', 'any new rules firing compared to before', 'how is this different from normal'
    ]) assert.equal(wantsComparison(q), true, q);
});

test('plain requests for data do not ask for a comparison', () => {
    for (const q of [
        'What is the log on the wazuh for the past 24hrs', 'show me failed logons today', 'top alerts this week',
        'list disconnected agents', 'Show me the top 20 most recent logs on the wazuh', 'is 197.159.78.164 attacking us?',
        'what happened on web-01 last night', 'how many brute force attempts yesterday', 'give me the 5 newest entries',
        'alerts from the last 7 days', 'what is going on with the windows hosts', 'summarise last week\'s alerts'
    ]) assert.equal(wantsComparison(q), false, q);
});

const PLAN = { thought: 't', tools: [{ tool: 'searchSecurityLogs', parameters: { timeRange: 'now-24h', intent: 'alerts', extractedIPs: [], minSeverity: null, cleanedSearchText: '' } }] };
const rec = id => ({ '@timestamp': '2026-10-12T08:00:00Z', rule: { id, level: 5, description: `rule ${id}` }, agent: { name: 'web-01' } });
const NOW = [rec('5710'), rec('5710'), rec('60122')];
const WEEK_AGO = Array.from({ length: 8 }, () => rec('5710'));
const COMPARISON_TEXT = /one week earlier|week-earlier|Compared with|\*\*Change:\*\*|New this period/;

async function ask(t, question, llm) {
    for (const level of ['log', 'warn', 'error']) t.mock.method(console, level, () => {});
    const stubs = stubBackends(t, { llm, logs: (url, body) => (isFirewallScopeQuery(body) ? [] : NOW), previousLogs: WEEK_AGO });
    const response = await runAgentWorkflow(question, [], USER_ID);
    await flushBackgroundWork();
    const reportRequest = stubs.llmCalls.find(m => m[0].content.includes('Reasoning Engine'));
    return { response, reportRequest };
}

test('a plain question: no comparison in the answer, and none sent to the model', async (t) => {
    const { response, reportRequest } = await ask(t, 'What is the log on the wazuh for the past 24hrs', { plan: PLAN, report: '{"insufficient_evidence": true}' });
    assert.doesNotMatch(response.summary, COMPARISON_TEXT);
    assert.match(response.summary, /\*\*Summary of the results\*\*/, 'the summary is still there');
    assert.match(response.summary, /\*\*Most frequent rules:\*\* 5710 rule 5710 \(2\)/);
    const evidence = reportRequest.at(-1).content;
    assert.match(evidence, /"comparison":null/);
    assert.doesNotMatch(evidence, /previousTotals|newThisWindow/);
});

test('a plain question with the model down: the calculated summary has no comparison either', async (t) => {
    const { response } = await ask(t, 'show me the alerts from the last 24 hours', 'down');
    assert.doesNotMatch(response.summary, COMPARISON_TEXT);
    assert.match(response.summary, /\*\*Summary of the results\*\*/);
});

test('a question that asks for a comparison still gets it', async (t) => {
    const { response, reportRequest } = await ask(t, 'how do the last 24 hours compare with last week', { plan: PLAN, report: '{"insufficient_evidence": true}' });
    assert.match(response.summary, /\*\*Compared with\*\* the same 24 hours one week earlier: 3 matches, against 8\./);
    assert.match(response.summary, /\*\*Change:\*\* 63% fewer matches than the same 24 hours one week earlier\./);
    assert.match(response.summary, /\*\*New this period:\*\* rule 60122/);
    assert.match(reportRequest.at(-1).content, /"previousTotals"/);
});

test('the earlier window reads plainly when the search started at a fixed time and runs to now', async () => {
    const { describeWindow, describePreviousWindow } = await import('../src/agent/evidenceIndex.js');
    const previous = { gte: '2026-09-28T11:34:18.119Z', lte: 'now-168h' };
    assert.equal(describePreviousWindow('2026-10-05T11:34:18.119Z', null, previous), 'the same period one week earlier');
    assert.equal(describeWindow('2026-10-05T11:34:18.119Z', null), 'since 2026-10-05 11:34 UTC');
    assert.equal(describePreviousWindow('now-24h', null, { gte: 'now-192h', lte: 'now-168h' }), 'the same 24 hours one week earlier');
    assert.equal(describePreviousWindow('2026-10-05T00:00:00Z', '2026-10-06T00:00:00Z', { gte: '2026-09-28T00:00:00.000Z', lte: '2026-09-29T00:00:00.000Z' }), '2026-09-28T00:00:00.000Z to 2026-09-29T00:00:00.000Z (one week earlier)');
});
