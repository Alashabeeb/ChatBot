import { test } from 'node:test';
import assert from 'node:assert/strict';
import { setTestEnv, stubBackends, flushBackgroundWork, isFirewallScopeQuery, USER_ID, SAMPLE_LOG, SEARCH_PLAN } from './helpers.js';

setTestEnv();
const { initDatabase } = await import('../src/config/db.js');
const { runAgentWorkflow } = await import('../src/agent/runtime.js');
const { RunModel } = await import('../src/models/Run.js');

initDatabase();

const FIREWALL_LOG = { '@timestamp': '2026-09-16T09:00:00Z', rule: { level: 6, description: 'iptables: dropped inbound connection', groups: ['firewall'] }, data: { srcip: '198.51.100.7' }, agent: { name: 'fw-01' } };

test('each search runs a firewall and a non-firewall query; both results are kept, labelled and summed once', async (t) => {
    const { searchCalls, llmCalls } = stubBackends(t, { llm: { plan: SEARCH_PLAN, report: 'r' }, logs: [SAMPLE_LOG], firewallLogs: [FIREWALL_LOG, FIREWALL_LOG] });
    t.mock.method(console, 'log', () => {});
    const response = await runAgentWorkflow('Show brute force attacks', [], USER_ID);
    await flushBackgroundWork();

    assert.equal(searchCalls.length, 2);
    assert.equal(searchCalls.filter(c => isFirewallScopeQuery(c.body)).length, 1, 'exactly one firewall-scoped query');
    assert.equal(searchCalls.filter(c => JSON.stringify(c.body.query.bool.must_not ?? []).includes('"iptables"')).length, 1, 'exactly one query excluding firewall records');

    assert.deepEqual(Object.keys(response.raw_logs), ['searchSecurityLogs', 'searchSecurityLogs:firewall']);
    assert.deepEqual(response.raw_logs['searchSecurityLogs:firewall'], [FIREWALL_LOG, FIREWALL_LOG]);
    assert.equal(response.total_hits, 3);
    assert.equal(response.source, 'Wazuh + Firewall (Wazuh)');

    const prompt = llmCalls.find(m => m[0].content.includes('Reasoning Engine')).at(-1).content;
    const evidence = JSON.parse(prompt.slice(prompt.indexOf('{')));
    const byKey = Object.fromEntries(evidence.searches.map(s => [s.key, s]));
    assert.deepEqual(Object.keys(byKey), ['searchSecurityLogs', 'firewallLogs']);
    assert.equal(byKey.firewallLogs.totalMatches, 2);
    assert.equal(byKey.firewallLogs.sampleLogs.length, 2);
    assert.equal(byKey.firewallLogs.source, 'firewall events from Wazuh');
    assert.equal(byKey.searchSecurityLogs.totalMatches, 1);
    // The report opens with both sources and their separate totals.
    assert.match(response.summary, /^\*\*Searched:\*\* Wazuh alerts \(1 match\) and firewall events from Wazuh \(2 matches\)/);

    // The run record keeps what the model planned (one search), separately from the two executed calls.
    const run = RunModel.findById(response.request_id);
    assert.equal(run.planner.tools.length, 1);
    assert.equal(run.tools.length, 2);
});
