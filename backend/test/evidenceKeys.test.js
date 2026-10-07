import { test } from 'node:test';
import assert from 'node:assert/strict';
import { setTestEnv, stubBackends, flushBackgroundWork, isFirewallScopeQuery, USER_ID } from './helpers.js';

setTestEnv();
const { initDatabase } = await import('../src/config/db.js');
const { runAgentWorkflow } = await import('../src/agent/runtime.js');
initDatabase();

const quiet = t => { for (const level of ['log', 'warn', 'error']) t.mock.method(console, level, () => {}); };
const search = (intent, extra = {}) => ({ tool: 'searchSecurityLogs', parameters: { timeRange: 'now-24h', intent, extractedIPs: [], minSeverity: null, cleanedSearchText: '', ...extra } });
const log = desc => ({ '@timestamp': '2026-10-07T08:00:00Z', rule: { level: 5, description: desc }, agent: { name: 'web-01' } });

// Different records per query, chosen from the query itself.
function logsFor(url, body) {
    const q = JSON.stringify(body);
    if (String(url).includes('vulnerabilities')) return [log('vuln-1'), log('vuln-2'), log('vuln-3')];
    if (q.includes('authentication_failed')) return [log('auth-1')];
    return [log('alert-1'), log('alert-2')];
}
const firewallFor = (url, body) => (JSON.stringify(body).includes('authentication_failed') ? [log('fw-auth-1')] : [log('fw-1'), log('fw-2'), log('fw-3'), log('fw-4')]);

function reasoningEvidence(llmCalls) {
    const prompt = llmCalls.find(m => m[0].content.includes('Reasoning Engine')).at(-1).content;
    return JSON.parse(prompt.slice(prompt.indexOf('{'))).evidence;
}

test('F-29: two planned searches each keep their own evidence for the model', async (t) => {
    quiet(t);
    const plan = { thought: 't', tools: [search('brute_force'), search('alerts')] };
    const { llmCalls } = stubBackends(t, { llm: { plan, report: 'r' }, logs: logsFor, firewallLogs: firewallFor });
    await runAgentWorkflow('failed logons and other alerts', [], USER_ID);
    await flushBackgroundWork();

    const evidence = reasoningEvidence(llmCalls);
    assert.deepEqual(
        Object.fromEntries(Object.entries(evidence).map(([k, v]) => [k, v.totalMatches])),
        { searchSecurityLogs: 1, firewallLogs: 1, 'searchSecurityLogs#2': 2, 'firewallLogs#2': 4 },
        'no search overwrites another'
    );
    assert.deepEqual(evidence['searchSecurityLogs#2'].sampleLogs.map(l => l.desc), ['alert-1', 'alert-2']);
});

test('item 5: a vulnerability search is not split into firewall and non-firewall halves', async (t) => {
    quiet(t);
    const plan = { thought: 't', tools: [search('vulnerabilities')] };
    const { searchCalls, llmCalls } = stubBackends(t, { llm: { plan, report: 'r' }, logs: logsFor, firewallLogs: firewallFor });
    const response = await runAgentWorkflow('show recent CVEs', [], USER_ID);
    await flushBackgroundWork();

    assert.equal(searchCalls.length, 1, 'one query, no firewall split');
    assert.ok(String(searchCalls[0].url).includes('wazuh-states-vulnerabilities'));
    assert.equal(isFirewallScopeQuery(searchCalls[0].body), false);
    assert.ok(!JSON.stringify(searchCalls[0].body.query.bool.must_not ?? []).includes('iptables'), 'no firewall exclusion either');
    assert.deepEqual(Object.keys(reasoningEvidence(llmCalls)), ['searchSecurityLogs']);
    assert.deepEqual(Object.keys(response.raw_logs), ['searchSecurityLogs']);
    assert.equal(response.total_hits, 3);
});

test('getEndpointStatus never replaces the logs of other tools, whatever order they finish in', async (t) => {
    quiet(t);
    const plan = { thought: 't', tools: [search('alerts'), { tool: 'getEndpointStatus', parameters: { target: 'agents', status: 'any' } }] };
    const agents = [{ id: '001', name: 'web-01', status: 'active' }];
    stubBackends(t, { llm: { plan, report: 'r' }, logs: logsFor, agents });
    const response = await runAgentWorkflow('alerts and agent status', [], USER_ID);
    await flushBackgroundWork();
    assert.deepEqual(response.raw_logs.searchSecurityLogs.map(l => l.rule.description), ['alert-1', 'alert-2']);
    assert.deepEqual(response.raw_logs.getEndpointStatus, agents);
});
