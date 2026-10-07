import { test } from 'node:test';
import assert from 'node:assert/strict';
import { setTestEnv, stubBackends, flushBackgroundWork, USER_ID } from './helpers.js';

setTestEnv();
const { initDatabase } = await import('../src/config/db.js');
const { runAgentWorkflow } = await import('../src/agent/runtime.js');

initDatabase();

const AUTH_LOGS = [
    { '@timestamp': '2026-09-16T08:00:00Z', rule: { level: 5, description: 'sshd: authentication failed', groups: ['authentication_failed'] }, agent: { name: 'web-01' } },
    { '@timestamp': '2026-09-16T08:01:00Z', rule: { level: 10, description: 'sshd: brute force trying to get access', groups: ['authentication_failures'] }, agent: { name: 'web-01' } }
];
const VULN_LOGS = [
    { '@timestamp': '2026-09-16T07:00:00Z', vulnerability: { id: 'CVE-2026-0001', severity: 'High', description: 'openssl flaw' }, agent: { name: 'db-01' } }
];
const AGENTS = [
    { id: '001', name: 'web-01', status: 'active', ip: '10.0.0.11' },
    { id: '002', name: 'db-01', status: 'disconnected', ip: '10.0.0.12' }
];

const PLAN = {
    thought: 'Check authentication failures, vulnerabilities and agent status.',
    tools: [
        { tool: 'searchSecurityLogs', parameters: { timeRange: 'now-24h', intent: 'brute_force', extractedIPs: [], minSeverity: null, cleanedSearchText: '' } },
        { tool: 'getEndpointStatus', parameters: { target: 'agents', status: 'any' } },
        { tool: 'searchSecurityLogs', parameters: { timeRange: 'now-7d', intent: 'vulnerabilities', extractedIPs: [], minSeverity: null, cleanedSearchText: '' } }
    ]
};

// Each search returns different logs, chosen by the index it targets.
const logsFor = url => (String(url).includes('wazuh-states-vulnerabilities') ? VULN_LOGS : AUTH_LOGS);

test('multi-tool run: every tool\'s raw logs are retained, keyed per tool in plan order', async (t) => {
    const { searchCalls, wazuhCalls } = stubBackends(t, { llm: { plan: PLAN, report: '**Executive Summary**: test' }, logs: logsFor, agents: AGENTS });

    const response = await runAgentWorkflow('Auth failures, CVEs and agent status', [], USER_ID);
    await flushBackgroundWork();

    // Two planned searches: the alerts search runs as non-firewall and firewall halves; the
    // vulnerability search is not split (Phase 2.5), so 3 OpenSearch calls in total.
    assert.equal(searchCalls.length, 3);
    assert.equal(wazuhCalls.length, 1);

    assert.deepEqual(Object.keys(response.raw_logs), ['searchSecurityLogs', 'getEndpointStatus', 'searchSecurityLogs#2']);
    assert.deepEqual(response.raw_logs.searchSecurityLogs, AUTH_LOGS);
    assert.deepEqual(response.raw_logs.getEndpointStatus, AGENTS);
    assert.deepEqual(response.raw_logs['searchSecurityLogs#2'], VULN_LOGS);

    // Nothing duplicated or dropped: the same logs, once each (payload size unchanged).
    assert.equal(Object.values(response.raw_logs).flat().length, AUTH_LOGS.length + AGENTS.length + VULN_LOGS.length);
    assert.equal(response.total_hits, AUTH_LOGS.length + AGENTS.length + VULN_LOGS.length);
});

test('keys follow plan order even when tools finish in a different order', async (t) => {
    stubBackends(t, { llm: { plan: PLAN, report: '**Executive Summary**: test' }, logs: logsFor, agents: AGENTS });
    // Make the first planned tool finish last.
    const post = (await import('axios')).default.post;
    t.mock.method((await import('axios')).default, 'post', async (url, body, config) => {
        if (String(url).includes('wazuh-alerts-*/_search') && !String(url).includes('vulnerabilities')) {
            await new Promise(resolve => setTimeout(resolve, 30));
        }
        return post(url, body, config);
    });

    const response = await runAgentWorkflow('Auth failures, CVEs and agent status', [], USER_ID);
    await flushBackgroundWork();

    assert.deepEqual(Object.keys(response.raw_logs), ['searchSecurityLogs', 'getEndpointStatus', 'searchSecurityLogs#2']);
    assert.deepEqual(response.raw_logs.searchSecurityLogs, AUTH_LOGS);
    assert.deepEqual(response.raw_logs['searchSecurityLogs#2'], VULN_LOGS);
});
