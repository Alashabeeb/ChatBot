import { test } from 'node:test';
import assert from 'node:assert/strict';
import axios from 'axios';

// Must be set before any app module loads: config/env.js and config/db.js read them at import time.
process.env.SOC_DB_PATH = ':memory:';
process.env.LLM_API_URL = 'http://llm.test/v1/chat/completions';
process.env.OPENSEARCH_URL = 'http://opensearch.test';
process.env.WAZUH_SERVER_API_URL = 'http://wazuh.test';
process.env.WAZUH_USER = 'test';
process.env.WAZUH_PASSWORD = 'test';

const { initDatabase } = await import('../src/config/db.js');
const { runAgentWorkflow, THREAT_INTEL_ABSENT_NOTE } = await import('../src/agent/runtime.js');
const { lookupThreatIntelTool } = await import('../src/tools/lookupThreatIntel.js');

initDatabase();

// Seeded by initDatabase; memory rows need a real user (foreign key).
const USER_ID = 'user_admin_root';
const IP = '41.203.12.56';

// Signatures of fabricated threat intel. If any of these shows up in a model prompt or a
// report, placeholder data has leaked into the pipeline.
const FABRICATION_MARKERS = [
    /mock/i,
    /fake/i,
    /dummy/i,
    /placeholder/i,
    /integration pending/i,
    /threat\s*score/i,
    /\bmalicious\b/i,
    /\bscanner\b/i
];

function assertNoFabrication(label, text) {
    for (const marker of FABRICATION_MARKERS) {
        assert.doesNotMatch(text, marker, `${label} contains fabricated threat intel (matched ${marker})`);
    }
}

function llmReply(content) {
    return { data: { choices: [{ message: { content } }] } };
}

/**
 * Stubs the LLM and OpenSearch HTTP calls. The reasoning "model" echoes its whole prompt
 * back as the report, so anything the model was shown also ends up in the output.
 */
function stubBackends(t, { plan, logs = [] }) {
    const llmCalls = [];
    t.mock.method(axios, 'post', async (url, body) => {
        if (body?.messages) {
            llmCalls.push(body.messages);
            const system = body.messages[0].content;
            const user = body.messages.at(-1).content;
            if (system.includes('Planning Engine')) {
                return llmReply(plan ? JSON.stringify(plan) : 'not a plan');
            }
            if (system.includes('Memory Engine')) {
                return llmReply('{"summary":"test investigation","keyEntities":[]}');
            }
            return llmReply(`Echoed prompt:\n${user}`);
        }
        return { data: { hits: { total: { value: logs.length }, hits: logs.map(l => ({ _source: l })) } } };
    });
    return llmCalls;
}

// The runtime writes memory in the background after returning; let it finish while stubs are active.
const flushBackgroundWork = () => new Promise(resolve => setTimeout(resolve, 50));

function assertRunIsClean(llmCalls, response) {
    for (const messages of llmCalls) {
        for (const msg of messages) {
            assertNoFabrication(`LLM ${msg.role} message`, msg.content);
        }
    }
    assertNoFabrication('report summary', response.summary);
    assertNoFabrication('response payload', JSON.stringify(response));
    assert.ok(response.summary.includes(THREAT_INTEL_ABSENT_NOTE), 'report must state that threat intel is absent');
}

test('lookupThreatIntel reports itself unavailable instead of returning a verdict', async () => {
    const result = await lookupThreatIntelTool.execute({ indicator: IP, type: 'ip' });

    assertNoFabrication('tool result', JSON.stringify(result));
    assert.equal(result.available, false);
    assert.equal(result.indicator, IP);
    for (const field of ['malicious', 'threatScore', 'tags', 'verdict', 'reputation']) {
        assert.ok(!(field in result), `unavailable result must not carry a '${field}' field`);
    }
});

test('LLM-planned run: unavailable threat intel never reaches the model as evidence', async (t) => {
    const llmCalls = stubBackends(t, {
        plan: {
            thought: 'Search logs for the IP and look it up.',
            tools: [
                { tool: 'searchSecurityLogs', parameters: { timeRange: 'now-24h', intent: 'alerts', extractedIPs: [IP], minSeverity: null, cleanedSearchText: '' } },
                { tool: 'lookupThreatIntel', parameters: { indicator: IP, type: 'ip' } }
            ]
        },
        logs: [{
            '@timestamp': '2026-09-16T08:00:00Z',
            rule: { level: 5, description: 'sshd: authentication failed' },
            data: { srcip: IP, srcuser: 'root' },
            agent: { name: 'web-01' }
        }]
    });

    const response = await runAgentWorkflow(`Check IP ${IP}`, [], USER_ID);
    await flushBackgroundWork();

    // Content check first: this is the guarantee that matters, whatever shape a future mock takes.
    assertRunIsClean(llmCalls, response);

    const reasoningCall = llmCalls.find(messages => messages[0].content.includes('Reasoning Engine'));
    assert.ok(reasoningCall, 'expected a reasoning call for a run with hits');
    const prompt = reasoningCall.at(-1).content;
    const evidence = JSON.parse(prompt.slice(prompt.indexOf('{')));

    assert.equal(evidence.evidence.lookupThreatIntel, undefined, 'unavailable threat intel must not be passed as evidence');
    assert.deepEqual(evidence.unavailableSources.map(s => s.tool), ['lookupThreatIntel']);
    assert.equal(evidence.summary.unavailable, 1);
});

test('fallback-planned run with zero hits: report states threat intel is absent', async (t) => {
    // The planner reply is not valid JSON, so the legacy planner runs and adds lookupThreatIntel for the IP.
    const llmCalls = stubBackends(t, { plan: null, logs: [] });

    const response = await runAgentWorkflow(`Check IP ${IP}`, [], USER_ID);
    await flushBackgroundWork();

    assertRunIsClean(llmCalls, response);
    assert.ok(!llmCalls.some(messages => messages[0].content.includes('Reasoning Engine')), 'zero-hit run should not call the reasoning model');
    assert.doesNotMatch(response.summary, /searched[^.]*intelligence/i, 'report must not claim intelligence sources were searched');
});
