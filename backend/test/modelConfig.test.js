import { test, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import axios from 'axios';
import { setTestEnv, flushBackgroundWork, USER_ID, llmReply } from './helpers.js';

setTestEnv();
const { initDatabase } = await import('../src/config/db.js');
const { runAgentWorkflow } = await import('../src/agent/runtime.js');
const { modelFor, DEFAULT_MODEL_NAME } = await import('../src/llm/models.js');
const { RunModel } = await import('../src/models/Run.js');
const { default: db } = await import('../src/config/db.js');

initDatabase();

const ROLE_VARS = ['PLANNER_LLM_API_URL', 'PLANNER_LLM_MODEL', 'PLANNER_LLM_API_KEY', 'REPORT_LLM_API_URL', 'REPORT_LLM_MODEL', 'REPORT_LLM_API_KEY', 'LLM_MODEL', 'LLM_API_KEY'];
afterEach(() => { for (const name of ROLE_VARS) delete process.env[name]; });

const PLAN = { thought: 't', tools: [{ tool: 'searchSecurityLogs', parameters: { timeRange: 'now-24h', intent: 'alerts', extractedIPs: [], minSeverity: null, cleanedSearchText: '' } }] };
const LOG = { '@timestamp': '2026-10-12T08:00:00Z', rule: { id: '5710', level: 5, description: 'sshd' }, agent: { name: 'web-01' }, data: { srcip: '203.0.113.9' } };
const REPORT = JSON.stringify({ answer: [{ text: 'One alert on web-01.', cite: [{ kind: 'agent', ref: 'web-01' }] }] });

/** Records every model call: which URL, which model name, which Authorization header. */
function stubAll(t) {
    const calls = [];
    t.mock.method(axios, 'get', async () => ({ status: 200, data: { data: { affected_items: [], total_affected_items: 0 } } }));
    t.mock.method(axios, 'post', async (url, body, config = {}) => {
        if (body?.messages) {
            const system = body.messages[0].content;
            const role = system.includes('Planning Engine') ? 'planner' : system.includes('Reasoning Engine') ? 'report' : system.includes('Memory Engine') ? 'memory' : 'other';
            calls.push({ role, url, model: body.model, authorization: config.headers?.Authorization ?? null });
            return llmReply(role === 'planner' ? JSON.stringify(PLAN) : role === 'memory' ? '{"summary":"s","keyEntities":[]}' : REPORT);
        }
        if (body?.size === 0) return { status: 200, data: { hits: { total: { value: 0 }, hits: [] }, aggregations: {} } };
        return { status: 200, data: { hits: { total: { value: 1 }, hits: [{ _source: LOG }] } } };
    });
    t.mock.method(console, 'log', () => {});
    t.mock.method(console, 'warn', () => {});
    return calls;
}

async function run(t) {
    const calls = stubAll(t);
    const response = await runAgentWorkflow('show me alerts today', [], USER_ID);
    await flushBackgroundWork();
    return { calls, response, run: RunModel.findById(response.request_id) };
}
const byRole = (calls, role) => calls.filter(c => c.role === role);

test('no role settings: planner, report and memory all use LLM_API_URL and the current model, as before', async (t) => {
    assert.equal(DEFAULT_MODEL_NAME, 'foundation-sec-8b-instruct');
    const { calls, response } = await run(t);
    for (const role of ['planner', 'report', 'memory']) {
        assert.ok(byRole(calls, role).length > 0, role);
        for (const c of byRole(calls, role)) {
            assert.equal(c.url, process.env.LLM_API_URL);
            assert.equal(c.model, 'foundation-sec-8b-instruct');
            assert.equal(c.authorization, null, 'no key configured, no Authorization header');
        }
    }
    assert.deepEqual(response.generation.models, { planner: 'foundation-sec-8b-instruct', report: 'foundation-sec-8b-instruct' });
    assert.match(response.footer, /^Analyzed by foundation-sec-8b-instruct \|/);
});

test('REPORT_LLM_* sends only the report to another model; planner and memory stay on the default', async (t) => {
    process.env.REPORT_LLM_API_URL = 'http://report-model.test/v1/chat/completions';
    process.env.REPORT_LLM_MODEL = 'candidate-report-model';
    process.env.REPORT_LLM_API_KEY = 'report-key-123';
    const { calls, response, run: record } = await run(t);
    const [report] = byRole(calls, 'report');
    assert.equal(report.url, 'http://report-model.test/v1/chat/completions');
    assert.equal(report.model, 'candidate-report-model');
    assert.equal(report.authorization, 'Bearer report-key-123');
    for (const role of ['planner', 'memory']) for (const c of byRole(calls, role)) {
        assert.equal(c.url, process.env.LLM_API_URL);
        assert.equal(c.model, 'foundation-sec-8b-instruct');
        assert.equal(c.authorization, null);
    }
    assert.deepEqual(response.generation.models, { planner: 'foundation-sec-8b-instruct', report: 'candidate-report-model' });
    assert.match(response.footer, /^Analyzed by candidate-report-model \| Planned by foundation-sec-8b-instruct \|/);
    assert.deepEqual(record.generation.models, response.generation.models);
});

test('PLANNER_LLM_* sends only the planner to another model', async (t) => {
    process.env.PLANNER_LLM_API_URL = 'http://planner-model.test/v1/chat/completions';
    process.env.PLANNER_LLM_MODEL = 'candidate-planner';
    const { calls } = await run(t);
    assert.deepEqual(byRole(calls, 'planner').map(c => [c.url, c.model]), [['http://planner-model.test/v1/chat/completions', 'candidate-planner']]);
    assert.deepEqual(byRole(calls, 'report').map(c => [c.url, c.model]), [[process.env.LLM_API_URL, 'foundation-sec-8b-instruct']]);
});

test("the default endpoint's key is never sent to a separately configured endpoint", async (t) => {
    process.env.LLM_API_KEY = 'default-key-abc';
    process.env.REPORT_LLM_API_URL = 'http://report-model.test/v1/chat/completions';
    const { calls } = await run(t);
    assert.equal(byRole(calls, 'report')[0].authorization, null, 'report endpoint has no key of its own');
    assert.equal(byRole(calls, 'planner')[0].authorization, 'Bearer default-key-abc', 'the default endpoint keeps its key');
});

test('model settings: names fall back per field; keys never appear in the run record', async (t) => {
    process.env.LLM_MODEL = 'renamed-default';
    assert.equal(modelFor('planner').model, 'renamed-default');
    assert.equal(modelFor('report').url, process.env.LLM_API_URL);
    process.env.REPORT_LLM_API_URL = 'http://report-model.test/v1/chat/completions';
    process.env.REPORT_LLM_API_KEY = 'secret-report-key-xyz';
    const { response } = await run(t);
    const row = db.prepare('SELECT * FROM runs WHERE request_id = ?').get(response.request_id);
    assert.doesNotMatch(JSON.stringify(row), /secret-report-key-xyz/);
    assert.doesNotMatch(JSON.stringify(response), /secret-report-key-xyz/);
});
