import { test } from 'node:test';
import assert from 'node:assert/strict';
import { setTestEnv, stubBackends, flushBackgroundWork, USER_ID, SAMPLE_LOG, SEARCH_PLAN } from './helpers.js';

setTestEnv();
const { initDatabase } = await import('../src/config/db.js');
const { handleChat } = await import('../src/controllers/chat.controller.js');
const { RunModel } = await import('../src/models/Run.js');

initDatabase();

// The removed data-source selector (F-39) refused any request whose body did not select Wazuh.
const REMOVED_REFUSAL = /Please select Wazuh from the Agents dropdown/;

function fakeRes() {
    return {
        statusCode: 200,
        body: undefined,
        status(code) { this.statusCode = code; return this; },
        json(body) { this.body = body; return this; }
    };
}

async function send(t, body) {
    stubBackends(t, { llm: { plan: SEARCH_PLAN, report: '**Executive Summary**: test' }, logs: [SAMPLE_LOG] });
    t.mock.method(console, 'log', () => {});
    const res = fakeRes();
    await handleChat({ body, user: { id: USER_ID } }, res);
    await flushBackgroundWork();
    return res;
}

test('a request with no sources field runs normally', async (t) => {
    const res = await send(t, { text: 'Show brute force attacks', history: [] });

    assert.equal(res.statusCode, 200);
    assert.equal(res.body.type, 'agent_response', JSON.stringify(res.body));
    assert.doesNotMatch(res.body.summary ?? '', REMOVED_REFUSAL);
    assert.ok(res.body.request_id, 'the request must produce a run');

    const run = RunModel.findById(res.body.request_id);
    assert.equal(run.status, 'completed');
    // One planned search runs as its non-firewall and firewall halves.
    assert.deepEqual(run.tools.filter(tool => tool.tool === 'searchSecurityLogs').map(tool => tool.parameters.sourceScope).sort(),
        ['firewall', 'non_firewall'], 'the SIEM search must still run');
    assert.equal(res.body.total_hits, 1);
});

test('a request with no body fields beyond text runs normally', async (t) => {
    const res = await send(t, { text: 'Show brute force attacks' });

    assert.equal(res.body.type, 'agent_response', JSON.stringify(res.body));
    assert.ok(res.body.request_id);
});

test('a stray sources field from an older client is ignored, not refused', async (t) => {
    // Old clients could send any combination; 'hisec' alone used to be refused outright.
    const res = await send(t, { text: 'Show brute force attacks', sources: ['hisec'], history: [] });

    assert.equal(res.body.type, 'agent_response', JSON.stringify(res.body));
    assert.doesNotMatch(res.body.summary ?? '', REMOVED_REFUSAL);
    assert.equal(RunModel.findById(res.body.request_id).status, 'completed');
});
