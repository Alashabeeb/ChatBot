import { test } from 'node:test';
import assert from 'node:assert/strict';
import { setTestEnv, stubBackends, flushBackgroundWork, USER_ID, SAMPLE_LOG, SEARCH_PLAN } from './helpers.js';

setTestEnv();
const { initDatabase } = await import('../src/config/db.js');
const { isConversational, processChatQuery } = await import('../src/services/chat.service.js');
const { handleChat } = await import('../src/controllers/chat.controller.js');
const { DEFAULT_QUESTIONS } = await import('../src/recording/common.js');

initDatabase();

// Security questions that carry no whole-word keyword ("alerts", "failed", "logons", "vulnerabilities").
// Routing on the keyword alone sent these to the chat-only path, which answers without searching.
const SECURITY_WITHOUT_KEYWORD = [
    ...DEFAULT_QUESTIONS,
    'how many vulnerabilities on web-01',
    'any suspicious activity overnight?'
];

test('security questions without a keyword are not treated as conversation', () => {
    for (const q of SECURITY_WITHOUT_KEYWORD) {
        assert.equal(isConversational(q.toLowerCase()), false, `"${q}" must go to the data-searching runtime`);
    }
});

test('clearly conversational messages are', () => {
    for (const q of ['hello', 'thanks', 'what can you do', 'how are you']) {
        assert.equal(isConversational(q), true, q);
    }
    assert.equal(isConversational('explain what mitre att&ck is'), false, 'a security keyword always wins');
});

test('each capture question runs a search', async (t) => {
    for (const question of DEFAULT_QUESTIONS) {
        const { searchCalls } = stubBackends(t, { llm: { plan: SEARCH_PLAN, report: 'r' }, logs: [SAMPLE_LOG] });
        t.mock.method(console, 'log', () => {});
        const response = await processChatQuery(question, [], USER_ID);
        await flushBackgroundWork();
        assert.equal(response.type, 'agent_response', `"${question}" got a ${response.type} reply`);
        assert.ok(searchCalls.length > 0, `"${question}" did not search`);
        t.mock.restoreAll();
    }
});

test('a greeting goes to the conversational model, with no run and no search', async (t) => {
    const { llmCalls, searchCalls } = stubBackends(t, { llm: { report: 'Hi! I can help investigate Wazuh data.' } });
    const response = await processChatQuery('hello', [], USER_ID);
    assert.equal(response.type, 'text');
    assert.equal(response.text, 'Hi! I can help investigate Wazuh data.');
    assert.equal(response.request_id, undefined);
    assert.equal(searchCalls.length, 0);
    assert.match(llmCalls[0][0].content, /conversational interface/);
});

test('model down on the conversational path: HTTP 503 with the kept error shape', async (t) => {
    stubBackends(t, { llm: 'down' });
    t.mock.method(console, 'warn', () => {});
    t.mock.method(console, 'error', () => {});
    const res = { statusCode: 200, body: undefined, status(c) { this.statusCode = c; return this; }, json(b) { this.body = b; return this; } };
    await handleChat({ body: { text: 'hello', history: [] }, user: { id: USER_ID } }, res);
    assert.equal(res.statusCode, 503);
    assert.deepEqual(res.body, { type: 'error', request_id: null, error: 'The AI service did not return a response.' });
});
