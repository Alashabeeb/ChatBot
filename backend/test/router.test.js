import { test, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import axios from 'axios';
import { setTestEnv, stubBackends, flushBackgroundWork, USER_ID, llmReply } from './helpers.js';

setTestEnv();
const { initDatabase } = await import('../src/config/db.js');
const { routeMessage, routeByRules } = await import('../src/services/router.service.js');
const { processChatQuery } = await import('../src/services/chat.service.js');
const { clearEvidenceCache } = await import('../src/agent/evidenceCache.js');
initDatabase();
beforeEach(() => { clearEvidenceCache(); delete process.env.ROUTER_TIMEOUT_MS; });

test('rules: clear data questions go to search', () => {
    for (const q of [
        'show me failed logons today', 'what are the top alerts this week', 'what is going on right now',
        'anything unusual on the AD servers', 'Show me the top 20 most recent logs on the wazuh', 'is 197.159.78.164 attacking us?',
        'list disconnected agents', 'how many brute force attempts yesterday', 'any vulnerabilities on DC01?', 'latest logs',
        'what happened on web-01 last night', 'status of our agents', 'check the alerts',
        'give me the 5 newest entries'   // only the recent-records rule recognises this one
    ]) assert.equal(routeByRules(q)?.route, 'search', q);
});

test('rules: greetings, writing and general knowledge go to chat', () => {
    for (const q of [
        'hi', 'thanks', 'good morning', 'how are you', 'write an email to the team about the outage',
        'explain what lateral movement is', 'what is MITRE ATT&CK', 'translate this to French: hello', 'give me a checklist for onboarding',
        'what is a brute force attack', 'how does Kerberoasting work', 'who won the world cup in 2018', 'draft a status update'
    ]) assert.equal(routeByRules(q)?.route, 'chat', q);
});

test('rules: unclear messages are left to the model', () => {
    for (const q of ['brute force', 'is failed password for root bad', 'the firewall seems slow', 'malware on the network']) {
        assert.equal(routeByRules(q), null, q);
    }
});

function stubModel(t, reply) {
    const calls = [];
    t.mock.method(axios, 'post', async (url, body) => {
        calls.push(body);
        if (reply instanceof Error) throw reply;
        return llmReply(reply);
    });
    t.mock.method(console, 'warn', () => {});
    return calls;
}

test('unclear messages: the model decides with one word, using a small, short request', async (t) => {
    const calls = stubModel(t, 'SEARCH');
    const decision = await routeMessage('the firewall seems slow', [], { userId: USER_ID });
    assert.deepEqual({ route: decision.route, by: decision.by }, { route: 'search', by: 'model' });
    assert.equal(calls.length, 1);
    assert.match(calls[0].messages[0].content, /SEARCH or CHAT/);
    assert.ok(calls[0].max_tokens <= 5);
    assert.equal(calls[0].messages.at(-1).content, 'the firewall seems slow');

    axios.post.mock.restore();
    stubModel(t, 'chat.');
    assert.equal((await routeMessage('the firewall seems slow', [], { userId: USER_ID })).route, 'chat');
});

test('clear messages never call the model', async (t) => {
    const calls = stubModel(t, 'CHAT');
    assert.equal((await routeMessage('show me failed logons today', [], { userId: USER_ID })).by, 'rule');
    assert.equal((await routeMessage('hi', [], { userId: USER_ID })).by, 'rule');
    assert.equal(calls.length, 0);
});

test('model down or unclear reply: a safe default (search when it mentions security terms, else chat)', async (t) => {
    stubModel(t, new Error('connect ECONNREFUSED'));
    const down = await routeMessage('the firewall seems slow', [], { userId: USER_ID });
    assert.deepEqual({ route: down.route, by: down.by }, { route: 'search', by: 'fallback' });
    axios.post.mock.restore();
    stubModel(t, 'maybe?');
    const vague = await routeMessage('the firewall seems slow', [], { userId: USER_ID });
    assert.deepEqual({ route: vague.route, by: vague.by }, { route: 'search', by: 'fallback' });
});

test('the analyst can override the choice (the "Search Wazuh for this" button)', async (t) => {
    const calls = stubModel(t, 'CHAT');
    const forced = await routeMessage('explain what lateral movement is', [], { userId: USER_ID, forceRoute: 'search' });
    assert.deepEqual({ route: forced.route, by: forced.by }, { route: 'search', by: 'user' });
    assert.equal(calls.length, 0);
});

test('replies to a clarifying question, and follow-ups to a search, always go to search', async (t) => {
    stubModel(t, 'CHAT');
    const history = [{ role: 'user', content: 'is that IP malicious?' }, { role: 'assistant', content: 'Quick question before I search: Which IP address do you mean?' }];
    assert.equal((await routeMessage('yes', history, { userId: USER_ID })).route, 'search');

    axios.post.mock.restore();
    for (const level of ['log', 'warn', 'error']) t.mock.method(console, level, () => {});
    stubBackends(t, { llm: { plan: { thought: 't', tools: [{ tool: 'searchSecurityLogs', parameters: { timeRange: 'now-24h', intent: 'alerts', extractedIPs: [], minSeverity: null, cleanedSearchText: '' } }] }, report: '{"answer":[]}' }, logs: [{ '@timestamp': '2026-10-12T08:00:00Z', rule: { id: '5710', level: 5, description: 'sshd' }, agent: { name: 'web-01' } }] });
    const first = await processChatQuery('show me failed logons today', [], USER_ID);
    await flushBackgroundWork();
    const followUp = await routeMessage('explain that', [], { userId: USER_ID, followUpOf: first.request_id });
    assert.deepEqual({ route: followUp.route, by: followUp.by }, { route: 'search', by: 'rule' });
});
