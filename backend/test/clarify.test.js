import { test, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { setTestEnv, stubBackends, flushBackgroundWork, USER_ID, askFoundationArgs } from './helpers.js';

setTestEnv();
const { initDatabase } = await import('../src/config/db.js');
const { processChatQuery } = await import('../src/services/chat.service.js');
const { clarificationFor, CLARIFICATION_LEAD } = await import('../src/agent/clarify.js');
const { clearEvidenceCache } = await import('../src/agent/evidenceCache.js');
const { RunModel } = await import('../src/models/Run.js');

initDatabase();
beforeEach(() => clearEvidenceCache());

const PLAN = { thought: 't', tools: [{ tool: 'searchSecurityLogs', parameters: { timeRange: 'now-24h', intent: 'alerts', extractedIPs: [], minSeverity: null, cleanedSearchText: '' } }] };
const LOG = { '@timestamp': '2026-10-12T08:00:00Z', rule: { id: '5710', level: 5, description: 'sshd' }, agent: { name: 'web-01' }, data: { srcip: '203.0.113.9' } };
const REPORT = JSON.stringify({ answer: [{ text: 'Activity on web-01.', cite: [{ kind: 'agent', ref: 'web-01' }] }] });
const quiet = t => { for (const level of ['log', 'warn', 'error']) t.mock.method(console, level, () => {}); };

async function ask(t, text, { history = [], plan = PLAN, options = {} } = {}) {
    quiet(t);
    const stubs = stubBackends(t, { llm: { plan, report: REPORT }, logs: [LOG] });
    const response = await processChatQuery(text, history, USER_ID, options);
    await flushBackgroundWork();
    const planner = stubs.llmCalls.filter(m => m[0].content.includes('Planning Engine'));
    return { response, stubs, planned: planner.length > 0, plannerPrompt: planner[0] ? askFoundationArgs(planner[0]).prompt.content : '', searched: stubs.searchCalls.length > 0 };
}

test('rules: only genuinely ambiguous requests get a question', () => {
    assert.match(clarificationFor('is that IP malicious?'), /Which IP/);
    assert.match(clarificationFor('did the user log in?'), /Which user/);
    assert.match(clarificationFor('check the server'), /Which server/);
    assert.match(clarificationFor('check'), /What should I look at/);
    assert.match(clarificationFor('investigate this'), /What should I look at/);
    for (const clear of [
        'is 203.0.113.9 malicious?', 'show me failed logons today', 'anything unusual on the AD servers', 'what are the top alerts this week',
        'what is going on right now', 'check web-01', 'did the user root log in on DC01?', 'alerts', 'list disconnected agents', 'rule 5710 details',
        'check the servers for errors'
    ]) {
        assert.equal(clarificationFor(clear), null, clear);
    }
});

test('an ambiguous request gets one short question, and nothing is planned or searched', async (t) => {
    const { response, planned, searched } = await ask(t, 'is that IP malicious?');
    assert.equal(response.type, 'text');
    assert.equal(response.clarification, true);
    assert.ok(response.text.startsWith(CLARIFICATION_LEAD));
    assert.equal((response.text.match(/\?/g) || []).length, 1, 'exactly one question');
    assert.equal(planned, false);
    assert.equal(searched, false);
    const run = RunModel.findById(response.request_id);
    assert.equal(run.planner.source, 'clarification_rule');
    assert.equal(run.generation.report, 'clarification');
    assert.equal(run.reportText, response.text);
});

test('the reply to a clarification proceeds with both parts, and is never asked again', async (t) => {
    const first = await ask(t, 'is that IP malicious?');
    const history = [{ role: 'user', content: 'is that IP malicious?' }, { role: 'assistant', content: first.response.text }];
    const { response, plannerPrompt, searched } = await ask(t, '203.0.113.9', { history });
    assert.equal(searched, true);
    assert.equal(response.type, 'agent_response');
    assert.match(plannerPrompt, /User Request: "is that IP malicious\? \(203\.0\.113\.9\)"/, 'the planner sees the original question and the answer');

    // Even a reply that is still vague proceeds rather than asking again.
    const vague = await ask(t, 'that one', { history });
    assert.notEqual(vague.response.clarification, true);
    // A reply that looks like small talk ("yes") is not sent to general conversation either.
    const yes = await ask(t, 'yes', { history });
    assert.equal(yes.planned, true);
});

test('the planner may ask one short question instead of guessing; it is shown as a clarification', async (t) => {
    const plan = { thought: 'ambiguous', tools: [], clarification: 'Which domain controller do you mean, DC01 or DC02?' };
    const { response, searched } = await ask(t, 'anything odd on the domain controller', { plan });
    assert.equal(searched, false);
    assert.equal(response.clarification, true);
    assert.equal(response.text, `${CLARIFICATION_LEAD} Which domain controller do you mean, DC01 or DC02?`);
    assert.equal(response.model_generated, true);
    assert.equal(RunModel.findById(response.request_id).planner.source, 'model');
});

test('a planner "clarification" that is not one short question is ignored', async (t) => {
    for (const clarification of ['Tell me more.', 'Which host? And which day?', 'x'.repeat(250) + '?']) {
        const { response } = await ask(t, 'anything odd on the domain controller', { plan: { thought: 't', tools: [], clarification } });
        assert.notEqual(response.clarification, true, clarification.slice(0, 30));
    }
});

test('after a clarification, the planner cannot ask again', async (t) => {
    const history = [{ role: 'user', content: 'anything odd on the domain controller' }, { role: 'assistant', content: `${CLARIFICATION_LEAD} Which one?` }];
    const plan = { thought: 't', tools: [], clarification: 'Which domain controller?' };
    const { response } = await ask(t, 'the main one', { history, plan });
    assert.notEqual(response.clarification, true);
});

test('with previous evidence, "that IP" is a follow-up, not a question back', async (t) => {
    const first = await ask(t, 'show me failed logons today');
    const { response, searched } = await ask(t, 'is that IP malicious?', { options: { followUpOf: first.response.request_id } });
    assert.equal(searched, false);
    assert.equal(response.generation.planner, 'follow_up');
});
