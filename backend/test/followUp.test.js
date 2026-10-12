import { test, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { setTestEnv, stubBackends, flushBackgroundWork, USER_ID } from './helpers.js';

setTestEnv();
const { initDatabase } = await import('../src/config/db.js');
const { processChatQuery } = await import('../src/services/chat.service.js');
const { clearEvidenceCache } = await import('../src/agent/evidenceCache.js');
const { RunModel } = await import('../src/models/Run.js');

initDatabase();
beforeEach(() => { clearEvidenceCache(); delete process.env.FOLLOW_UP_TTL_MS; });

const PLAN = { thought: 't', tools: [{ tool: 'searchSecurityLogs', parameters: { timeRange: 'now-24h', intent: 'brute_force', extractedIPs: [], minSeverity: null, cleanedSearchText: '' } }] };
const rec = (ruleId, agent, ip, user) => ({
    '@timestamp': '2026-10-12T08:00:00Z', rule: { id: ruleId, level: 5, description: `rule ${ruleId}`, mitre: { id: ['T1110'] } },
    agent: { name: agent }, data: { srcip: ip, srcuser: user }
});
const LOGS = [rec('5710', 'web-01', '203.0.113.9', 'root'), rec('5710', 'web-01', '203.0.113.9', 'root'), rec('5712', 'web-02', '198.51.100.4', 'admin')];
const cite = (kind, ref, count) => (count === undefined ? { kind, ref } : { kind, ref, count });
const REPORT = { answer: [{ text: 'Rule 5710 fired 2 times on web-01.', cite: [cite('rule', '5710', 2), cite('agent', 'web-01')] }] };
const quiet = t => { for (const level of ['log', 'warn', 'error']) t.mock.method(console, level, () => {}); };

async function firstSearch(t, { userId = USER_ID } = {}) {
    quiet(t);
    const stubs = stubBackends(t, { llm: { plan: PLAN, report: JSON.stringify(REPORT) }, logs: LOGS });
    const response = await processChatQuery('show me failed logons today', [], userId);
    await flushBackgroundWork();
    return { response, stubs };
}
const plannerCalls = stubs => stubs.llmCalls.filter(m => m[0].content.includes('Planning Engine')).length;
const reportCalls = stubs => stubs.llmCalls.filter(m => m[0].content.includes('Reasoning Engine'));

async function followUp(stubs, text, followUpOf, userId = USER_ID) {
    const before = { planner: plannerCalls(stubs), searches: stubs.searchCalls.length, reports: reportCalls(stubs).length };
    const response = await processChatQuery(text, [], userId, { followUpOf });
    await flushBackgroundWork();
    return {
        response,
        planned: plannerCalls(stubs) > before.planner,
        searched: stubs.searchCalls.length > before.searches,
        reported: reportCalls(stubs).length > before.reports,
        prompt: reportCalls(stubs).at(-1)?.at(-1)?.content ?? ''
    };
}

test('a follow-up naming something in the previous evidence is answered from it: no new plan, no new search', async (t) => {
    const { response: first, stubs } = await firstSearch(t);
    const r = await followUp(stubs, 'tell me more about rule 5710', first.request_id);
    assert.equal(r.planned, false, 'no planner call');
    assert.equal(r.searched, false, 'no OpenSearch call');
    assert.equal(r.reported, true, 'the report model answers from the cached evidence');
    assert.match(r.prompt, /"ruleId":"5710"/);   // compact JSON (report size fix 2)
    assert.match(r.response.summary, /^\*\*Answered from the evidence of your previous search\*\* \("show me failed logons today"/);
    assert.match(r.response.summary, /\*\*Searched:\*\* Wazuh alerts \(3 matches\)/);
    assert.ok(r.response.summary.includes(REPORT.answer[0].text), 'claims still verified against that evidence and shown');
    assert.equal(r.response.generation.planner, 'follow_up');
    assert.equal(r.response.follow_up_of, first.request_id);
    assert.deepEqual(Object.keys(r.response.raw_logs), Object.keys(first.raw_logs), 'View Full Details shows the same evidence');
    const run = RunModel.findById(r.response.request_id);
    assert.equal(run.planner.source, 'follow_up');
    assert.equal(run.planner.followUpOf, first.request_id);
    assert.equal(run.tools.length, 2, 'the run record lists the evidence it reused');
});

test('pronouns and "which one" refer back to the previous answer', async (t) => {
    const { response: first, stubs } = await firstSearch(t);
    for (const text of ['which IP was that?', 'why is it suspicious?', 'explain those alerts']) {
        const r = await followUp(stubs, text, first.request_id);
        assert.equal(r.searched, false, text);
        assert.equal(r.response.generation.planner, 'follow_up', text);
    }
});

test('a follow-up of a follow-up still uses the original evidence', async (t) => {
    const { response: first, stubs } = await firstSearch(t);
    const second = await followUp(stubs, 'what about web-02?', first.request_id);
    const third = await followUp(stubs, 'and the user on it?', second.response.request_id);
    assert.equal(third.searched, false);
    assert.match(third.response.summary, /\("show me failed logons today"/);
});

test('new data, a time window or "search again" always searches again', async (t) => {
    const { response: first, stubs } = await firstSearch(t);
    for (const text of ['search again for rule 5710', 'what about yesterday?', 'rule 5710 in the last 7 days', 'show me the latest on web-01']) {
        const r = await followUp(stubs, text, first.request_id);
        assert.equal(r.searched, true, text);
        assert.notEqual(r.response.generation.planner, 'follow_up', text);
    }
});

test('an unrelated question searches again, even with a previous search given', async (t) => {
    const { response: first, stubs } = await firstSearch(t);
    const r = await followUp(stubs, 'list the vulnerabilities on DC01', first.request_id);
    assert.equal(r.searched, true);
});

test("another user's search, an unknown ID or expired evidence is never reused", async (t) => {
    const { response: first, stubs } = await firstSearch(t);
    assert.equal((await followUp(stubs, 'tell me more about rule 5710', first.request_id, 'user_other')).searched, true, 'other user');
    assert.equal((await followUp(stubs, 'tell me more about rule 5710', 'no-such-request')).searched, true, 'unknown');
    process.env.FOLLOW_UP_TTL_MS = '1';
    await new Promise(resolve => setTimeout(resolve, 5));
    assert.equal((await followUp(stubs, 'tell me more about rule 5710', first.request_id)).searched, true, 'expired');
});

test('"explain that" is answered from the evidence, not routed to general conversation', async (t) => {
    const { response: first, stubs } = await firstSearch(t);
    const r = await followUp(stubs, 'explain that', first.request_id);
    assert.equal(r.response.type, 'agent_response');
    assert.equal(r.response.generation.planner, 'follow_up');
});
