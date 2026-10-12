import { test, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import axios from 'axios';
import { setTestEnv, stubBackends, flushBackgroundWork, USER_ID, llmReply } from './helpers.js';

setTestEnv();
const { initDatabase } = await import('../src/config/db.js');
const { generateLLMPlan } = await import('../src/agent/planner.js');
const { runAgentWorkflow } = await import('../src/agent/runtime.js');
const { RunModel } = await import('../src/models/Run.js');
const { default: registry } = await import('../src/llm/registry.js');
initDatabase();

afterEach(() => { delete process.env.PLANNER_PROMPT_MAX_CHARS; delete process.env.LLM_PLANNER_MAX_TOKENS; });

const PLAN = { thought: 't', tools: [{ tool: 'searchSecurityLogs', parameters: { timeRange: 'now-24h', intent: 'alerts', extractedIPs: [], minSeverity: null, cleanedSearchText: '' } }] };
const long = n => 'word '.repeat(n / 5);
const HISTORY = Array.from({ length: 10 }, (_, i) => ({ role: i % 2 ? 'assistant' : 'user', content: i % 2 ? long(4000) : `question ${i} ${long(1500)}` }));
const STORED = { recent: [{ user: 'earlier question', bot: long(5000) }, { user: 'another', bot: long(5000) }], preferences: [long(1000), long(1000), long(1000), long(1000)] };

function capturePlanner(t) {
    const bodies = [];
    t.mock.method(axios, 'post', async (url, body) => {
        bodies.push(body);
        return llmReply(JSON.stringify(PLAN));
    });
    t.mock.method(console, 'log', () => {});
    t.mock.method(console, 'warn', () => {});
    return bodies;
}
const total = body => body.messages.reduce((n, m) => n + m.content.length, 0);

test('the tool list is sent as compact JSON', async (t) => {
    const bodies = capturePlanner(t);
    await generateLLMPlan('show me failed logons today');
    assert.ok(bodies[0].messages.at(-1).content.includes(JSON.stringify(registry.listTools())), 'compact tool list');
    assert.ok(!bodies[0].messages.at(-1).content.includes('\n  {'), 'no indentation');
});

test('the planner sees the last four chat messages, shortened (questions 500, answers 300 characters)', async (t) => {
    const bodies = capturePlanner(t);
    await generateLLMPlan('what about yesterday', HISTORY);
    const history = bodies[0].messages.slice(1, -1);
    assert.equal(history.length, 4);
    for (const m of history) assert.ok(m.content.length <= (m.role === 'user' ? 500 : 300), `${m.role}: ${m.content.length}`);
    assert.match(history.at(-2).content, /^question 8/, 'the most recent turns are kept');
});

test('stored context is compact and shortened', async (t) => {
    process.env.PLANNER_PROMPT_MAX_CHARS = '1000000';   // no trimming, so only the shortening is under test
    const bodies = capturePlanner(t);
    await generateLLMPlan('show me failed logons today', [], { storedContext: STORED });
    const prompt = bodies[0].messages.at(-1).content;
    const block = prompt.slice(prompt.indexOf('<stored_context>'), prompt.indexOf('</stored_context>'));
    assert.ok(block.length > 100, 'the stored context is there');
    assert.ok(block.length < 2000, `stored context is ${block.length} characters`);
    assert.ok(!block.includes('\n  '), 'compact JSON');
});

test('a hard limit drops stored context, then history, and says what it trimmed; the plan still comes from the model', async (t) => {
    process.env.PLANNER_PROMPT_MAX_CHARS = '5400';
    const bodies = capturePlanner(t);
    const plan = await generateLLMPlan('what about yesterday', HISTORY, { storedContext: STORED });
    assert.ok(total(bodies[0]) <= 5400, `planner request is ${total(bodies[0])} characters`);
    assert.equal(plan.source, 'model');
    assert.deepEqual(plan.promptTrimmed, ['stored context left out', 'chat history cut to the last 2 messages', 'chat history left out']);
    assert.equal(plan.promptChars, total(bodies[0]));
});

test('without a limit set, a long conversation still gives a planner request under 10,000 characters', async (t) => {
    const bodies = capturePlanner(t);
    await generateLLMPlan('what about yesterday', HISTORY, { storedContext: STORED });
    assert.ok(total(bodies[0]) <= 10000, `planner request is ${total(bodies[0])} characters`);
});

test('the plan length is capped (LLM_PLANNER_MAX_TOKENS, default 600)', async (t) => {
    let bodies = capturePlanner(t);
    await generateLLMPlan('show me failed logons today');
    assert.equal(bodies[0].max_tokens, 600);
    axios.post.mock.restore();
    process.env.LLM_PLANNER_MAX_TOKENS = '400';
    bodies = capturePlanner(t);
    await generateLLMPlan('show me failed logons today');
    assert.equal(bodies[0].max_tokens, 400);
});

test('the run record keeps the planner request size and what was trimmed', async (t) => {
    stubBackends(t, { llm: { plan: PLAN, report: '{"answer":[]}' }, logs: [] });
    t.mock.method(console, 'log', () => {});
    t.mock.method(console, 'warn', () => {});
    const response = await runAgentWorkflow('show me failed logons today', HISTORY, USER_ID);
    await flushBackgroundWork();
    const run = RunModel.findById(response.request_id);
    assert.equal(typeof run.planner.promptChars, 'number');
    assert.ok(run.planner.promptChars <= 10000);
    assert.deepEqual(run.planner.promptTrimmed, []);
    assert.equal(run.timings.plannerPromptChars, run.planner.promptChars);
});
