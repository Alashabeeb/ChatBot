import { test } from 'node:test';
import assert from 'node:assert/strict';
import { setTestEnv, stubBackends, flushBackgroundWork, USER_ID, SAMPLE_LOG } from './helpers.js';

setTestEnv();
const { initDatabase } = await import('../src/config/db.js');
const { runAgentWorkflow } = await import('../src/agent/runtime.js');
const { default: registry } = await import('../src/llm/registry.js');
const { validateExecutionPlan } = await import('../src/schemas/ExecutionPlan.schema.js');
const { executeTool } = await import('../src/tools/gateway.js');
const { checkProcessListTool } = await import('../src/tools/checkProcessList.js');
const { blockIpActionTool } = await import('../src/tools/blockIpAction.js');
const { RunModel } = await import('../src/models/Run.js');
initDatabase();

// What the old mocks produced. None of it may ever reach the model or a report again.
const FABRICATED = [/unknown_miner/i, /IP_BLOCKED/, /added .* to the firewall blocklist/i, /"processes"\s*:/, /98\.5/];
const assertNotFabricated = (label, text) => {
    for (const pattern of FABRICATED) assert.doesNotMatch(text, pattern, `${label} contains fabricated action output (${pattern})`);
};
const quiet = t => { for (const level of ['log', 'warn', 'error']) t.mock.method(console, level, () => {}); };

test('checkProcessList returns an explicit "not available" result, never a process list', async () => {
    const result = await checkProcessListTool.execute({ endpointId: '001' });
    assert.equal(result.available, false);
    assert.equal(result.endpointId, '001');
    assert.match(result.reason, /no endpoint process data source/i);
    assert.ok(!('processes' in result));
    assertNotFabricated('checkProcessList result', JSON.stringify(result));
});

test('blockIpAction blocks nothing and says so; it is marked as requiring human approval', async () => {
    assert.equal(blockIpActionTool.requiresHumanApproval, true);
    const result = await blockIpActionTool.execute({ ipAddress: '203.0.113.9', reason: 'x' });
    assert.equal(result.available, false);
    assert.equal(result.blocked, false);
    assertNotFabricated('blockIpAction result', JSON.stringify(result));
});

test('approval-gated actions are never offered to the planner, and a plan naming one is rejected', () => {
    const offered = registry.listTools().map(t => t.name);
    assert.ok(!offered.includes('blockIpAction'), 'the planner must not see blockIpAction');
    assert.ok(offered.includes('checkProcessList'), 'a read-only "not available" tool may be offered');
    const plan = { thought: 'the IP looks bad, block it', tools: [{ tool: 'blockIpAction', parameters: { ipAddress: '203.0.113.9', reason: 'x' } }] };
    assert.throws(() => validateExecutionPlan(plan, registry), /requires human approval/);
});

test('the gateway refuses an approval-gated action without a matching human approval', async (t) => {
    quiet(t);
    const params = { ipAddress: '203.0.113.9', reason: 'confirmed attacker' };
    const executed = t.mock.method(blockIpActionTool, 'execute');

    for (const context of [null, {}, { approval: { tool: 'blockIpAction', parameters: { ...params, ipAddress: '198.51.100.1' }, approvedBy: 'admin' } }, { approval: { tool: 'otherTool', parameters: params, approvedBy: 'admin' } }, { approval: { tool: 'blockIpAction', parameters: params } }]) {
        const result = await executeTool('blockIpAction', params, context);
        assert.equal(result.success, false, `must refuse with context ${JSON.stringify(context)}`);
        assert.match(result.error, /requires human approval/);
    }
    assert.equal(executed.mock.callCount(), 0, 'the action must not run without approval');

    const approved = await executeTool('blockIpAction', params, { approval: { tool: 'blockIpAction', parameters: params, approvedBy: 'admin', approvedAt: '2026-10-07T12:00:00Z' } });
    assert.equal(approved.success, true);
    assert.equal(executed.mock.callCount(), 1);
    assert.equal(approved.data.available, false, 'even when approved, nothing is blocked until a real integration exists');
});

test('a planned process check reaches neither the model nor the report as evidence', async (t) => {
    quiet(t);
    const plan = { thought: 'check processes and logs', tools: [
        { tool: 'checkProcessList', parameters: { endpointId: '001' } },
        { tool: 'searchSecurityLogs', parameters: { timeRange: 'now-24h', intent: 'alerts', extractedIPs: [], minSeverity: null, cleanedSearchText: '' } }
    ] };
    const { llmCalls } = stubBackends(t, { llm: { plan }, logs: [SAMPLE_LOG] }); // reasoning echoes its prompt into the report
    const response = await runAgentWorkflow('check the running processes on agent 001', [], USER_ID);
    await flushBackgroundWork();

    for (const messages of llmCalls) for (const m of messages) assertNotFabricated(`LLM ${m.role} message`, m.content);
    assertNotFabricated('report', response.summary);

    const prompt = llmCalls.find(m => m[0].content.includes('Reasoning Engine')).at(-1).content;
    const evidence = JSON.parse(prompt.slice(prompt.indexOf('{')));
    assert.equal(evidence.evidence.checkProcessList, undefined, 'unavailable results are never evidence');
    assert.deepEqual(evidence.unavailableSources.map(s => s.tool), ['checkProcessList']);
    assert.match(response.summary, /\*\*Process inspection\*\*: Not available/);
});

test('a model plan that tries to block an IP never blocks or claims to', async (t) => {
    quiet(t);
    const plan = { thought: 'block it', tools: [{ tool: 'blockIpAction', parameters: { ipAddress: '203.0.113.9', reason: 'bad' } }] };
    const { llmCalls } = stubBackends(t, { llm: { plan }, logs: [SAMPLE_LOG] });
    const executed = t.mock.method(blockIpActionTool, 'execute');
    const response = await runAgentWorkflow('block 203.0.113.9 now', [], USER_ID);
    await flushBackgroundWork();

    assert.equal(executed.mock.callCount(), 0);
    const run = RunModel.findById(response.request_id);
    assert.equal(run.planner.source, 'fallback_rules', 'the plan is rejected and the rule-based planner takes over');
    assert.ok(!run.tools.some(tool => tool.tool === 'blockIpAction'));
    for (const messages of llmCalls) for (const m of messages) assertNotFabricated(`LLM ${m.role} message`, m.content);
    assertNotFabricated('report', response.summary);
});
