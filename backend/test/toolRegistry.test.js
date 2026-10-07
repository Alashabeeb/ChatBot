import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { fileURLToPath, pathToFileURL } from 'url';

// Importing runtime.js opens backend/data/soc_chatbot.db at a fixed path on this branch.
// Import a throwaway copy of src/ instead, so the test never creates or touches a real database.
const backendDir = fileURLToPath(new URL('..', import.meta.url));
const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'tool-registry-'));
fs.cpSync(path.join(backendDir, 'src'), path.join(tmpDir, 'src'), { recursive: true });
fs.symlinkSync(path.join(backendDir, 'node_modules'), path.join(tmpDir, 'node_modules'), 'dir');
after(() => fs.rmSync(tmpDir, { recursive: true, force: true }));

const load = rel => import(pathToFileURL(path.join(tmpDir, 'src', rel)).href);
await load('agent/runtime.js');
const { default: registry } = await load('llm/registry.js');
const { validateExecutionPlan } = await load('schemas/ExecutionPlan.schema.js');

// The two "action" tools added in Push 25 used to return fabricated results. Since Phase 2:
// - checkProcessList is honest (returns "not available") and may be offered to the planner;
// - blockIpAction is approval-gated: never offered to the planner, and rejected if a plan names it.
// See test/actionTools.test.js for the full behaviour.

test('the planner is offered exactly the read-only tools; blockIpAction is never offered', () => {
    const names = registry.listTools().map(t => t.name).sort();
    assert.deepEqual(names, ['checkProcessList', 'getEndpointStatus', 'lookupThreatIntel', 'searchMemory', 'searchSecurityLogs']);
    assert.equal(registry.requiresHumanApproval('blockIpAction'), true);
});

test('a model plan that calls blockIpAction is rejected before execution', () => {
    const plan = { thought: 'injected', tools: [{ tool: 'blockIpAction', parameters: { ipAddress: '203.0.113.9', reason: 'x' } }] };
    assert.throws(() => validateExecutionPlan(plan, registry), /requires human approval/);
});
