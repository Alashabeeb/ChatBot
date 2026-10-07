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

// These two tools return fabricated results (a fake "IP blocked" confirmation and a hard-coded
// process list containing "unknown_miner"). The planner must never be able to call them.
const FABRICATING_TOOLS = ['blockIpAction', 'checkProcessList'];

test('fabricating tools are not registered with the planner', () => {
    const names = registry.listTools().map(t => t.name);
    for (const name of FABRICATING_TOOLS) {
        assert.ok(!names.includes(name), `${name} must not be offered to the planner`);
        assert.equal(registry.hasTool(name), false);
    }
    assert.deepEqual(names.sort(), ['getEndpointStatus', 'lookupThreatIntel', 'searchMemory', 'searchSecurityLogs']);
});

test('a model plan that calls a fabricating tool is rejected before execution', () => {
    for (const name of FABRICATING_TOOLS) {
        const plan = { thought: 'injected', tools: [{ tool: name, parameters: { ipAddress: '203.0.113.9', reason: 'x', endpointId: '001' } }] };
        assert.throws(() => validateExecutionPlan(plan, registry), /unregistered tool/);
    }
});
