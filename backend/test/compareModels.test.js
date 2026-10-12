import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'child_process';
import http from 'http';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { fileURLToPath } from 'url';
import { setTestEnv, stubBackends, flushBackgroundWork } from './helpers.js';

setTestEnv();
const { initDatabase } = await import('../src/config/db.js');
const { captureFixtures } = await import('../src/recording/capture.js');
initDatabase();

const backendDir = fileURLToPath(new URL('..', import.meta.url));
const script = path.resolve(backendDir, '..', 'evals', 'compare_models.py');
const python = ['python3', 'python'].find(cmd => spawnSync(cmd, ['--version']).status === 0);
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'compare-models-'));
const fixturesDir = path.join(tmp, 'fixtures');

const PLAN = { thought: 't', tools: [{ tool: 'searchSecurityLogs', parameters: { timeRange: 'now-24h', intent: 'alerts', extractedIPs: [], minSeverity: null, cleanedSearchText: '' } }] };
const LOG = { '@timestamp': '2026-10-12T08:00:00Z', rule: { id: '5710', level: 5, description: 'sshd: authentication failed', mitre: { id: ['T1110'] } }, agent: { name: 'web-01' }, data: { srcip: '203.0.113.9' } };
const GOOD = { text: 'Rule 5710 fired 2 times on web-01.', cite: [{ kind: 'rule', ref: '5710', count: 2 }, { kind: 'agent', ref: 'web-01' }] };
const FABRICATED = { text: 'It came from 91.92.93.94.', cite: [{ kind: 'rule', ref: '5710' }] };

// A local stand-in for OpenAI-compatible model endpoints: the path picks the behaviour.
const requests = [];
const server = http.createServer((req, res) => {
    let body = '';
    req.on('data', d => { body += d; });
    req.on('end', () => {
        const parsed = JSON.parse(body);
        const system = parsed.messages[0].content;
        requests.push({ path: req.url, model: parsed.model, authorization: req.headers.authorization ?? null });
        let content = '{"summary":"s","keyEntities":[]}';
        if (system.includes('Planning Engine')) content = JSON.stringify(PLAN);
        else if (system.includes('Reasoning Engine')) {
            content = req.url.startsWith('/good') ? JSON.stringify({ answer: [GOOD] })
                : req.url.startsWith('/bad') ? JSON.stringify({ answer: [GOOD, FABRICATED] })
                : 'There were some failed logins, probably an attack.';
        }
        res.writeHead(200, { 'Content-Type': 'application/json' }).end(JSON.stringify({ choices: [{ message: { content } }] }));
    });
});
let base;

before(async () => {
    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
    base = `http://127.0.0.1:${server.address().port}`;
});
after(async () => {
    await new Promise(resolve => server.close(resolve));
    fs.rmSync(tmp, { recursive: true, force: true });
});

async function makeFixtures(t) {
    if (fs.existsSync(fixturesDir)) return;
    stubBackends(t, { llm: { plan: PLAN, report: JSON.stringify({ answer: [GOOD] }) }, logs: [LOG, LOG] });
    for (const level of ['log', 'warn', 'error']) t.mock.method(console, level, () => {});
    await captureFixtures({ questions: ['show me failed logons today', 'what are the top alerts this week'], outDir: fixturesDir, timeoutMs: 10000, log: () => {} });
    await flushBackgroundWork();
    // Blank the captured answers: a comparison must score each model's own answer, never the capture's.
    for (const name of fs.readdirSync(fixturesDir).filter(n => n.endsWith('.json') && n !== 'manifest.json')) {
        const file = path.join(fixturesDir, name);
        const fixture = JSON.parse(fs.readFileSync(file, 'utf8'));
        fixture.result.report = '';
        fs.writeFileSync(file, JSON.stringify(fixture));
    }
}

function compare(config, extraArgs = [], extraEnv = {}) {
    const configPath = path.join(tmp, `config-${Math.random().toString(36).slice(2)}.json`);
    fs.writeFileSync(configPath, JSON.stringify(config));
    const env = {
        PATH: process.env.PATH, JWT_SECRET: 'compare-test-secret-0123456789abcdefghijklmn',
        OPENSEARCH_URL: 'http://opensearch.test', WAZUH_SERVER_API_URL: 'http://wazuh.test', LLM_API_URL: `${base}/default`, ...extraEnv
    };
    return new Promise(resolve => {
        const child = spawn(python, [script, '--config', configPath, '--fixtures', fixturesDir, ...extraArgs], { env });
        let output = '';
        child.stdout.on('data', d => { output += d; });
        child.stderr.on('data', d => { output += d; });
        child.on('close', status => resolve({ status, output }));
    });
}
const model = (name, pathPrefix, extra = {}) => ({
    name, approved_by: 'test suite (local stand-in)', env: { REPORT_LLM_API_URL: `${base}/${pathPrefix}/v1`, REPORT_LLM_MODEL: `${name}-model` }, ...extra
});

const skip = !python && 'python3 not installed';

test('dry run validates and calls nothing', { skip }, async (t) => {
    await makeFixtures(t);
    const before = requests.length;
    const run = await compare({ models: [model('good', 'good')] }, ['--dry-run']);
    assert.equal(run.status, 0, run.output);
    assert.match(run.output, /2 fixture\(s\)/);
    assert.match(run.output, /Dry run: nothing was called/);
    assert.equal(requests.length, before);
});

test('a model without a named approval is refused before anything is called', { skip }, async (t) => {
    await makeFixtures(t);
    const before = requests.length;
    const run = await compare({ models: [model('good', 'good'), { ...model('unapproved', 'good'), approved_by: '' }] });
    assert.equal(run.status, 2, run.output);
    assert.match(run.output, /no "approved_by"/);
    assert.equal(requests.length, before);
});

test('the example config is refused as it stands: its candidate has no approval', { skip }, async () => {
    const run = spawnSync(python, [script, '--config', path.resolve(backendDir, '..', 'evals', 'models.example.json'), '--fixtures', fixturesDir, '--dry-run'], { encoding: 'utf8' });
    assert.equal(run.status, 2, run.stdout + run.stderr);
    assert.match(run.stderr, /candidate-example.*no "approved_by"/);
});

test('keys never go in the config; a referenced key comes from the environment and is sent', { skip }, async (t) => {
    await makeFixtures(t);
    const inline = await compare({ models: [{ ...model('good', 'good'), env: { ...model('good', 'good').env, REPORT_LLM_API_KEY: 'sk-inline' } }] }, ['--dry-run']);
    assert.equal(inline.status, 2);
    assert.match(inline.output, /looks like a credential/);

    const missing = await compare({ models: [model('good', 'good', { api_key_env: { REPORT_LLM_API_KEY: 'COMPARE_TEST_KEY' } })] });
    assert.equal(missing.status, 2);
    assert.match(missing.output, /COMPARE_TEST_KEY .* is not set/);

    const before = requests.length;
    const run = await compare({ models: [model('keyed', 'good', { api_key_env: { REPORT_LLM_API_KEY: 'COMPARE_TEST_KEY' } })] }, ['--out', path.join(tmp, 'keyed')], { COMPARE_TEST_KEY: 'sk-from-env' });
    assert.equal(run.status, 0, run.output);
    const reportCalls = requests.slice(before).filter(r => r.path.startsWith('/good'));
    assert.ok(reportCalls.length > 0);
    assert.ok(reportCalls.every(r => r.authorization === 'Bearer sk-from-env'));
    assert.ok(requests.slice(before).filter(r => r.path === '/default').every(r => r.authorization === null), 'the key only goes to its own endpoint');
    assert.ok(!fs.readFileSync(path.join(tmp, 'keyed', 'comparison.json'), 'utf8').includes('sk-from-env'));
});

test('side-by-side: quality, fabrication and format failures are measured per model', { skip }, async (t) => {
    await makeFixtures(t);
    const out = path.join(tmp, 'side-by-side');
    const run = await compare({ models: [model('good', 'good'), model('bad', 'bad'), model('freetext', 'freetext')] }, ['--out', out]);
    assert.equal(run.status, 0, run.output);
    const { results } = JSON.parse(fs.readFileSync(path.join(out, 'comparison.json'), 'utf8'));
    const by = Object.fromEntries(results.map(r => [r.model, r]));
    for (const r of results) {
        assert.equal(r.cases, 2);
        assert.equal(r.replay_matched, 2, `${r.model}: the captured searches replayed`);
        assert.equal(r.fabrications_shown, 0, `${r.model}: verification keeps fabrications out of the answer`);
        assert.equal(typeof r.model_ms_mean, 'number');
        assert.ok(r.prompt_chars_mean > 0);
    }
    assert.deepEqual([by.good.claims, by.good.claims_dropped, by.good.format_failures], [2, 0, 0]);
    assert.deepEqual([by.bad.claims, by.bad.claims_dropped, by.bad.format_failures], [4, 2, 0]);
    assert.equal(by.bad.dropped_rate, 0.5);
    assert.equal(by.freetext.format_failures, 2);
    assert.ok(by.good.mean_score >= by.freetext.mean_score);
    assert.ok(by.good.mean_score > 0, 'scored on the model\'s answer (the captured one is blank and would score 0)');
    assert.match(run.output, /model\s+cases\s+matched\s+score/);
    // Each model's report went to its own endpoint, under its own name.
    for (const name of ['good', 'bad', 'freetext']) {
        assert.ok(requests.some(r => r.path.startsWith(`/${name}`) && r.model === `${name}-model`), name);
    }
});

test('--live-planner also asks each planner model, and times it', { skip }, async (t) => {
    await makeFixtures(t);
    const before = requests.length;
    const out = path.join(tmp, 'live');
    const run = await compare({ models: [{ ...model('good', 'good'), env: { ...model('good', 'good').env, PLANNER_LLM_API_URL: `${base}/planner/v1`, PLANNER_LLM_MODEL: 'cand-planner' } }] }, ['--out', out, '--live-planner']);
    assert.equal(run.status, 0, run.output);
    assert.ok(requests.slice(before).some(r => r.path.startsWith('/planner') && r.model === 'cand-planner'));
    const [row] = JSON.parse(fs.readFileSync(path.join(out, 'comparison.json'), 'utf8')).results;
    assert.equal(row.replay_matched, 2, 'the planner reproduced the captured searches');
    assert.equal(typeof row.planning_ms_mean, 'number');
});

test('synthetic cases are refused: models are compared on real captured fixtures only', { skip }, async (t) => {
    await makeFixtures(t);
    const mixed = path.join(tmp, 'mixed');
    fs.cpSync(fixturesDir, mixed, { recursive: true });
    const synthetic = path.resolve(backendDir, '..', 'evals', 'synthetic');
    const one = fs.readdirSync(synthetic).find(n => n.endsWith('.json'));
    fs.copyFileSync(path.join(synthetic, one), path.join(mixed, one));
    const configPath = path.join(tmp, 'synthetic-config.json');
    fs.writeFileSync(configPath, JSON.stringify({ models: [model('good', 'good')] }));
    const run = spawnSync(python, [script, '--config', configPath, '--fixtures', mixed, '--dry-run'], { encoding: 'utf8' });
    assert.equal(run.status, 2, run.stdout + run.stderr);
    assert.match(run.stderr, /SYNTHETIC case/);
});
