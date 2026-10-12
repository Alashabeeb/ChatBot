import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'child_process';
import fs from 'fs';
import os from 'os';
import path from 'path';
import Database from 'better-sqlite3';
import { setTestEnv, stubBackends, flushBackgroundWork, USER_ID, SAMPLE_LOG, SEARCH_PLAN } from './helpers.js';

setTestEnv();
const { default: db, initDatabase } = await import('../src/config/db.js');
const { runAgentWorkflow } = await import('../src/agent/runtime.js');
const { RunModel } = await import('../src/models/Run.js');
const { memoryManager } = await import('../src/memory/manager.js');
const { saveSessionMessage, getSessionMessages } = await import('../src/controllers/session.controller.js');

initDatabase();

// The report model returns claims with citations (Phase 4); this one is grounded in SAMPLE_LOG's search.
const MODEL_CLAIM = 'One sshd authentication failure on web-01.';
const MODEL_REPORT = JSON.stringify({ answer: [{ text: MODEL_CLAIM, cite: [{ kind: 'total', ref: 'searchSecurityLogs', count: 1 }, { kind: 'agent', ref: 'web-01' }] }] });
const RAW_LOG_SENTINEL = 'RAW-LOG-SENTINEL-full_log-must-not-be-stored';
const LOG_WITH_SENTINEL = { ...SAMPLE_LOG, full_log: RAW_LOG_SENTINEL };

/** Captures console output (and silences it) for the duration of fn, including background work. */
async function captureConsole(t, fn) {
    const lines = [];
    for (const level of ['log', 'warn', 'error']) {
        t.mock.method(console, level, (...args) => lines.push(args.map(a => (a instanceof Error ? a.message : String(a))).join(' ')));
    }
    try {
        return { result: await fn(), lines };
    } finally {
        await flushBackgroundWork();
        for (const level of ['log', 'warn', 'error']) console[level].mock.restore();
    }
}

function fakeRes() {
    return {
        statusCode: 200,
        body: undefined,
        status(code) { this.statusCode = code; return this; },
        json(body) { this.body = body; return this; }
    };
}

test('completed run: one record with planner output, the exact OpenSearch query, counts, report, timings and flags', async (t) => {
    const { searchCalls } = stubBackends(t, { llm: { plan: SEARCH_PLAN, report: MODEL_REPORT }, logs: [LOG_WITH_SENTINEL] });

    const { result: response, lines } = await captureConsole(t, () => runAgentWorkflow('Show brute force attacks', [], USER_ID));
    const run = RunModel.findById(response.request_id);

    assert.ok(response.request_id, 'response must carry request_id');
    assert.ok(run, 'run record must exist for the returned request_id');
    assert.equal(run.status, 'completed');
    assert.equal(run.userId, USER_ID);
    assert.equal(run.question, 'Show brute force attacks');

    // Full planner output.
    assert.equal(run.planner.source, 'model');
    assert.equal(run.planner.rawOutput, JSON.stringify(SEARCH_PLAN));
    assert.equal(run.planner.thought, SEARCH_PLAN.thought);
    assert.deepEqual(run.planner.tools, SEARCH_PLAN.tools);
    assert.equal(run.planner.error, null);

    // The query recorded is exactly the one sent to OpenSearch.
    // One planned search runs as two OpenSearch calls (non-firewall and firewall halves);
    // each recorded query must be exactly the body that was sent.
    assert.equal(searchCalls.length, 2);
    assert.equal(run.tools.length, 2);
    for (const scope of ['non_firewall', 'firewall']) {
        const recorded = run.tools.find(tool => tool.parameters?.sourceScope === scope);
        assert.ok(recorded, `no run-record entry for the ${scope} half`);
        assert.equal(recorded.tool, 'searchSecurityLogs');
        const sent = searchCalls.filter(call => JSON.stringify(call.body) === JSON.stringify(recorded.query));
        assert.equal(sent.length, 1, `the ${scope} query in the run record must match exactly one query sent`);
        assert.equal(recorded.targetIndex, sent[0].url);
        assert.deepEqual(recorded.parameters, { ...SEARCH_PLAN.tools[0].parameters, sourceScope: scope });
        assert.equal(recorded.success, true);
    }
    const search = run.tools.find(tool => tool.parameters.sourceScope === 'non_firewall');
    assert.equal(search.totalHits, 1);
    assert.equal(search.returnedCount, 1);
    assert.equal(run.tools.find(tool => tool.parameters.sourceScope === 'firewall').totalHits, 0);

    // Counts only, never raw logs.
    assert.ok(!('rawData' in search), 'tool metadata must not include rawData');
    const rawRow = db.prepare('SELECT * FROM runs WHERE request_id = ?').get(response.request_id);
    assert.doesNotMatch(JSON.stringify(rawRow), new RegExp(RAW_LOG_SENTINEL), 'raw log content must not be stored in the run record');

    // Report, timings, errors, F-01 flags.
    assert.equal(run.reportText, response.summary);
    for (const key of ['planningDuration', 'executionDuration', 'aggregationDuration', 'reasoningDuration', 'totalDuration']) {
        assert.equal(typeof run.timings[key], 'number', `timings.${key}`);
    }
    assert.deepEqual(run.errors, []);
    assert.equal(run.modelGenerated, true);
    assert.equal(run.modelGenerated, response.model_generated);
    assert.deepEqual(run.generation, response.generation);
    assert.ok(run.completedAt >= run.startedAt);

    // Every console line from the run is tagged with the same request ID.
    assert.ok(lines.length > 0);
    for (const line of lines) {
        assert.ok(line.includes(`[req:${response.request_id}]`), `untagged console line: ${line}`);
    }
});

test('model down: record flags the fallback and stores the model and planner errors', async (t) => {
    stubBackends(t, { llm: 'down', logs: [SAMPLE_LOG] });

    const { result: response } = await captureConsole(t, () => runAgentWorkflow('Show brute force attacks', [], USER_ID));
    const run = RunModel.findById(response.request_id);

    assert.equal(run.status, 'completed');
    assert.equal(run.modelGenerated, false);
    assert.deepEqual(run.generation, { planner: 'fallback_rules', report: 'fallback_model_unavailable', model: 'foundation-sec-8b-instruct', models: { planner: 'foundation-sec-8b-instruct', report: 'foundation-sec-8b-instruct' } });
    assert.equal(run.planner.rawOutput, null);
    assert.match(run.planner.error, /LLM did not return a response/);
    assert.ok(run.errors.some(e => e.stage === 'llm' && /ECONNREFUSED/.test(e.message)), JSON.stringify(run.errors));
    assert.ok(run.errors.some(e => e.stage === 'planner'), JSON.stringify(run.errors));
    assert.match(run.reportText, /AI analysis is not included/);
});

test('failed run: record is finalized as failed with the error, and the thrown error carries the request ID', async (t) => {
    stubBackends(t, { llm: { plan: SEARCH_PLAN, report: MODEL_REPORT }, logs: [SAMPLE_LOG] });
    t.mock.method(memoryManager, 'retrieve', async () => { throw new Error('memory store offline'); });

    let thrown;
    await captureConsole(t, async () => {
        thrown = await runAgentWorkflow('Show brute force attacks', [], USER_ID).catch(e => e);
    });

    assert.ok(thrown instanceof Error);
    assert.ok(thrown.requestId, 'thrown error must carry requestId');
    const run = RunModel.findById(thrown.requestId);
    assert.equal(run.status, 'failed');
    assert.ok(run.errors.some(e => e.stage === 'runtime' && e.message === 'memory store offline'), JSON.stringify(run.errors));
    assert.equal(typeof run.timings.totalDuration, 'number');
    assert.ok(run.completedAt);
});

test('hung model call: the run is already recorded as running (the F-03 symptom is visible)', async (t) => {
    stubBackends(t, { llm: 'hang', logs: [SAMPLE_LOG] });
    const before = new Set(db.prepare('SELECT request_id FROM runs').all().map(r => r.request_id));

    t.mock.method(console, 'log', () => {});
    runAgentWorkflow('Show brute force attacks', [], USER_ID); // never settles: the planner call hangs
    await flushBackgroundWork();

    const started = db.prepare("SELECT request_id, status, completed_at FROM runs").all().filter(r => !before.has(r.request_id));
    assert.equal(started.length, 1);
    assert.equal(started[0].status, 'running');
    assert.equal(started[0].completed_at, null);
});

test('saved report links to its run only when the run belongs to the saving user', async (t) => {
    stubBackends(t, { llm: { plan: SEARCH_PLAN, report: MODEL_REPORT }, logs: [SAMPLE_LOG] });
    const { result: response } = await captureConsole(t, () => runAgentWorkflow('Show brute force attacks', [], USER_ID));

    const now = new Date().toISOString();
    db.prepare("INSERT INTO users (id, username, password_hash, role, created_at) VALUES ('user_other', 'other', 'x', 'user', ?)").run(now);

    const save = (userId, sessionId, msgId, requestId) => {
        const res = fakeRes();
        return saveSessionMessage({ params: { id: sessionId }, user: { id: userId }, body: { id: msgId, role: 'assistant', type: 'agent_response', summary: response.summary, requestId } }, res).then(() => res);
    };

    t.mock.method(console, 'warn', () => {});
    const own = await save(USER_ID, 'sess_link', 'msg_own', response.request_id);
    const foreign = await save('user_other', 'sess_other', 'msg_foreign', response.request_id);
    const bogus = await save(USER_ID, 'sess_link', 'msg_bogus', 'not-a-real-run');

    assert.equal(own.statusCode, 201);
    assert.equal(own.body.message.request_id, response.request_id);
    assert.equal(foreign.body.message.request_id, null, "another user's run must not be linkable");
    assert.equal(bogus.body.message.request_id, null);

    const listed = fakeRes();
    await getSessionMessages({ params: { id: 'sess_link' }, user: { id: USER_ID } }, listed);
    const saved = listed.body.messages.find(m => m.id === 'msg_own');
    assert.equal(saved.request_id, response.request_id);

    // Saved report → run record → the same flags and report text.
    const run = RunModel.findById(saved.request_id);
    assert.equal(run.reportText, saved.summary);
    assert.equal(run.modelGenerated, true);
});

test('initDatabase migrates a pre-existing database: adds messages.request_id and runs, keeps existing rows', () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'run-migration-'));
    try {
        const dbPath = path.join(tmpDir, 'legacy.db');
        // Schema as it was before run logging.
        const legacy = new Database(dbPath);
        legacy.exec(`
            CREATE TABLE users (id TEXT PRIMARY KEY, username TEXT UNIQUE NOT NULL COLLATE NOCASE, password_hash TEXT NOT NULL, role TEXT NOT NULL CHECK(role IN ('admin', 'user')), created_at TEXT NOT NULL);
            CREATE TABLE sessions (id TEXT PRIMARY KEY, user_id TEXT NOT NULL, title TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL, FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE);
            CREATE TABLE messages (id TEXT PRIMARY KEY, session_id TEXT NOT NULL, user_id TEXT NOT NULL, role TEXT NOT NULL, type TEXT NOT NULL, text TEXT, summary TEXT, raw_logs TEXT, total_hits INTEGER, is_new INTEGER DEFAULT 0, created_at TEXT NOT NULL, FOREIGN KEY (session_id) REFERENCES sessions(id) ON DELETE CASCADE, FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE);
            INSERT INTO users VALUES ('user_admin_root', 'admin', 'x', 'admin', '2026-01-01T00:00:00Z');
            INSERT INTO sessions VALUES ('s1', 'user_admin_root', 'Old session', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z');
            INSERT INTO messages (id, session_id, user_id, role, type, summary, created_at) VALUES ('m_old', 's1', 'user_admin_root', 'assistant', 'agent_response', 'old report', '2026-01-01T00:00:00Z');
        `);
        legacy.close();

        const script = `
            const { initDatabase } = await import(${JSON.stringify(new URL('../src/config/db.js', import.meta.url).href)});
            initDatabase();
            initDatabase();
        `;
        const result = spawnSync(process.execPath, ['--input-type=module', '-e', script], {
            cwd: tmpDir,
            env: { ...process.env, SOC_DB_PATH: dbPath, JWT_SECRET: 'x' },
            encoding: 'utf8'
        });
        assert.equal(result.status, 0, result.stdout + result.stderr);

        const migrated = new Database(dbPath, { readonly: true });
        try {
            assert.ok(migrated.prepare('PRAGMA table_info(messages)').all().some(c => c.name === 'request_id'));
            assert.ok(migrated.prepare("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'runs'").get());
            assert.deepEqual(migrated.prepare("SELECT id, summary, request_id FROM messages").all(), [{ id: 'm_old', summary: 'old report', request_id: null }]);
        } finally {
            migrated.close();
        }
    } finally {
        fs.rmSync(tmpDir, { recursive: true, force: true });
    }
});
