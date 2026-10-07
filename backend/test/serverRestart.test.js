import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'child_process';
import net from 'net';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { fileURLToPath } from 'url';
import Database from 'better-sqlite3';

const serverPath = fileURLToPath(new URL('../src/server.js', import.meta.url));
const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'server-restart-'));
const dbPath = path.join(tmpDir, 'soc_chatbot.db');
const ADMIN_PASSWORD = 'restart-test-password';

const cleanups = [];
after(async () => {
    for (const cleanup of cleanups.reverse()) await cleanup();
    fs.rmSync(tmpDir, { recursive: true, force: true });
});

function freePort() {
    return new Promise((resolve, reject) => {
        const srv = net.createServer();
        srv.listen(0, '127.0.0.1', () => {
            const { port } = srv.address();
            srv.close(() => resolve(port));
        });
        srv.on('error', reject);
    });
}

/** A model server that accepts connections and never answers: the F-03 hang. */
async function startHangingModelServer() {
    const sockets = new Set();
    const srv = net.createServer(socket => {
        sockets.add(socket);
        socket.on('close', () => sockets.delete(socket));
        socket.on('error', () => {});
    });
    await new Promise(resolve => srv.listen(0, '127.0.0.1', resolve));
    cleanups.push(() => new Promise(resolve => {
        for (const s of sockets) s.destroy();
        srv.close(resolve);
    }));
    return `http://127.0.0.1:${srv.address().port}/v1/chat/completions`;
}

async function startServer(port, llmUrl) {
    const child = spawn(process.execPath, [serverPath], {
        cwd: tmpDir,
        env: {
            ...process.env,
            PORT: String(port),
            SOC_DB_PATH: dbPath,
            JWT_SECRET: 'restart-test-secret',
            ADMIN_INITIAL_PASSWORD: ADMIN_PASSWORD,
            LLM_API_URL: llmUrl,
            OPENSEARCH_URL: 'http://127.0.0.1:9',
            WAZUH_SERVER_API_URL: 'http://127.0.0.1:9',
            WAZUH_USER: 'test',
            WAZUH_PASSWORD: 'test'
        }
    });
    let output = '';
    child.stdout.on('data', c => { output += c; });
    child.stderr.on('data', c => { output += c; });
    cleanups.push(() => { child.kill('SIGKILL'); });

    await waitFor(() => output.includes('running on port'), 15000, () => `server did not start:\n${output}`);
    const instanceId = output.match(/\[Server\] Instance ID: ([0-9a-f-]{36})/)?.[1];
    assert.ok(instanceId, `instance ID not logged:\n${output}`);
    return { child, instanceId, port, output: () => output };
}

async function waitFor(predicate, timeoutMs, message) {
    const deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline) {
        if (await predicate()) return;
        await new Promise(resolve => setTimeout(resolve, 50));
    }
    throw new Error(typeof message === 'function' ? message() : message);
}

/** Logs in and sends a chat question whose planner call will hang. Does not wait for the response. */
async function startHangingRun(port, question) {
    const login = await fetch(`http://127.0.0.1:${port}/api/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: 'admin', password: ADMIN_PASSWORD })
    });
    const { token } = await login.json();
    assert.ok(token, 'login failed');

    const controller = new AbortController();
    fetch(`http://127.0.0.1:${port}/api/chat`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
        body: JSON.stringify({ text: question, history: [] }),
        signal: controller.signal
    }).catch(() => {});
    cleanups.push(() => controller.abort());

    let row;
    await waitFor(() => {
        const reader = new Database(dbPath, { readonly: true });
        try {
            row = reader.prepare('SELECT * FROM runs WHERE question = ?').get(question);
        } finally {
            reader.close();
        }
        return Boolean(row);
    }, 10000, `no run row for "${question}"`);
    return row;
}

function readRun(question) {
    const reader = new Database(dbPath, { readonly: true });
    try {
        return reader.prepare('SELECT * FROM runs WHERE question = ?').get(question);
    } finally {
        reader.close();
    }
}

test('a genuine hang stays running; a restart marks the previous instance\'s running runs interrupted', async () => {
    const llmUrl = await startHangingModelServer();

    // Instance A: a run hangs on the model call.
    const serverA = await startServer(await freePort(), llmUrl);
    const hungA = await startHangingRun(serverA.port, 'Show brute force attacks (instance A)');
    assert.equal(hungA.status, 'running');
    assert.equal(hungA.instance_id, serverA.instanceId);

    // A genuine hang: still running after time passes while its instance is alive.
    await new Promise(resolve => setTimeout(resolve, 750));
    assert.equal(readRun('Show brute force attacks (instance A)').status, 'running');

    // Restart: instance A dies without finishing the run (SIGKILL: no cleanup code runs).
    serverA.child.kill('SIGKILL');
    await new Promise(resolve => serverA.child.once('exit', resolve));

    // Instance B starts on the same database.
    const serverB = await startServer(await freePort(), llmUrl);
    assert.notEqual(serverB.instanceId, serverA.instanceId);
    assert.match(serverB.output(), /Marked 1 run\(s\) from a previous server instance as interrupted/);

    const interrupted = readRun('Show brute force attacks (instance A)');
    assert.equal(interrupted.status, 'interrupted');
    assert.equal(interrupted.instance_id, serverA.instanceId, 'the original instance is kept on the row');
    assert.equal(interrupted.completed_at, null, 'an interrupted run never completed');
    const [serverError] = JSON.parse(interrupted.errors_json);
    assert.equal(serverError.stage, 'server');
    assert.ok(serverError.message.includes(serverA.instanceId) && serverError.message.includes(serverB.instanceId), serverError.message);

    // Instance B's own hang is still reported as running, alongside A's interrupted run.
    const hungB = await startHangingRun(serverB.port, 'Show brute force attacks (instance B)');
    await new Promise(resolve => setTimeout(resolve, 750));
    const stillHung = readRun('Show brute force attacks (instance B)');
    assert.equal(stillHung.status, 'running');
    assert.equal(stillHung.instance_id, serverB.instanceId);
    assert.equal(hungB.instance_id, serverB.instanceId);
    assert.equal(readRun('Show brute force attacks (instance A)').status, 'interrupted');
});

test('migrates a runs table created before instance_id existed, keeping rows', async () => {
    const legacyPath = path.join(tmpDir, 'legacy-runs.db');
    const legacy = new Database(legacyPath);
    legacy.exec(`
        CREATE TABLE runs (
            request_id TEXT PRIMARY KEY, user_id TEXT NOT NULL,
            status TEXT NOT NULL CHECK(status IN ('running', 'completed', 'failed')),
            question TEXT NOT NULL, planner_json TEXT, tools_json TEXT, report_text TEXT, timings_json TEXT,
            errors_json TEXT, model_generated INTEGER, generation_json TEXT, started_at TEXT NOT NULL, completed_at TEXT
        );
        CREATE INDEX idx_runs_status ON runs(status);
        INSERT INTO runs (request_id, user_id, status, question, started_at, completed_at, report_text)
            VALUES ('r_done', 'u', 'completed', 'old question', '2026-09-16T00:00:00Z', '2026-09-16T00:00:01Z', 'old report');
        INSERT INTO runs (request_id, user_id, status, question, started_at)
            VALUES ('r_stuck', 'u', 'running', 'stuck question', '2026-09-16T00:00:00Z');
    `);
    legacy.close();

    const script = `
        const { initDatabase } = await import(${JSON.stringify(new URL('../src/config/db.js', import.meta.url).href)});
        const { RunModel } = await import(${JSON.stringify(new URL('../src/models/Run.js', import.meta.url).href)});
        initDatabase();
        initDatabase();
        console.log('INTERRUPTED=' + JSON.stringify(RunModel.markInterruptedRuns('new-instance')));
    `;
    const child = spawn(process.execPath, ['--input-type=module', '-e', script], { cwd: tmpDir, env: { ...process.env, SOC_DB_PATH: legacyPath } });
    let output = '';
    child.stdout.on('data', c => { output += c; });
    child.stderr.on('data', c => { output += c; });
    const code = await new Promise(resolve => child.on('exit', resolve));
    assert.equal(code, 0, output);
    assert.match(output, /INTERRUPTED=\["r_stuck"\]/);

    const migrated = new Database(legacyPath, { readonly: true });
    try {
        assert.ok(migrated.prepare('PRAGMA table_info(runs)').all().some(c => c.name === 'instance_id'));
        const rows = migrated.prepare('SELECT request_id, status, instance_id, report_text FROM runs ORDER BY request_id').all();
        assert.deepEqual(rows, [
            { request_id: 'r_done', status: 'completed', instance_id: null, report_text: 'old report' },
            { request_id: 'r_stuck', status: 'interrupted', instance_id: null, report_text: null }
        ]);
    } finally {
        migrated.close();
    }
});
