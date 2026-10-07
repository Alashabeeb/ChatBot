import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'child_process';
import crypto from 'crypto';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { fileURLToPath } from 'url';
import Database from 'better-sqlite3';

const backendDir = fileURLToPath(new URL('..', import.meta.url));
const script = path.join(backendDir, 'scripts', 'auditFabricatedActions.js');
const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'audit-fabricated-'));
after(() => fs.rmSync(tmpDir, { recursive: true, force: true }));

// Schema as it exists on main (no request_id column).
function seed(dbPath) {
    const db = new Database(dbPath);
    db.exec(`
        CREATE TABLE users (id TEXT PRIMARY KEY, username TEXT NOT NULL, password_hash TEXT NOT NULL, role TEXT NOT NULL, created_at TEXT NOT NULL);
        CREATE TABLE messages (id TEXT PRIMARY KEY, session_id TEXT NOT NULL, user_id TEXT NOT NULL, role TEXT NOT NULL, type TEXT NOT NULL,
            text TEXT, summary TEXT, raw_logs TEXT, total_hits INTEGER, is_new INTEGER DEFAULT 0, created_at TEXT NOT NULL);
        INSERT INTO users VALUES ('u1', 'analyst1', 'x', 'user', '2026-09-01T00:00:00Z'), ('u2', 'admin', 'x', 'admin', '2026-09-01T00:00:00Z');
    `);
    const add = db.prepare(`INSERT INTO messages (id, session_id, user_id, role, type, text, summary, created_at) VALUES (?, 's1', ?, 'assistant', 'agent_response', '', ?, ?)`);
    add.run('m_block', 'u1', '**Evidence**: blockIpAction returned {"status":"success","action":"IP_BLOCKED","target_ip":"203.0.113.9"}', '2026-09-23T10:00:00Z');
    add.run('m_blocklist', 'u2', 'Successfully added 198.51.100.4 to the firewall blocklist.', '2026-09-24T11:00:00Z');
    add.run('m_miner', 'u1', 'Endpoint 001 is running unknown_miner at 98.5% CPU as root.', '2026-09-25T12:00:00Z');
    add.run('m_ti', 'u2', 'lookupThreatIntel: Mock threat intelligence response for 203.0.113.9. Real integration pending.', '2026-09-10T09:00:00Z');
    add.run('m_clean', 'u1', '**Answer**: 12 authentication failures from 203.0.113.9 in the last 24 hours.', '2026-09-26T13:00:00Z');
    db.close();
}

const hash = file => crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex');
const run = (...args) => spawnSync(process.execPath, [script, ...args], { encoding: 'utf8' });

test('lists every fabricated-action match with date, user and snippet; skips clean messages', () => {
    const dbPath = path.join(tmpDir, 'audit.db');
    seed(dbPath);
    const before = hash(dbPath);

    const result = run('--db', dbPath);
    assert.equal(result.status, 2, result.stdout + result.stderr);

    for (const [id, date, user, signature] of [
        ['m_block', '2026-09-23T10:00:00Z', 'analyst1', 'IP_BLOCKED'],
        ['m_blocklist', '2026-09-24T11:00:00Z', 'admin', 'blocklist'],
        ['m_miner', '2026-09-25T12:00:00Z', 'analyst1', 'unknown_miner'],
        ['m_ti', '2026-09-10T09:00:00Z', 'admin', 'threat-intel mock']
    ]) {
        const line = result.stdout.split('\n').find(l => l.includes(id));
        assert.ok(line, `${id} missing from output:\n${result.stdout}`);
        assert.ok(line.includes(date) && line.includes(user), `${id} line lacks date or user: ${line}`);
        assert.ok(result.stdout.includes(signature), `signature ${signature} not reported`);
    }
    assert.ok(!result.stdout.includes('m_clean'), 'clean message must not be listed');
    assert.match(result.stdout, /….*IP_BLOCKED.*…/, 'snippet shows the matched text in context');
    assert.match(result.stdout, /4 message\(s\) matched/);

    assert.equal(hash(dbPath), before, 'database must be unchanged');
    assert.ok(!fs.existsSync(`${dbPath}-wal`), 'no WAL file created');
});

test('exits 0 on a clean database and 1 (without creating a file) when the database is missing', () => {
    const clean = path.join(tmpDir, 'clean.db');
    const db = new Database(clean);
    db.exec(`CREATE TABLE users (id TEXT, username TEXT); CREATE TABLE messages (id TEXT, user_id TEXT, text TEXT, summary TEXT, raw_logs TEXT, created_at TEXT);
             INSERT INTO messages VALUES ('m1', 'u1', 'hello', 'normal report', NULL, '2026-09-26T00:00:00Z');`);
    db.close();
    const ok = run('--db', clean);
    assert.equal(ok.status, 0, ok.stdout + ok.stderr);
    assert.match(ok.stdout, /No fabricated-action text found/);

    const missingPath = path.join(tmpDir, 'missing.db');
    const missing = run('--db', missingPath);
    assert.equal(missing.status, 1);
    assert.ok(!fs.existsSync(missingPath), 'must not create a database');
});
