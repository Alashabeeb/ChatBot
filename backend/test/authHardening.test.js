import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'child_process';
import fs from 'fs';
import os from 'os';
import path from 'path';
import express from 'express';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import Database from 'better-sqlite3';
import { setTestEnv } from './helpers.js';

setTestEnv();
const { default: db, initDatabase } = await import('../src/config/db.js');
const { default: authRoutes } = await import('../src/routes/auth.routes.js');
const { default: sessionRoutes } = await import('../src/routes/session.routes.js');
const { default: chatRoutes } = await import('../src/routes/chat.routes.js');
const { authenticateToken } = await import('../src/middleware/auth.middleware.js');
initDatabase();

const app = express();
app.use(express.json());
app.use('/api/auth', authRoutes);
app.use('/api/sessions', sessionRoutes);
app.use('/api/chat', authenticateToken, chatRoutes);
const server = await new Promise(r => { const s = app.listen(0, '127.0.0.1', () => r(s)); });
after(() => new Promise(r => server.close(r)));
const BASE = `http://127.0.0.1:${server.address().port}`;

const sign = claims => jwt.sign(claims, process.env.JWT_SECRET, { expiresIn: '1h' });
async function call(method, url, { token, body } = {}) {
    const res = await fetch(BASE + url, {
        method,
        headers: { 'Content-Type': 'application/json', ...(token ? { Authorization: `Bearer ${token}` } : {}) },
        body: body ? JSON.stringify(body) : undefined
    });
    let json = null;
    try { json = await res.json(); } catch { /* no body */ }
    return { status: res.status, body: json };
}
function addUser(id, username, role, password = 'a-long-test-password-1', mustChange = 0) {
    db.prepare('INSERT INTO users (id, username, password_hash, role, created_at, must_change_password) VALUES (?, ?, ?, ?, ?, ?)')
        .run(id, username, bcrypt.hashSync(password, 4), role, new Date().toISOString(), mustChange);
}

// ------------------------------------------------------------------ F-24

test('F-24: a token for a deleted user is rejected', async () => {
    addUser('u_gone', 'gone_user', 'user');
    const token = sign({ id: 'u_gone', username: 'gone_user', role: 'user' });
    assert.equal((await call('GET', '/api/auth/me', { token })).status, 200);
    db.prepare("DELETE FROM users WHERE id = 'u_gone'").run();
    for (const url of ['/api/auth/me', '/api/sessions']) {
        const r = await call('GET', url, { token });
        assert.equal(r.status, 401, url);
    }
});

test('F-24: the role comes from the database, not the token', async () => {
    addUser('u_plain', 'plain_user', 'user');
    const forged = sign({ id: 'u_plain', username: 'plain_user', role: 'admin' });   // claims admin
    assert.equal((await call('GET', '/api/auth/users', { token: forged })).status, 403, 'a token cannot grant admin');

    const stale = sign({ id: 'u_plain', username: 'plain_user', role: 'user' });
    db.prepare("UPDATE users SET role = 'admin' WHERE id = 'u_plain'").run();
    assert.equal((await call('GET', '/api/auth/users', { token: stale })).status, 200, 'a promotion takes effect at once');
    db.prepare("UPDATE users SET role = 'user' WHERE id = 'u_plain'").run();
    assert.equal((await call('GET', '/api/auth/users', { token: stale })).status, 403, 'so does a demotion');
});

// ------------------------------------------------------------------ F-08b

test('F-08b: the seeded default admin must change its password before using anything else', async () => {
    const login = await call('POST', '/api/auth/login', { body: { username: 'admin', password: 'Password12$' } });
    assert.equal(login.status, 200);
    assert.equal(login.body.user.mustChangePassword, true);
    const token = login.body.token;

    for (const [method, url] of [['GET', '/api/sessions'], ['POST', '/api/chat'], ['GET', '/api/auth/users']]) {
        const r = await call(method, url, { token, body: method === 'POST' ? { text: 'hi' } : undefined });
        assert.equal(r.status, 403, `${method} ${url}`);
        assert.equal(r.body.code, 'PASSWORD_CHANGE_REQUIRED', `${method} ${url}`);
    }
    const me = await call('GET', '/api/auth/me', { token });
    assert.equal(me.status, 200);
    assert.equal(me.body.user.mustChangePassword, true);

    const wrongCurrent = await call('POST', '/api/auth/change-password', { token, body: { currentPassword: 'nope', newPassword: 'a-much-better-passphrase-42' } });
    assert.equal(wrongCurrent.status, 400);
    for (const weak of ['short1', 'Password12$', 'admin-admin-admin', 'aaaaaaaaaaaaaaaa']) {
        const r = await call('POST', '/api/auth/change-password', { token, body: { currentPassword: 'Password12$', newPassword: weak } });
        assert.equal(r.status, 400, `"${weak}" must be refused`);
    }

    const ok = await call('POST', '/api/auth/change-password', { token, body: { currentPassword: 'Password12$', newPassword: 'a-much-better-passphrase-42' } });
    assert.equal(ok.status, 200, JSON.stringify(ok.body));
    assert.equal((await call('GET', '/api/sessions', { token })).status, 200, 'unlocked once changed');

    const relogin = await call('POST', '/api/auth/login', { body: { username: 'admin', password: 'a-much-better-passphrase-42' } });
    assert.equal(relogin.body.user.mustChangePassword, false);
    assert.equal((await call('POST', '/api/auth/login', { body: { username: 'admin', password: 'Password12$' } })).status, 401, 'the default no longer works');
});

test('F-08b: an existing database flags the admin only if it still has the published default password', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'admin-migration-'));
    try {
        for (const [name, password, expected] of [['default.db', 'Password12$', 1], ['custom.db', 'their-own-strong-password', 0]]) {
            const file = path.join(dir, name);
            const legacy = new Database(file);
            legacy.exec(`CREATE TABLE users (id TEXT PRIMARY KEY, username TEXT UNIQUE NOT NULL COLLATE NOCASE, password_hash TEXT NOT NULL, role TEXT NOT NULL CHECK(role IN ('admin', 'user')), created_at TEXT NOT NULL)`);
            legacy.prepare("INSERT INTO users VALUES ('user_admin_root', 'admin', ?, 'admin', '2026-01-01T00:00:00Z')").run(bcrypt.hashSync(password, 4));
            legacy.close();
            const script = `const { initDatabase } = await import(${JSON.stringify(new URL('../src/config/db.js', import.meta.url).href)}); initDatabase(); initDatabase();`;
            const r = spawnSync(process.execPath, ['--input-type=module', '-e', script], { cwd: dir, env: { ...process.env, SOC_DB_PATH: file }, encoding: 'utf8' });
            assert.equal(r.status, 0, r.stderr);
            const check = new Database(file, { readonly: true });
            assert.equal(check.prepare("SELECT must_change_password FROM users WHERE id = 'user_admin_root'").get().must_change_password, expected, name);
            check.close();
        }
    } finally {
        fs.rmSync(dir, { recursive: true, force: true });
    }
});
