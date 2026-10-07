import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'child_process';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { fileURLToPath } from 'url';

const serverPath = fileURLToPath(new URL('../src/server.js', import.meta.url));
const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'startup-config-'));
after(() => fs.rmSync(tmpDir, { recursive: true, force: true }));

function serverEnv(dbName, overrides) {
    const env = {
        ...process.env,
        PORT: '0',
        SOC_DB_PATH: path.join(tmpDir, dbName),
        LLM_API_URL: 'http://llm.test',
        OPENSEARCH_URL: 'http://opensearch.test',
        WAZUH_SERVER_API_URL: 'http://wazuh.test',
        WAZUH_USER: 'test',
        WAZUH_PASSWORD: 'test',
        ...overrides
    };
    for (const [key, value] of Object.entries(env)) {
        if (value === undefined) delete env[key];
    }
    return env;
}

// cwd is an empty temp dir so dotenv cannot pick up a real backend/.env that sets JWT_SECRET.
function startServerSync(dbName, overrides) {
    return spawnSync(process.execPath, [serverPath], { cwd: tmpDir, env: serverEnv(dbName, overrides), encoding: 'utf8', timeout: 15000 });
}

for (const [label, value] of [['unset', undefined], ['empty', ''], ['whitespace', '   ']]) {
    test(`server refuses to start when JWT_SECRET is ${label}`, () => {
        const dbName = `refused-${label}.db`;
        const result = startServerSync(dbName, { JWT_SECRET: value });

        assert.equal(result.signal, null, `server did not exit on its own (killed by ${result.signal}); it may have started`);
        assert.equal(result.status, 1, result.stdout + result.stderr);
        assert.match(result.stderr, /FATAL CONFIG ERROR: JWT_SECRET is not set/);
        assert.match(result.stderr, /Refusing to start/);
        assert.doesNotMatch(result.stdout, /running on port/);
        assert.ok(!fs.existsSync(path.join(tmpDir, dbName)), 'exit must happen before the database is created');
    });
}

for (const [label, value] of [
    ['too short (31 characters)', 'x'.repeat(10) + '0123456789abcdefghijk'],
    ['a common word', 'secret'],
    ['the old fallback published in the source history', 'soc_chatbot_jwt_secret_key_2026_secure_random'],
    ['long but one repeated character', 'a'.repeat(64)]
]) {
    test(`F-23: server refuses to start when JWT_SECRET is weak: ${label}`, () => {
        const dbName = `weak-${label.replace(/\W+/g, '-')}.db`;
        const result = startServerSync(dbName, { JWT_SECRET: value });
        assert.equal(result.status, 1, result.stdout + result.stderr);
        assert.match(result.stderr, /FATAL CONFIG ERROR: JWT_SECRET/);
        assert.ok(!fs.existsSync(path.join(tmpDir, dbName)), 'exit must happen before the database is created');
    });
}

test('server starts when JWT_SECRET is set (control)', async () => {
    const dbName = 'started.db';
    const child = spawn(process.execPath, [serverPath], { cwd: tmpDir, env: serverEnv(dbName, { JWT_SECRET: 'test-secret-for-startup-check-0123456789abcdef' }) });
    let output = '';
    try {
        await new Promise((resolve, reject) => {
            const timer = setTimeout(() => reject(new Error(`server did not start:\n${output}`)), 15000);
            const onData = chunk => {
                output += chunk;
                if (output.includes('running on port')) {
                    clearTimeout(timer);
                    resolve();
                }
            };
            child.stdout.on('data', onData);
            child.stderr.on('data', onData);
            child.on('exit', code => {
                clearTimeout(timer);
                reject(new Error(`server exited with ${code}:\n${output}`));
            });
        });
        await new Promise(resolve => setTimeout(resolve, 300)); // collect the rest of the startup output
        assert.doesNotMatch(output, /FATAL/);
        // F-35: internal service addresses are not written to the startup log.
        assert.ok(!output.includes('http://opensearch.test'), `startup log leaks the OpenSearch URL:\n${output}`);
        assert.ok(fs.existsSync(path.join(tmpDir, dbName)));
    } finally {
        child.removeAllListeners('exit');
        child.kill();
    }
});

test('JWT_SECRET has no fallback value anywhere, not just at server startup', () => {
    // Without JWT_SECRET, the exported value must be undefined for every importer (scripts too),
    // and no hard-coded secret may exist in the source.
    const envModule = new URL('../src/config/env.js', import.meta.url).href;
    const env = { ...process.env };
    delete env.JWT_SECRET;
    const probe = spawnSync(process.execPath, ['--input-type=module', '-e', `const m = await import(${JSON.stringify(envModule)}); console.log(JSON.stringify({ type: typeof m.JWT_SECRET }));`],
        { cwd: tmpDir, env, encoding: 'utf8' });
    assert.equal(probe.status, 0, probe.stderr);
    assert.deepEqual(JSON.parse(probe.stdout.trim().split('\n').at(-1)), { type: 'undefined' });

    const srcDir = fileURLToPath(new URL('../src', import.meta.url));
    const offenders = [];
    const walk = dir => {
        for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
            const full = path.join(dir, entry.name);
            if (entry.isDirectory()) walk(full);
            else if (/soc_chatbot_jwt_secret/i.test(fs.readFileSync(full, 'utf8'))) offenders.push(path.relative(srcDir, full));
        }
    };
    walk(srcDir);
    assert.deepEqual(offenders, [], 'the old fallback secret must not appear in src/');
});
