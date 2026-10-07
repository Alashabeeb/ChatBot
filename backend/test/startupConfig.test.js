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

test('server starts when JWT_SECRET is set (control)', async () => {
    const dbName = 'started.db';
    const child = spawn(process.execPath, [serverPath], { cwd: tmpDir, env: serverEnv(dbName, { JWT_SECRET: 'test-secret-for-startup-check' }) });
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
        assert.doesNotMatch(output, /FATAL/);
        assert.ok(fs.existsSync(path.join(tmpDir, dbName)));
    } finally {
        child.removeAllListeners('exit');
        child.kill();
    }
});
