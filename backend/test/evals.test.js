import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'child_process';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { fileURLToPath } from 'url';

const backendDir = fileURLToPath(new URL('..', import.meta.url));
const evalsDir = path.resolve(backendDir, '..', 'evals');
const syntheticDir = path.join(evalsDir, 'synthetic');
const committed = () => fs.readdirSync(syntheticDir).filter(n => n.endsWith('.json')).sort();
const python = ['python3', 'python'].find(cmd => spawnSync(cmd, ['--version']).status === 0);

test('every synthetic case is marked SYNTHETIC and lives outside fixtures/', () => {
    const names = committed();
    assert.ok(names.length >= 20, `expected the synthetic set, found ${names.length}`);
    for (const name of names) {
        const c = JSON.parse(fs.readFileSync(path.join(syntheticDir, name), 'utf8'));
        assert.ok(name.startsWith('SYNTHETIC-'), name);
        assert.equal(c.synthetic, true, name);
        assert.match(c.SYNTHETIC, /Not real data/, name);
        assert.ok(c.expect && Array.isArray(c.expect.hard_fail), `${name} needs an expect block`);
    }
});

test('the committed synthetic cases are exactly what the current capture code produces', () => {
    const out = fs.mkdtempSync(path.join(os.tmpdir(), 'synthetic-regen-'));
    try {
        const run = spawnSync(process.execPath, [path.join(backendDir, 'scripts', 'makeSyntheticEvalCases.js'), '--out', out], { encoding: 'utf8', env: { PATH: process.env.PATH } });
        assert.equal(run.status, 0, run.stdout + run.stderr);
        const fresh = fs.readdirSync(out).filter(n => n.endsWith('.json')).sort();
        assert.deepEqual(fresh, committed(), 'regenerate with: node scripts/makeSyntheticEvalCases.js');
        for (const name of fresh) {
            assert.equal(fs.readFileSync(path.join(out, name), 'utf8'), fs.readFileSync(path.join(syntheticDir, name), 'utf8'),
                `${name} is stale; regenerate with: node scripts/makeSyntheticEvalCases.js`);
        }
    } finally {
        fs.rmSync(out, { recursive: true, force: true });
    }
});

test('evals/check.py passes its self-test on the synthetic cases', { skip: !python && 'python3 not installed' }, () => {
    const run = spawnSync(python, [path.join(evalsDir, 'check.py'), syntheticDir, '--expect'], { encoding: 'utf8' });
    assert.equal(run.status, 0, run.stdout + run.stderr);
    assert.match(run.stdout, /Checker self-test: (\d+)\/\1 synthetic case\(s\) behaved as expected/);
});
