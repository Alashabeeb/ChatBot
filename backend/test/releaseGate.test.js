import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'child_process';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { fileURLToPath } from 'url';

const repo = path.resolve(fileURLToPath(new URL('..', import.meta.url)), '..');
const gate = path.join(repo, 'evals', 'gate.py');
const python = ['python3', 'python'].find(cmd => spawnSync(cmd, ['--version']).status === 0);
const skip = !python && 'python3 not installed';
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'gate-test-'));

// A pipeline-evaluation result as evals/check.py --json writes it.
const result = (file, { score = 100, pass = true, fabrications = 0, failed = [] } = {}) => ({ file, score, pass, fabrications, failed_checks: failed, synthetic: true });
const GOOD = [
    result('SYNTHETIC-pipeline-faithful--a.json'), result('SYNTHETIC-pipeline-adversarial--a.json'),
    result('SYNTHETIC-pipeline-legacy--a.json', { score: 70, pass: false, fabrications: 3, failed: ['H5_ips_grounded'] })
];
const BASELINE = { cases: { 'pipeline/faithful/a': 100, 'pipeline/adversarial/a': 100 }, means: { faithful: 100, adversarial: 100 } };

function runGate(results, baseline = BASELINE, extra = []) {
    const resultsFile = path.join(tmp, `results-${Math.random().toString(36).slice(2)}.json`);
    const baselineFile = path.join(tmp, `baseline-${Math.random().toString(36).slice(2)}.json`);
    fs.writeFileSync(resultsFile, JSON.stringify({ results }));
    fs.writeFileSync(baselineFile, JSON.stringify(baseline));
    return spawnSync(python, [gate, '--pipeline-results', resultsFile, '--baseline', baselineFile, '--skip-self-test', ...extra], { encoding: 'utf8' });
}

test('the gate passes when nothing regressed', { skip }, () => {
    const run = runGate(GOOD);
    assert.equal(run.status, 0, run.stdout + run.stderr);
    assert.match(run.stdout, /RELEASE GATE: PASS/);
});

test('any fabricated claim reaching an answer fails the gate', { skip }, () => {
    const run = runGate([result('SYNTHETIC-pipeline-faithful--a.json'), result('SYNTHETIC-pipeline-adversarial--a.json', { score: 100, pass: false, fabrications: 1, failed: ['H5_ips_grounded'] }), GOOD[2]]);
    assert.equal(run.status, 1);
    assert.match(run.stdout, /adversarial\/a: 1 fabrication/);
    assert.match(run.stdout, /RELEASE GATE: FAIL/);
});

test('a hard-check failure fails the gate even without a fabrication', { skip }, () => {
    const run = runGate([result('SYNTHETIC-pipeline-faithful--a.json', { pass: false, failed: ['H8_time_window'] }), GOOD[1], GOOD[2]]);
    assert.equal(run.status, 1);
    assert.match(run.stdout, /H8_time_window/);
});

test('a score below the baseline fails the gate, per case and on average', { skip }, () => {
    const run = runGate([result('SYNTHETIC-pipeline-faithful--a.json', { score: 97.5 }), GOOD[1], GOOD[2]]);
    assert.equal(run.status, 1);
    assert.match(run.stdout, /faithful\/a: score 97\.5 < baseline 100/);
    assert.match(run.stdout, /faithful: mean 97\.5 < baseline 100/);
});

test('a case in the baseline that is missing from the results fails the gate', { skip }, () => {
    const run = runGate([GOOD[0], GOOD[2]]);
    assert.equal(run.status, 1);
    assert.match(run.stdout, /adversarial\/a: missing/);
});

test('the gate fails if the evaluation can no longer see fabrications (legacy pass-through shows none)', { skip }, () => {
    const run = runGate([GOOD[0], GOOD[1], result('SYNTHETIC-pipeline-legacy--a.json', { score: 100 })]);
    assert.equal(run.status, 1);
    assert.match(run.stdout, /legacy pass-through shows no fabrications/);
});

test('--update writes a new baseline from the results; scores only go up through review', { skip }, () => {
    const baselineFile = path.join(tmp, 'update-baseline.json');
    const resultsFile = path.join(tmp, 'update-results.json');
    fs.writeFileSync(resultsFile, JSON.stringify({ results: GOOD }));
    const run = spawnSync(python, [gate, '--pipeline-results', resultsFile, '--baseline', baselineFile, '--skip-self-test', '--update'], { encoding: 'utf8' });
    assert.equal(run.status, 0, run.stdout + run.stderr);
    const written = JSON.parse(fs.readFileSync(baselineFile, 'utf8'));
    assert.deepEqual(written.cases, { 'pipeline/adversarial/a': 100, 'pipeline/faithful/a': 100 });
    assert.deepEqual(written.means, { adversarial: 100, faithful: 100 });
    // --update refuses to record a baseline that itself fails the absolute rules.
    fs.writeFileSync(resultsFile, JSON.stringify({ results: [GOOD[0], result('SYNTHETIC-pipeline-adversarial--a.json', { pass: false, fabrications: 2, failed: ['H2_rule_ids_grounded'] }), GOOD[2]] }));
    const refused = spawnSync(python, [gate, '--pipeline-results', resultsFile, '--baseline', baselineFile, '--skip-self-test', '--update'], { encoding: 'utf8' });
    assert.equal(refused.status, 1);
});

test('a checker self-test failure fails the gate', { skip }, () => {
    const dir = path.join(tmp, 'synthetic-broken');
    fs.cpSync(path.join(repo, 'evals', 'synthetic'), dir, { recursive: true });
    const file = path.join(dir, 'SYNTHETIC-top-alerts-week--fabricated-ip.json');
    const broken = JSON.parse(fs.readFileSync(file, 'utf8'));
    broken.expect.hard_fail = [];   // now claims the fabricated IP should pass
    fs.writeFileSync(file, JSON.stringify(broken));
    const resultsFile = path.join(tmp, 'selftest-results.json');
    const baselineFile = path.join(tmp, 'selftest-baseline.json');
    fs.writeFileSync(resultsFile, JSON.stringify({ results: GOOD }));
    fs.writeFileSync(baselineFile, JSON.stringify(BASELINE));
    const run = spawnSync(python, [gate, '--pipeline-results', resultsFile, '--baseline', baselineFile, '--synthetic', dir], { encoding: 'utf8' });
    assert.equal(run.status, 1, run.stdout);
    assert.match(run.stdout, /checker self-test/);
});

test('the committed gate passes on the current code (full run: checker self-test and the pipeline evaluation)', { skip }, () => {
    const run = spawnSync(python, [gate], { encoding: 'utf8', cwd: repo, env: { PATH: process.env.PATH } });
    assert.equal(run.status, 0, run.stdout + run.stderr);
    assert.match(run.stdout, /RELEASE GATE: PASS/);
});
