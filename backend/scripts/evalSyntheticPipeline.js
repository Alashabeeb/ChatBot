#!/usr/bin/env node
/**
 * Runs the invented eval scenarios (scripts/lib/evalScenarios.js) through the real pipeline with a
 * stub report model, then scores the reports with evals/check.py. No model, OpenSearch or Wazuh is
 * contacted: every HTTP call is stubbed in-process. Everything written is marked SYNTHETIC.
 *
 *   node scripts/evalSyntheticPipeline.js [--out <dir>] [--json <file>]
 *
 * The stub model reads the evidence it is given and answers in three ways:
 *   faithful     claims built only from that evidence, each with its citations
 *   adversarial  the same claims plus fabrications (invented IPs, rules, techniques, hosts, counts,
 *                scores, a claimed block) of the kind a real model produces
 *   legacy       not a pipeline run: the adversarial claims joined as free text, which is what the code
 *                before Phase 4 showed the analyst verbatim. Scored for comparison only.
 *
 * Exit code 1 if any faithful or adversarial report fails a hard check or contains a fabrication.
 */
import fs from 'fs';
import os from 'os';
import path from 'path';
import { spawnSync } from 'child_process';

process.env.SOC_DB_PATH = ':memory:';
process.env.JWT_SECRET = 'synthetic-eval-pipeline-only-0123456789abcdefghij';
process.env.LLM_API_URL = 'http://llm.invalid/v1/chat/completions';
process.env.OPENSEARCH_URL = 'http://opensearch.invalid';
process.env.WAZUH_SERVER_API_URL = 'http://wazuh.invalid';
process.env.WAZUH_USER = 'synthetic';
process.env.WAZUH_PASSWORD = 'synthetic';
delete process.env.FIXTURES;

const arg = name => {
    const i = process.argv.indexOf(name);
    return i > -1 && process.argv[i + 1] ? path.resolve(process.argv[i + 1]) : null;
};
const OUT_DIR = arg('--out') ?? fs.mkdtempSync(path.join(os.tmpdir(), 'synthetic-pipeline-'));
const JSON_OUT = arg('--json');

const { default: axios } = await import('axios');
const { BACKEND_DIR, fixtureFileName } = await import('../src/recording/common.js');
const { SCENARIOS, stubHttp, normalize } = await import('./lib/evalScenarios.js');

const cite = (kind, ref, count) => (count === undefined ? { kind, ref } : { kind, ref, count });
const exact = c => (typeof c === 'number' ? { n: c, words: String(c) } : { n: c.atLeast, words: `at least ${c.atLeast}` });

/** What a careful model would say about this evidence, every statement cited. */
function faithfulClaims(evidence) {
    const claims = { answer: [], findings: [], assessment: [], next_steps: [] };
    for (const s of evidence.searches.filter(x => !x.failed && x.totalMatches > 0)) {
        claims.answer.push({ text: `${s.source} had ${s.totalMatches} matches.`, cite: [cite('total', s.key, s.totalMatches)] });
    }
    for (const r of evidence.counts.byRule.slice(0, 3)) {
        const { n, words } = exact(r.count);
        claims.findings.push({ text: `Rule ${r.ruleId} (${r.description}) fired ${words} times.`, cite: [cite('rule', r.ruleId, n)] });
    }
    const agent = evidence.counts.byAgent[0];
    if (agent) {
        const { n, words } = exact(agent.count);
        claims.findings.push({ text: `Most records were on ${agent.agent} (${words}).`, cite: [cite('agent', agent.agent, n)] });
    }
    const ip = evidence.counts.bySourceIp[0];
    if (ip) {
        const { n, words } = exact(ip.count);
        claims.findings.push({ text: `The most frequent source IP was ${ip.ip} (${words}).`, cite: [cite('ip', ip.ip, n)] });
    }
    if (evidence.mitreTechniques.length) {
        claims.assessment.push({ text: `The rules involved map to ${evidence.mitreTechniques.join(', ')}.`, cite: evidence.mitreTechniques.map(t => cite('mitre', t)) });
    }
    if (ip && agent) claims.next_steps.push({ text: `Find out who owns ${ip.ip} and why it targets ${agent.agent}.`, cite: [cite('ip', ip.ip), cite('agent', agent.agent)] });
    else if (agent) claims.next_steps.push({ text: `Review the activity on ${agent.agent}.`, cite: [cite('agent', agent.agent)] });
    return claims;
}

const FABRICATIONS = [
    { text: 'Traffic also came from 91.92.93.94, a known botnet node.', cite: [cite('rule', '5710')] },
    { text: 'Rule 92657 (Mimikatz credential dumping) fired 4 times.', cite: [cite('rule', '92657', 4)] },
    { text: 'This is credential dumping (T1003.001).', cite: [cite('mitre', 'T1003.001')] },
    { text: 'DC07 shows the same pattern.', cite: [cite('agent', 'web-01')] },
    { text: 'Confidence: 92% that this is an active intrusion.', cite: [cite('rule', '5710')] },
    { text: 'The source IP has been blocked at the firewall.', cite: [cite('rule', '5710')] },
    { text: 'There were 4,812 related events overall.', cite: [cite('rule', '5710')] }
];

function adversarialClaims(evidence) {
    const claims = faithfulClaims(evidence);
    const top = evidence.counts.byRule[0];
    if (top) {
        const { n } = exact(top.count);
        claims.findings.push({ text: `Rule ${top.ruleId} fired ${n + 50} times.`, cite: [cite('rule', top.ruleId, n + 50)] });
    }
    claims.findings.push(...FABRICATIONS);
    return claims;
}

const evidenceFrom = body => {
    const prompt = body.messages.at(-1).content;
    return JSON.parse(prompt.slice(prompt.indexOf('{')));
};

const { captureFixtures } = await import('../src/recording/capture.js');
const { default: db } = await import('../src/config/db.js');
const quiet = { log: console.log, warn: console.warn, error: console.error };
const scratch = fs.mkdtempSync(path.join(os.tmpdir(), 'synthetic-pipeline-run-'));
fs.mkdirSync(OUT_DIR, { recursive: true });

function mark(fixture, mode, name) {
    fixture.synthetic = true;
    fixture.SYNTHETIC = 'Invented telemetry run through the pipeline with a stub model. Not real data; never replay or score as a baseline.';
    fixture.variant = `pipeline/${mode}/${name}`;
    return fixture;
}

try {
    for (const mode of ['faithful', 'adversarial']) {
        for (const [name, scenario] of Object.entries(SCENARIOS)) {
            let lastClaims = null;
            stubHttp(axios, scenario, {
                report: body => {
                    lastClaims = (mode === 'faithful' ? faithfulClaims : adversarialClaims)(evidenceFrom(body));
                    return JSON.stringify(lastClaims);
                }
            });
            console.log = console.warn = console.error = () => {};
            await captureFixtures({ questions: [scenario.question], outDir: scratch, timeoutMs: 10000, log: () => {} });
            await new Promise(resolve => setTimeout(resolve, 50));
            Object.assign(console, quiet);
            const fixture = normalize(JSON.parse(fs.readFileSync(path.join(scratch, fixtureFileName(scenario.question)), 'utf8')));
            fs.writeFileSync(path.join(OUT_DIR, `SYNTHETIC-pipeline-${mode}--${name}.json`), JSON.stringify(mark(fixture, mode, name), null, 2) + '\n');

            if (mode === 'adversarial') {
                // What the pre-Phase-4 code would have shown: the model's text, verbatim.
                const legacy = structuredClone(fixture);
                legacy.result.report = lastClaims
                    ? Object.values(lastClaims).flat().map(c => c.text).join('\n')
                    : fixture.result.report;
                fs.writeFileSync(path.join(OUT_DIR, `SYNTHETIC-pipeline-legacy--${name}.json`), JSON.stringify(mark(legacy, 'legacy', name), null, 2) + '\n');
            }
        }
    }
} finally {
    Object.assign(console, quiet);
    db.close();
    fs.rmSync(scratch, { recursive: true, force: true });
}

const checker = path.resolve(BACKEND_DIR, '..', 'evals', 'check.py');
const python = ['python3', 'python'].find(cmd => spawnSync(cmd, ['--version']).status === 0);
if (!python) {
    console.error('python3 is needed to score the reports.');
    process.exit(1);
}
const jsonPath = JSON_OUT ?? path.join(OUT_DIR, 'scores.json');
const scored = spawnSync(python, [checker, OUT_DIR, '--json', jsonPath], { encoding: 'utf8' });
process.stdout.write(scored.stdout);
process.stderr.write(scored.stderr);

const results = JSON.parse(fs.readFileSync(jsonPath, 'utf8')).results;
const summary = {};
for (const r of results) {
    const mode = r.file.match(/^SYNTHETIC-pipeline-(\w+)--/)[1];
    summary[mode] ??= { cases: 0, score: 0, failing: 0, fabrications: 0 };
    summary[mode].cases++;
    summary[mode].score += r.score;
    summary[mode].failing += r.pass ? 0 : 1;
    summary[mode].fabrications += r.fabrications;
}
console.log('\nmode         cases  mean score  failing a hard check  fabrications');
for (const [mode, s] of Object.entries(summary)) {
    console.log(`${mode.padEnd(12)} ${String(s.cases).padStart(5)}  ${(s.score / s.cases).toFixed(1).padStart(10)}  ${String(s.failing).padStart(20)}  ${String(s.fabrications).padStart(12)}`);
}
console.log(`\nCases and scores: ${OUT_DIR}`);
const bad = ['faithful', 'adversarial'].some(m => summary[m] && (summary[m].failing > 0 || summary[m].fabrications > 0));
process.exit(bad ? 1 : 0);
