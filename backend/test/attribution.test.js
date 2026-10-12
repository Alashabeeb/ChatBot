import { test } from 'node:test';
import assert from 'node:assert/strict';
import { setTestEnv, stubBackends, flushBackgroundWork, USER_ID, SAMPLE_LOG, SEARCH_PLAN } from './helpers.js';

setTestEnv();
const { initDatabase } = await import('../src/config/db.js');
const { runAgentWorkflow } = await import('../src/agent/runtime.js');

initDatabase();

// The report model returns claims with citations (Phase 4); this one is grounded in SAMPLE_LOG's search.
const MODEL_CLAIM = 'One sshd authentication failure on web-01.';
const MODEL_REPORT = JSON.stringify({ answer: [{ text: MODEL_CLAIM, cite: [{ kind: 'total', ref: 'searchSecurityLogs', count: 1 }, { kind: 'agent', ref: 'web-01' }] }] });

async function run(t, backends) {
    stubBackends(t, backends);
    const response = await runAgentWorkflow('Show brute force attacks', [], USER_ID);
    await flushBackgroundWork();
    return response;
}

test('model down: report says it is not model-generated and the run is flagged as a fallback', async (t) => {
    const response = await run(t, { llm: 'down', logs: [SAMPLE_LOG] });

    assert.equal(response.model_generated, false);
    assert.deepEqual(response.generation, { planner: 'fallback_rules', report: 'fallback_model_unavailable', model: 'foundation-sec-8b-instruct', models: { planner: 'foundation-sec-8b-instruct', report: 'foundation-sec-8b-instruct' } });
    assert.match(response.summary, /AI analysis is not included: the analysis model could not be reached/);
    assert.doesNotMatch(response.summary, /Successfully retrieved records/);
    assert.doesNotMatch(response.footer, /Analyzed by/);
    assert.match(response.footer, /System summary: AI analysis unavailable/);
    assert.match(response.footer, /Plan: rule-based fallback/);
});

test('model up: report is attributed to the model', async (t) => {
    const response = await run(t, { llm: { plan: SEARCH_PLAN, report: MODEL_REPORT }, logs: [SAMPLE_LOG] });

    assert.equal(response.model_generated, true);
    assert.deepEqual(response.generation, { planner: 'model', report: 'model', model: 'foundation-sec-8b-instruct', models: { planner: 'foundation-sec-8b-instruct', report: 'foundation-sec-8b-instruct' } });
    assert.match(response.summary, /^\*\*Searched:\*\* Wazuh alerts \(1 match\)/);
    assert.ok(response.summary.endsWith(MODEL_CLAIM));
    assert.match(response.footer, /^Analyzed by foundation-sec-8b-instruct \| Runtime: \d+ms$/);
});

test('planner falls back but model writes the report: both facts are recorded', async (t) => {
    const response = await run(t, { llm: { plan: null, report: MODEL_REPORT }, logs: [SAMPLE_LOG] });

    assert.equal(response.model_generated, true);
    assert.equal(response.generation.planner, 'fallback_rules');
    assert.equal(response.generation.report, 'model');
    assert.match(response.footer, /^Analyzed by foundation-sec-8b-instruct \| Plan: rule-based fallback \| Runtime: \d+ms$/);
});

test('no matching data: canned message is not attributed to the model', async (t) => {
    const response = await run(t, { llm: { plan: SEARCH_PLAN, report: MODEL_REPORT }, logs: [] });

    assert.equal(response.model_generated, false);
    assert.equal(response.generation.report, 'template_no_results');
    assert.doesNotMatch(response.footer, /Analyzed by/);
    assert.match(response.footer, /No model analysis: no matching data/);
});
