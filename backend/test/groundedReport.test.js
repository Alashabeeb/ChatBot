import { test } from 'node:test';
import assert from 'node:assert/strict';
import axios from 'axios';
import { setTestEnv, stubBackends, flushBackgroundWork, USER_ID, askFoundationArgs } from './helpers.js';

setTestEnv();
const { initDatabase } = await import('../src/config/db.js');
const { runAgentWorkflow } = await import('../src/agent/runtime.js');
const { RunModel } = await import('../src/models/Run.js');

initDatabase();

const PLAN = {
    thought: 'Search failed logons.',
    tools: [{ tool: 'searchSecurityLogs', parameters: { timeRange: 'now-24h', intent: 'brute_force', extractedIPs: [], minSeverity: null, cleanedSearchText: '' } }]
};
const log = (ruleId, extra = {}) => ({
    '@timestamp': '2026-10-12T08:00:00Z',
    rule: { id: ruleId, level: 5, description: 'sshd: authentication failed (see also T1003 in vendor notes)', mitre: { id: ['T1110.001'] } },
    agent: { name: 'web-01', id: '001' },
    data: { srcip: '203.0.113.9', srcuser: 'root' },
    ...extra
});
const LOGS = [log('5710'), log('5710'), log('5710'), log('5712', { agent: { name: 'web-02', id: '002' } })];

const cite = (kind, ref, count) => (count === undefined ? { kind, ref } : { kind, ref, count });
const GOOD = {
    answer: { text: 'There were 4 failed SSH logins.', cite: [cite('total', 'searchSecurityLogs', 4)] },
    finding: { text: 'Rule 5710 fired 3 times on web-01, all from 203.0.113.9.', cite: [cite('rule', '5710', 3), cite('agent', 'web-01'), cite('ip', '203.0.113.9')] },
    assessment: { text: 'This matches password guessing (T1110.001).', cite: [cite('mitre', 'T1110.001')] },
    step: { text: 'Check who owns 203.0.113.9 before blocking it.', cite: [cite('ip', '203.0.113.9')] }
};
// Each fabricated claim carries a marker that must never reach the analyst.
const FABRICATED = [
    { marker: '91.92.93.94', claim: { text: 'Traffic also came from 91.92.93.94.', cite: [cite('rule', '5710')] } },
    { marker: '92657', claim: { text: 'Rule 92657 (Mimikatz) fired.', cite: [cite('rule', '92657')] } },
    { marker: 'T1003', claim: { text: 'This is credential dumping (T1003).', cite: [cite('mitre', 'T1003')] } },
    { marker: 'T1059', claim: { text: 'Uncited technique T1059 was seen.', cite: [cite('rule', '5710')] } },
    { marker: '17 times', claim: { text: 'Rule 5712 fired 17 times.', cite: [cite('rule', '5712', 17)] } },
    { marker: '250 attempts', claim: { text: 'There were 250 attempts overall.', cite: [cite('rule', '5710')] } },
    { marker: 'DC07', claim: { text: 'DC07 was also targeted.', cite: [cite('agent', 'web-01')] } },
    { marker: 'confidence', claim: { text: 'Confidence: 95 out of 100 that this is an attack.', cite: [cite('rule', '5710')] } },
    { marker: 'has been blocked', claim: { text: 'The IP 203.0.113.9 has been blocked.', cite: [cite('ip', '203.0.113.9')] } },
    { marker: 'no citation at all', claim: { text: 'This statement has no citation at all.' } },
    { marker: 'hunch', claim: { text: 'A hunch about the attacker.', cite: [cite('vibes', 'x')] } },
    { marker: 'earlier case', claim: { text: 'An earlier case looked the same.', cite: [cite('memory', 'memory#9')] } },
    { marker: 'admin99', claim: { text: 'The account admin99 was targeted.', cite: [cite('user', 'admin99')] } },
    { marker: '999 matches', claim: { text: 'There were 999 matches.', cite: [cite('total', 'searchSecurityLogs', 999)] } },
    // Each of these gets past every check but one, so that check is tested on its own.
    { marker: 'Risk score', claim: { text: 'Risk score 4 for this activity.', cite: [cite('total', 'searchSecurityLogs', 4)] } },
    { marker: 'credential dumping', claim: { text: 'This is credential dumping.', cite: [cite('mitre', 'T1003')] } },
    { marker: '92658', claim: { text: 'Rule 92658 fired as well.', cite: [cite('rule', '5710')] } },
    { marker: 'mallory', claim: { text: 'The account mallory was targeted.', cite: [cite('user', 'mallory')] } }
];

async function ask(t, { report, logs = LOGS, llm } = {}) {
    const stubs = stubBackends(t, { llm: llm ?? { plan: PLAN, report: typeof report === 'string' ? report : JSON.stringify(report) }, logs });
    const response = await runAgentWorkflow('show me failed logons today', [], USER_ID);
    await flushBackgroundWork();
    return { response, stubs, run: RunModel.findById(response.request_id) };
}

const REPORT_SYSTEM = 'Reasoning Engine';
const reportCall = llmCalls => llmCalls.find(m => m[0].content.includes(REPORT_SYSTEM));

test('every report opens with the sources and time window actually searched (written by the code)', async (t) => {
    const { response } = await ask(t, { report: { answer: [GOOD.answer] } });
    const firstLine = response.summary.split('\n')[0];
    assert.match(firstLine, /^\*\*Searched:\*\* Wazuh alerts \(4 matches\) and firewall events from Wazuh \(0 matches\) for the last 24 hours\.$/);
});

test('verified claims are shown; the report is attributed to the model', async (t) => {
    const { response, run } = await ask(t, { report: { answer: [GOOD.answer], findings: [GOOD.finding], assessment: [GOOD.assessment], next_steps: [GOOD.step] } });
    for (const claim of Object.values(GOOD)) assert.ok(response.summary.includes(claim.text), `missing: ${claim.text}`);
    assert.match(response.summary, /\*\*Findings\*\*\n- Rule 5710 fired 3 times/);
    assert.match(response.summary, /\*\*Next steps\*\*\n- Check who owns/);
    assert.equal(response.model_generated, true);
    assert.equal(response.generation.report, 'model');
    assert.deepEqual(response.grounding, { claims: 4, shown: 4, dropped: 0 });
    assert.deepEqual(run.grounding.dropped, []);
    assert.doesNotMatch(response.footer, /removed/);
});

test('fabricated claims are dropped, logged with a reason, and never reach the analyst', async (t) => {
    const report = { answer: [GOOD.answer], findings: [GOOD.finding, ...FABRICATED.map(f => f.claim)] };
    const { response, run } = await ask(t, { report });

    assert.ok(response.summary.includes(GOOD.finding.text));
    const visible = JSON.stringify({ ...response, raw_logs: undefined });
    for (const { marker } of FABRICATED) {
        assert.ok(!visible.includes(marker), `fabricated "${marker}" reached the response`);
    }
    assert.deepEqual(response.grounding, { claims: 2 + FABRICATED.length, shown: 2, dropped: FABRICATED.length });
    assert.match(response.footer, new RegExp(`${FABRICATED.length} unsupported statements removed`));

    assert.equal(run.grounding.dropped.length, FABRICATED.length);
    for (const { marker } of FABRICATED) {
        const entry = run.grounding.dropped.find(d => d.text.toLowerCase().includes(marker.toLowerCase()));
        assert.ok(entry, `dropped claim with "${marker}" not logged`);
        assert.ok(entry.reason.length > 0);
    }
    assert.ok(run.reportText === response.summary);
});

test('numbers inside a rule description quoted from the evidence are not treated as uncited counts', async (t) => {
    const logs = [log('31151', { rule: { id: '31151', level: 10, description: 'Multiple web server 400 error codes from same source ip' } })];
    const quoted = { text: 'Rule 31151 (Multiple web server 400 error codes from same source ip) fired once.', cite: [cite('rule', '31151', 1)] };
    const invented = { text: 'Rule 31151 saw 400 errors.', cite: [cite('rule', '31151', 1)] };
    const { response, run } = await ask(t, { logs, report: { findings: [quoted, invented] } });
    assert.ok(response.summary.includes(quoted.text));
    assert.ok(!response.summary.includes(invented.text), 'a number outside the quoted description still needs a citation');
    assert.match(run.grounding.dropped[0].reason, /400/);
});

test('MITRE techniques come only from rule.mitre.id, not from descriptions or other text', async (t) => {
    // T1003 appears in a rule description in the evidence, but in no rule.mitre.id.
    const { response, run } = await ask(t, { report: { answer: [GOOD.answer], assessment: [{ text: 'Looks like T1003.', cite: [cite('rule', '5710')] }] } });
    assert.doesNotMatch(response.summary, /T1003/);
    assert.match(run.grounding.dropped[0].reason, /rule\.mitre\.id/);
});

test('free-text model output is not shown: the analyst gets the code-written evidence summary, not attributed to the model', async (t) => {
    const { response, run } = await ask(t, { report: '**Executive Summary**: 40 brute force attempts from 10.9.9.9; confidence 90%.' });
    assert.doesNotMatch(response.summary, /Executive Summary|10\.9\.9\.9|40 brute/);
    assert.match(response.summary, /^\*\*Searched:\*\*/);
    assert.match(response.summary, /couldn't be verified/);
    assert.match(response.summary, /rule 5710 \(sshd: authentication failed.*?\): 3/);
    assert.equal(response.model_generated, false);
    assert.equal(response.generation.report, 'fallback_unverifiable');
    assert.match(run.grounding.parseError, /JSON/);
});

test('when no claim survives verification, nothing the model wrote is shown', async (t) => {
    // (T1003 is left out here: it legitimately appears in a rule description shown in the evidence summary.)
    const picked = FABRICATED.filter(f => f.marker !== 'T1003').slice(0, 4);
    const { response } = await ask(t, { report: { findings: picked.map(f => f.claim) } });
    for (const { marker } of picked) assert.ok(!response.summary.includes(marker), marker);
    assert.equal(response.generation.report, 'fallback_unverifiable');
    assert.equal(response.model_generated, false);
    assert.match(response.summary, /None of the model's statements could be verified/);
});

test('insufficient evidence produces an honest "not enough evidence" answer, never a guess', async (t) => {
    const { response } = await ask(t, { report: { insufficient_evidence: true, findings: [GOOD.finding] } });
    assert.match(response.summary, /\*\*Not enough evidence\*\*/);
    assert.ok(!response.summary.includes(GOOD.finding.text), 'claims are not shown when the model says the evidence is insufficient');
    assert.equal(response.generation.report, 'insufficient_evidence');
    assert.equal(response.model_generated, false);
});

test('zero hits: says plainly that nothing matched, for which sources and window', async (t) => {
    const { response, stubs } = await ask(t, { report: { answer: [GOOD.answer] }, logs: [] });
    assert.match(response.summary, /^\*\*Searched:\*\* Wazuh alerts \(0 matches\) and firewall events from Wazuh \(0 matches\) for the last 24 hours\./);
    assert.match(response.summary, /\*\*No matching records\*\* for the last 24 hours/);
    assert.equal(reportCall(stubs.llmCalls), undefined, 'the model is not asked when there is nothing to analyse');
});

test('every search failed: says the search could not be completed, never "0 matching records" (F-62)', async (t) => {
    stubBackends(t, { llm: { plan: PLAN, report: JSON.stringify({ answer: [GOOD.answer] }) } });
    axios.post.mock.restore();
    t.mock.method(axios, 'post', async (url, body) => {
        if (body?.messages) {
            const system = body.messages[0].content;
            const content = system.includes('Planning Engine') ? JSON.stringify(PLAN) : '{"summary":"x","keyEntities":[]}';
            return { data: { choices: [{ message: { content } }] } };
        }
        const error = new Error('Request failed with status code 503');
        error.response = { status: 503, data: {} };
        throw error;
    });
    const response = await runAgentWorkflow('show me failed logons today', [], USER_ID);
    await flushBackgroundWork();
    assert.match(response.summary, /\*\*The search could not be completed\*\*/);
    assert.match(response.summary, /\*\*Not available:\*\* Wazuh alerts: the search failed \(Request failed with status code 503\); firewall events from Wazuh: the search failed/);
    assert.doesNotMatch(response.summary, /0 matching record|No matching records/);
    assert.equal(response.generation.report, 'template_search_failed');
});

test('model down: the notice, the header and the code-written counts; no "0 matching record(s)" line', async (t) => {
    const { response } = await ask(t, { llm: 'down' });
    assert.match(response.summary, /Model unavailable: this response was not generated by a model/);
    assert.match(response.summary, /\*\*Searched:\*\*/);
    assert.match(response.summary, /\*\*Most frequent rules:\*\* rule 5710/);
    assert.doesNotMatch(response.summary, /matching record\(s\) were retrieved/);
});

test('the evidence sent to the model carries what it needs to cite: rule IDs, counts, techniques, search keys', async (t) => {
    const { stubs } = await ask(t, { report: { answer: [GOOD.answer] } });
    const { prompt } = askFoundationArgs(reportCall(stubs.llmCalls));
    const evidence = JSON.parse(prompt.content.slice(prompt.content.indexOf('{')));
    assert.equal(evidence.searches[0].key, 'searchSecurityLogs');
    assert.equal(evidence.searches[0].totalMatches, 4);
    assert.equal(evidence.searches[0].sampleLogs[0].ruleId, '5710');
    assert.deepEqual(evidence.counts.byRule[0], { ruleId: '5710', description: LOGS[0].rule.description, count: 3 });
    assert.deepEqual(evidence.mitreTechniques, ['T1110.001']);
});
