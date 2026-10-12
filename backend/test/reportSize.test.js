import { test, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import axios from 'axios';
import { setTestEnv, flushBackgroundWork, USER_ID, llmReply } from './helpers.js';
import { isAggregationRequest } from '../scripts/lib/fakeAggregations.js';

setTestEnv();
const { initDatabase } = await import('../src/config/db.js');
const { runAgentWorkflow } = await import('../src/agent/runtime.js');
const { RunModel } = await import('../src/models/Run.js');
const { listingRequest } = await import('../src/agent/listing.js');
initDatabase();

afterEach(() => { delete process.env.REPORT_PROMPT_MAX_CHARS; delete process.env.LLM_REPORT_MAX_TOKENS; });

const PLAN = { thought: 't', tools: [{ tool: 'searchSecurityLogs', parameters: { timeRange: 'now-24h', intent: 'alerts', extractedIPs: [], minSeverity: null, cleanedSearchText: '' } }] };
const rec = (i, firewall = false) => ({
    '@timestamp': `2026-10-12T${String(8 + Math.floor(i / 60)).padStart(2, '0')}:${String(i % 60).padStart(2, '0')}:00.000Z`,
    rule: { id: firewall ? '600000' : String(60100 + (i % 7)), level: 5 + (i % 3), description: firewall ? 'Abuja-CORE-Firewall drop' : `Windows event ${i % 7} with a fairly long description`, mitre: { id: ['T1078'] } },
    agent: { name: firewall ? 'fw-core-01' : `host-${i % 5}` },
    data: { srcip: `10.128.52.${i % 250}`, srcuser: `user${i % 9}` }
});
// 200 records per search, newest first, behind millions of matches; OpenSearch's counts carry an error bound.
const NON_FW = Array.from({ length: 200 }, (_, i) => rec(199 - i));
const FW = Array.from({ length: 200 }, (_, i) => rec(199 - i - 0.5 > 0 ? 199 - i : 0, true)).map((r, i) => ({ ...r, '@timestamp': `2026-10-12T07:${String(59 - (i % 60)).padStart(2, '0')}:30.000Z` }));
const terms = (keys, error) => ({ doc_count_error_upper_bound: error, sum_other_doc_count: 0, buckets: keys.map((key, i) => ({ key, doc_count: 1000000 - i * 1000, doc_count_error_upper_bound: error, description: { buckets: [{ key: `desc ${key}` }] } })) });
const aggWindow = error => ({
    doc_count: 5708019,
    by_rule: terms(Array.from({ length: 30 }, (_, i) => String(60100 + i)), error),
    by_agent: terms(Array.from({ length: 20 }, (_, i) => `host-${i}`), error),
    by_srcip: terms(Array.from({ length: 20 }, (_, i) => `10.128.52.${i}`), error),
    by_win_ip: terms([], 0), by_level: terms([5, 6, 7], 0), by_mitre: terms(['T1078'], 0)
});

function stub(t, { report = { answer: [{ text: 'Rule 60100 is the most frequent.', cite: [{ kind: 'rule', ref: '60100' }] }] }, error = 12 } = {}) {
    const calls = { report: [], searches: 0 };
    t.mock.method(axios, 'get', async () => ({ status: 200, data: { data: { affected_items: [], total_affected_items: 0 } } }));
    t.mock.method(axios, 'post', async (url, body) => {
        if (body?.messages) {
            const system = body.messages[0].content;
            if (system.includes('Planning Engine')) return llmReply(JSON.stringify(PLAN));
            if (system.includes('Memory Engine')) return llmReply('{"summary":"s","keyEntities":[]}');
            calls.report.push(body);
            return llmReply(JSON.stringify(report));
        }
        const firewall = JSON.stringify(body?.query?.bool?.must ?? []).includes('"iptables"');
        if (isAggregationRequest(body)) return { status: 200, data: { hits: { total: { value: 0 }, hits: [] }, aggregations: { current: aggWindow(error), previous: aggWindow(error) } } };
        calls.searches++;
        const hits = firewall ? FW : NON_FW;
        return { status: 200, data: { hits: { total: { value: firewall ? 3536 : 5708019 }, hits: hits.map(h => ({ _source: h })) } } };
    });
    for (const level of ['log', 'warn']) t.mock.method(console, level, () => {});
    return calls;
}

async function ask(t, question, { history = [], ...opts } = {}) {
    const calls = stub(t, opts);
    const response = await runAgentWorkflow(question, history, USER_ID);
    await flushBackgroundWork();
    return { calls, response, run: RunModel.findById(response.request_id) };
}
const evidenceOf = body => {
    const prompt = body.messages.at(-1).content;
    return { prompt, evidence: JSON.parse(prompt.slice(prompt.indexOf('{'))) };
};

// ---------------------------------------------------------------- fixes 1-5: the report request stays small

test('1: approximate aggregation counts still cover every match, so at most 10 example records per search are sent', async (t) => {
    process.env.REPORT_PROMPT_MAX_CHARS = '1000000';   // no trimming, so only the sample size is under test
    const { calls } = await ask(t, 'what is going on with the windows hosts');
    const { evidence } = evidenceOf(calls.report[0]);
    assert.equal(evidence.countsExact, false, 'OpenSearch reported an error bound');
    assert.equal(evidence.countsCoverAllMatches, true);
    for (const s of evidence.searches) assert.ok(s.sampleLogs.length <= 10, `${s.key}: ${s.sampleLogs.length} samples`);
});

test('2: the evidence is sent as compact JSON, without indentation', async (t) => {
    const { calls } = await ask(t, 'what is going on with the windows hosts');
    const { prompt } = evidenceOf(calls.report[0]);
    const json = prompt.slice(prompt.indexOf('{'));
    assert.equal(json, JSON.stringify(JSON.parse(json)), 'no whitespace formatting');
});

test('3: a hard size limit trims the evidence (examples first, then lists) and records what was trimmed', async (t) => {
    process.env.REPORT_PROMPT_MAX_CHARS = '6000';
    const { calls, run, response } = await ask(t, 'what is going on with the windows hosts');
    const body = calls.report[0];
    const total = body.messages.reduce((n, m) => n + m.content.length, 0);
    assert.ok(total <= 6000, `request is ${total} characters`);
    const { evidence } = evidenceOf(body);
    assert.ok(Array.isArray(evidence.trimmed) && evidence.trimmed.length > 0, 'the model is told what was left out');
    assert.ok(evidence.searches.every(s => (s.sampleLogs ?? []).length === 0), 'example records go first');
    assert.deepEqual(run.timings.reportPromptTrimmed, evidence.trimmed);
    assert.ok(run.timings.reportPromptChars <= 6000);
    // Verification still uses the full evidence: a claim about a rule trimmed from the lists still holds.
    assert.match(response.summary, /Rule 60100 is the most frequent\./);
});

test('3: without a limit set, the default keeps a production-sized request under 16,000 characters', async (t) => {
    const { calls } = await ask(t, 'what is going on with the windows hosts');
    const total = calls.report[0].messages.reduce((n, m) => n + m.content.length, 0);
    assert.ok(total <= 16000, `request is ${total} characters`);
});

test('4: the report sees at most the last two chat messages, each shortened', async (t) => {
    const long = 'x'.repeat(5000);
    const history = [
        { role: 'user', content: 'first question' }, { role: 'assistant', content: long },
        { role: 'user', content: 'second question' }, { role: 'assistant', content: long }
    ];
    const { calls } = await ask(t, 'what is going on with the windows hosts', { history });
    const messages = calls.report[0].messages;
    const historyPart = messages.slice(1, -1);
    assert.equal(historyPart.length, 2);
    assert.deepEqual(historyPart.map(m => m.role), ['user', 'assistant']);
    for (const m of historyPart) assert.ok(m.content.length <= 1000, `history message of ${m.content.length} characters`);
});

test('5: the report answer length is capped (LLM_REPORT_MAX_TOKENS, default 1000)', async (t) => {
    let { calls } = await ask(t, 'what is going on with the windows hosts');
    assert.equal(calls.report[0].max_tokens, 1000);
    process.env.LLM_REPORT_MAX_TOKENS = '600';
    ({ calls } = await ask(t, 'what is going on with the windows hosts'));
    assert.equal(calls.report[0].max_tokens, 600);
});

// ---------------------------------------------------------------- 7: "the N most recent logs" is a table the code writes

test('7: listing requests are recognised; "top N" by frequency and time windows are not', () => {
    const cases = {
        'Show me the top 20 most recent logs on the wazuh': 20,
        'show me the top 20 most recent logs on the wazuh for 197.159.78.164': 20,
        'last 10 alerts': 10,
        'latest logs': 20,
        'the 5 newest events on DC01': 5,
        'most recent failed logins for 10.0.0.1': 20,
        'give me the 500 most recent logs': 100,
        'what was the last alert on DC01': 1
    };
    for (const [q, n] of Object.entries(cases)) assert.deepEqual(listingRequest(q), { count: n }, q);
    for (const q of ['what are the top alerts this week', 'top 20 alerts', 'alerts in the last 24 hours', 'the last 24 hours of alerts', 'show me failed logons today', 'what happened in the last hour']) {
        assert.equal(listingRequest(q), null, q);
    }
});

test('7: "the 20 most recent logs" is answered with a table of exactly those records, newest first, written by the code', async (t) => {
    const { calls, response } = await ask(t, 'Show me the top 20 most recent logs on the wazuh');
    assert.equal(calls.report.length, 0, 'the model is not needed');
    assert.equal(response.generation.report, 'template_recent_records');
    assert.equal(response.model_generated, false);
    const lines = response.summary.split('\n');
    assert.match(lines[0], /^\*\*Searched:\*\* Wazuh alerts \(5,708,019 matches\) and firewall events from Wazuh \(3,536 matches\) for the last 24 hours\./);
    assert.match(response.summary, /\*\*The 20 most recent records\*\* of 5,711,555 matches, newest first:/);
    const rows = lines.filter(l => l.startsWith('| 2026-'));
    assert.equal(rows.length, 20);
    // Newest first across both searches: the non-firewall records (08:00-11:19) are all newer than the firewall ones (07:xx).
    const times = rows.map(r => r.split('|')[1].trim());
    assert.deepEqual(times, [...times].sort().reverse());
    assert.equal(times[0], '2026-10-12 11:19:00');
    assert.match(rows[0], /\| 60103 \| 6 \| Windows event 3 with a fairly long description \| host-4 \| 10\.128\.52\.199 \| user1 \|/);
    assert.match(response.summary, /\| Time \(UTC\) \| Rule \| Level \| Description \| Agent \| Source IP \| User \|/);
    assert.match(response.summary, /All 400 records retrieved are under View Full Details\./);
});

test('7: when fewer records match than were asked for, the answer says so', async (t) => {
    const calls = stub(t);
    axios.post.mock.restore();
    t.mock.method(axios, 'post', async (url, body) => {
        if (body?.messages) return llmReply(body.messages[0].content.includes('Planning Engine') ? JSON.stringify(PLAN) : '{"summary":"s","keyEntities":[]}');
        if (isAggregationRequest(body)) return { status: 200, data: { hits: { total: { value: 0 }, hits: [] }, aggregations: {} } };
        const firewall = JSON.stringify(body?.query?.bool?.must ?? []).includes('"iptables"');
        const hits = firewall ? [] : NON_FW.slice(0, 3);
        return { status: 200, data: { hits: { total: { value: hits.length }, hits: hits.map(h => ({ _source: h })) } } };
    });
    const response = await runAgentWorkflow('last 10 alerts', [], USER_ID);
    await flushBackgroundWork();
    assert.match(response.summary, /\*\*Only 3 records matched\*\*, newest first:/);
    assert.equal(response.summary.split('\n').filter(l => l.startsWith('| 2026-')).length, 3);
    assert.equal(calls.report.length, 0);
});

test('7: table cells are escaped so a log value cannot break the table', async () => {
    const { listingTable } = await import('../src/agent/listing.js');
    const table = listingTable([{ '@timestamp': '2026-10-12T08:00:00Z', rule: { id: '1', level: 3, description: 'a | b\nc' }, agent: { name: 'x' } }]);
    const row = table.split('\n').find(l => l.startsWith('| 2026-'));
    assert.match(row, /a \\\| b c/);
    assert.equal(row.split(/(?<!\\)\|/).length, 9, 'seven cells, no extra columns');
});
