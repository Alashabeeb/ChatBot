import { test, after, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import http from 'http';
import express from 'express';
import jwt from 'jsonwebtoken';
import axios from 'axios';
import { setTestEnv, USER_ID } from './helpers.js';
import { isAggregationRequest, fakeAggregationResponse } from '../scripts/lib/fakeAggregations.js';

// ---------------------------------------------------------------------------------------------
// A local fake model (no real model is called): plans like a planner, and streams its report as
// small chunks with a pause after the first claim, so the test can see claims arrive early.
// ---------------------------------------------------------------------------------------------
const PLAN = { thought: 't', tools: [{ tool: 'searchSecurityLogs', parameters: { timeRange: 'now-24h', intent: 'brute_force', extractedIPs: [], minSeverity: null, cleanedSearchText: '' } }] };
const cite = (kind, ref, count) => (count === undefined ? { kind, ref } : { kind, ref, count });
const CLAIM_1 = { text: 'There were 3 failed logons.', cite: [cite('total', 'searchSecurityLogs', 3)] };
const CLAIM_2 = { text: 'Rule 5710 fired 2 times on web-01.', cite: [cite('rule', '5710', 2), cite('agent', 'web-01')] };
const FABRICATED = { text: 'They came from 91.92.93.94.', cite: [cite('rule', '5710')] };
const STEP = { text: 'Check who owns 203.0.113.9.', cite: [cite('ip', '203.0.113.9')] };
const model = { report: { insufficient_evidence: false, answer: [CLAIM_1], findings: [CLAIM_2, FABRICATED], next_steps: [STEP] }, behaviour: 'stream', pauseMs: 300, reportFinishedAt: null, clientClosed: false, reportRequests: 0 };

const llmServer = http.createServer((req, res) => {
    let raw = '';
    req.on('data', c => { raw += c; });
    req.on('end', async () => {
        const body = JSON.parse(raw || '{}');
        const system = body.messages?.[0]?.content ?? '';
        const reply = content => res.writeHead(200, { 'Content-Type': 'application/json' }).end(JSON.stringify({ choices: [{ message: { content }, finish_reason: 'stop' }] }));
        if (system.includes('Planning Engine')) return reply(JSON.stringify(PLAN));
        if (system.includes('Memory Engine')) return reply('{"summary":"s","keyEntities":[]}');
        model.reportRequests++;
        if (body.stream) { model.streamModels.push(body.model); model.streamMaxTokens.push(body.max_tokens); }
        if (model.behaviour === 'down') return res.writeHead(400, { 'Content-Type': 'application/json' }).end('{"error":"This model\'s maximum context length is 8192 tokens"}');
        const text = JSON.stringify(model.report);
        if (!body.stream) return reply(text);
        res.on('close', () => { if (!res.writableEnded) model.clientClosed = true; });
        res.writeHead(200, { 'Content-Type': 'text/event-stream' });
        const firstClaimEnd = text.indexOf(JSON.stringify(CLAIM_1)) + JSON.stringify(CLAIM_1).length + 1;
        const send = piece => res.write(`data: ${JSON.stringify({ choices: [{ index: 0, delta: { content: piece }, finish_reason: null }] })}\n\n`);
        for (let i = 0; i < firstClaimEnd; i += 7) send(text.slice(i, Math.min(i + 7, firstClaimEnd)));
        await new Promise(r => setTimeout(r, model.pauseMs));
        if (model.clientClosed) return;
        for (let i = firstClaimEnd; i < text.length; i += 7) send(text.slice(i, i + 7));
        model.reportFinishedAt = Date.now();
        res.end('data: [DONE]\n\n');
    });
});
await new Promise(r => llmServer.listen(0, '127.0.0.1', r));

setTestEnv();
process.env.LLM_API_URL = `http://127.0.0.1:${llmServer.address().port}/v1/chat/completions`;

const { initDatabase, default: db } = await import('../src/config/db.js');
const { default: chatRoutes } = await import('../src/routes/chat.routes.js');
const { authenticateToken } = await import('../src/middleware/auth.middleware.js');
const { RunModel } = await import('../src/models/Run.js');
const { clearEvidenceCache } = await import('../src/agent/evidenceCache.js');
initDatabase();
db.prepare("UPDATE users SET must_change_password = 0 WHERE id = 'user_admin_root'").run();

const app = express();
app.use(express.json());
app.use('/api/chat', authenticateToken, chatRoutes);
const appServer = await new Promise(r => { const s = app.listen(0, '127.0.0.1', () => r(s)); });
const BASE = `http://127.0.0.1:${appServer.address().port}`;
const TOKEN = jwt.sign({ id: USER_ID, username: 'admin', role: 'admin' }, process.env.JWT_SECRET);
after(async () => {
    await new Promise(r => appServer.close(r));
    llmServer.closeAllConnections?.();
    await new Promise(r => llmServer.close(r));
});

// OpenSearch is stubbed; model calls go to the fake model server above.
const LOGS = [
    { '@timestamp': '2026-10-12T08:00:00Z', rule: { id: '5710', level: 5, description: 'sshd: failed' }, agent: { name: 'web-01' }, data: { srcip: '203.0.113.9' } },
    { '@timestamp': '2026-10-12T08:00:00Z', rule: { id: '5710', level: 5, description: 'sshd: failed' }, agent: { name: 'web-01' }, data: { srcip: '203.0.113.9' } },
    { '@timestamp': '2026-10-12T08:00:00Z', rule: { id: '5712', level: 5, description: 'sshd: other' }, agent: { name: 'web-02' }, data: { srcip: '198.51.100.4' } }
];
const realPost = axios.post;
beforeEach((t) => {
    clearEvidenceCache();
    Object.assign(model, { behaviour: 'stream', pauseMs: 300, reportFinishedAt: null, clientClosed: false, reportRequests: 0, streamModels: [], streamMaxTokens: [] });
    model.report = { insufficient_evidence: false, answer: [CLAIM_1], findings: [CLAIM_2, FABRICATED], next_steps: [STEP] };
    delete process.env.REPORT_LLM_MODEL;
    t.mock.method(axios, 'post', async (url, body, config) => {
        if (!String(url).includes('/_search')) return realPost.call(axios, url, body, config);
        const firewall = JSON.stringify(body?.query?.bool?.must ?? []).includes('"iptables"');
        if (isAggregationRequest(body)) return fakeAggregationResponse(body, { current: firewall ? [] : LOGS });
        const hits = firewall ? [] : LOGS;
        return { status: 200, data: { hits: { total: { value: hits.length }, hits: hits.map(h => ({ _source: h })) } } };
    });
    for (const level of ['log', 'warn']) t.mock.method(console, level, () => {});
});

async function stream(body, { token = TOKEN, abortAfterFirstClaim = false } = {}) {
    const controller = new AbortController();
    const res = await fetch(`${BASE}/api/chat/search/stream`, {
        method: 'POST', headers: { 'Content-Type': 'application/json', ...(token ? { Authorization: `Bearer ${token}` } : {}) },
        body: JSON.stringify(body), signal: controller.signal
    });
    if (!res.ok) return { status: res.status, events: [] };
    const events = [];
    const decoder = new TextDecoder();
    let buffer = '';
    try {
        for await (const chunk of res.body) {
            buffer += decoder.decode(chunk, { stream: true });
            const blocks = buffer.split('\n\n');
            buffer = blocks.pop();
            for (const block of blocks) {
                const event = /^event: (.*)$/m.exec(block)?.[1];
                const data = JSON.parse(/^data: (.*)$/m.exec(block)?.[1] ?? 'null');
                events.push({ event, data, at: Date.now() });
                if (abortAfterFirstClaim && event === 'report' && data.markdown.includes(CLAIM_1.text)) controller.abort();
            }
        }
    } catch (error) {
        if (error.name !== 'AbortError') throw error;
    }
    return { status: res.status, events };
}
const reports = events => events.filter(e => e.event === 'report').map(e => e.data.markdown);
const stages = events => events.filter(e => e.event === 'stage').map(e => e.data.stage);
const done = events => events.find(e => e.event === 'done')?.data.response;

test('search answers stream: meta, real stages, the header, then each verified statement, then done', async () => {
    const { status, events } = await stream({ text: 'show me failed logons today', history: [] });
    assert.equal(status, 200);
    assert.equal(events[0].event, 'meta');
    assert.equal(events.at(-1).event, 'done');
    assert.deepEqual(stages(events), ['planning', 'searching', 'analysing', 'verifying']);
    for (const s of events.filter(e => e.event === 'stage')) assert.ok(s.data.label.length > 0);
    assert.match(events.find(e => e.data?.stage === 'searching').data.label, /2 queries/);

    const shown = reports(events);
    assert.match(shown[0], /^\*\*Searched:\*\* Wazuh alerts \(3 matches\)/, 'the header comes first, before the model answers');
    assert.ok(!shown[0].includes(CLAIM_1.text));
    assert.ok(shown.some(m => m.includes(CLAIM_1.text) && !m.includes(CLAIM_2.text)), 'statements appear one by one');
    for (let i = 1; i < shown.length; i++) assert.ok(shown[i].startsWith(shown[i - 1].split('\n\n')[0]), 'each update keeps the header');

    const response = done(events);
    assert.equal(response.type, 'agent_response');
    assert.equal(response.request_id, events[0].data.request_id);
    assert.equal(response.summary, shown.at(-1), 'the last streamed report is the final answer');
    for (const claim of [CLAIM_1, CLAIM_2, STEP]) assert.ok(response.summary.includes(claim.text));
    assert.deepEqual(response.grounding, { claims: 4, shown: 3, dropped: 1 });
});

test('a fabricated statement never appears in any streamed update', async () => {
    const { events } = await stream({ text: 'show me failed logons today', history: [] });
    for (const markdown of reports(events)) assert.ok(!markdown.includes('91.92.93.94'), markdown);
    assert.ok(!JSON.stringify(done(events)).includes('91.92.93.94'));
});

test('a verified statement reaches the browser before the model has finished', async () => {
    const { events } = await stream({ text: 'show me failed logons today', history: [] });
    const first = events.find(e => e.event === 'report' && e.data.markdown.includes(CLAIM_1.text));
    assert.ok(first.at < model.reportFinishedAt, `claim at ${first.at}, model finished at ${model.reportFinishedAt}`);
});

test('the streamed answer is the same as the non-streamed /api/chat answer for the same model output', async () => {
    const { events } = await stream({ text: 'show me failed logons today', history: [] });
    const res = await fetch(`${BASE}/api/chat`, { method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${TOKEN}` }, body: JSON.stringify({ text: 'show me failed logons today', history: [] }) });
    const plain = await res.json();
    assert.equal(done(events).summary.replace(/Runtime: \d+ms/, ''), plain.summary.replace(/Runtime: \d+ms/, ''));
});

test('follow-ups stream too: no planning or searching stage, and the header says the evidence is reused', async () => {
    const first = done((await stream({ text: 'show me failed logons today', history: [] })).events);
    const { events } = await stream({ text: 'tell me more about rule 5710', history: [], follow_up_of: first.request_id });
    assert.deepEqual(stages(events), ['reading', 'analysing', 'verifying']);
    assert.match(reports(events)[0], /^\*\*Answered from the evidence of your previous search\*\*/);
    assert.equal(done(events).generation.planner, 'follow_up');
});

test('a clarifying question comes back as the whole answer, with nothing searched', async () => {
    const { events } = await stream({ text: 'is that IP malicious?', history: [] });
    assert.deepEqual(stages(events), []);
    const response = done(events);
    assert.equal(response.clarification, true);
    assert.match(response.text, /^Quick question before I search: Which IP/);
});

test('model down: the header still streams; the answer is the code-written fallback', async () => {
    model.behaviour = 'down';
    const { events } = await stream({ text: 'show me failed logons today', history: [] });
    assert.match(reports(events)[0], /^\*\*Searched:\*\*/);
    const response = done(events);
    assert.equal(response.model_generated, false);
    assert.match(response.summary, /Model unavailable/);
    // The model server's own explanation is kept in the run record (for diagnosis), not shown to the analyst.
    const run = RunModel.findById(response.request_id);
    assert.ok(run.errors.some(e => e.stage === 'llm' && /HTTP 400.*maximum context length is 8192 tokens/.test(e.message)), JSON.stringify(run.errors));
    assert.doesNotMatch(response.summary, /context length/);
});

test('Stop during the analysis cancels the model request and records the run', async () => {
    const { events } = await stream({ text: 'show me failed logons today', history: [] }, { abortAfterFirstClaim: true });
    const requestId = events[0].data.request_id;
    await new Promise(r => setTimeout(r, 500));
    assert.equal(model.clientClosed, true, 'the model request was cancelled');
    const run = RunModel.findById(requestId);
    assert.notEqual(run.status, 'running');
    assert.equal(run.generation.report, 'stopped');
});

test('the search stream requires a login', async () => {
    const { status } = await stream({ text: 'show me failed logons today' }, { token: null });
    assert.equal(status, 401);
});

test('when the model says the evidence is insufficient, no statement is streamed', async () => {
    model.report = { insufficient_evidence: true, answer: [CLAIM_1], findings: [CLAIM_2] };
    const { events } = await stream({ text: 'show me failed logons today', history: [] });
    for (const markdown of reports(events)) assert.ok(!markdown.includes(CLAIM_1.text) && !markdown.includes(CLAIM_2.text), markdown);
    assert.match(done(events).summary, /\*\*Not enough evidence\*\*/);
});

test('the streamed report goes to the configured report model', async () => {
    process.env.REPORT_LLM_MODEL = 'stream-report-model';
    await stream({ text: 'show me failed logons today', history: [] });
    assert.deepEqual(model.streamModels, ['stream-report-model']);
    assert.deepEqual(model.streamMaxTokens, [1000], 'the streamed report is capped too (LLM_REPORT_MAX_TOKENS)');
});
