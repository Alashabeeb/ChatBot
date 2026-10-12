import { test, after, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import http from 'http';
import express from 'express';
import jwt from 'jsonwebtoken';
import axios from 'axios';
import { setTestEnv, USER_ID } from './helpers.js';
import { isAggregationRequest, fakeAggregationResponse } from '../scripts/lib/fakeAggregations.js';

// A local fake model (no real model is called) answering each kind of request the assistant makes.
const PLAN = { thought: 't', tools: [{ tool: 'searchSecurityLogs', parameters: { timeRange: 'now-24h', intent: 'brute_force', extractedIPs: [], minSeverity: null, cleanedSearchText: '' } }] };
const REPORT = { answer: [{ text: 'There were 2 failed logons.', cite: [{ kind: 'total', ref: 'searchSecurityLogs', count: 2 }] }] };
const model = { routerReply: 'CHAT', requests: [] };
const llmServer = http.createServer((req, res) => {
    let raw = '';
    req.on('data', c => { raw += c; });
    req.on('end', () => {
        const body = JSON.parse(raw || '{}');
        const system = body.messages?.[0]?.content ?? '';
        const kind = system.includes('You route messages') ? 'router' : system.includes('Planning Engine') ? 'planner'
            : system.includes('Reasoning Engine') ? 'report' : system.includes('Memory Engine') ? 'memory' : 'chat';
        model.requests.push(kind);
        const content = { router: model.routerReply, planner: JSON.stringify(PLAN), report: JSON.stringify(REPORT), memory: '{"summary":"s","keyEntities":[]}', chat: 'Hello! How can I help?' }[kind];
        if (body.stream) {
            res.writeHead(200, { 'Content-Type': 'text/event-stream' });
            for (const piece of content.match(/.{1,6}/gs)) res.write(`data: ${JSON.stringify({ choices: [{ index: 0, delta: { content: piece }, finish_reason: null }] })}\n\n`);
            return res.end('data: [DONE]\n\n');
        }
        res.writeHead(200, { 'Content-Type': 'application/json' }).end(JSON.stringify({ choices: [{ message: { content }, finish_reason: 'stop' }] }));
    });
});
await new Promise(r => llmServer.listen(0, '127.0.0.1', r));

setTestEnv();
process.env.LLM_API_URL = `http://127.0.0.1:${llmServer.address().port}/v1/chat/completions`;
const { initDatabase, default: db } = await import('../src/config/db.js');
const { default: chatRoutes } = await import('../src/routes/chat.routes.js');
const { authenticateToken } = await import('../src/middleware/auth.middleware.js');
const { RunModel } = await import('../src/models/Run.js');
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

const LOGS = [1, 2].map(() => ({ '@timestamp': '2026-10-12T08:00:00Z', rule: { id: '5710', level: 5, description: 'sshd: failed' }, agent: { name: 'web-01' } }));
const realPost = axios.post;
let searches = 0;
beforeEach((t) => {
    model.routerReply = 'CHAT';
    model.requests = [];
    searches = 0;
    t.mock.method(axios, 'post', async (url, body, config) => {
        if (!String(url).includes('/_search')) return realPost.call(axios, url, body, config);
        const firewall = JSON.stringify(body?.query?.bool?.must ?? []).includes('"iptables"');
        if (isAggregationRequest(body)) return fakeAggregationResponse(body, { current: firewall ? [] : LOGS });
        searches++;
        const hits = firewall ? [] : LOGS;
        return { status: 200, data: { hits: { total: { value: hits.length }, hits: hits.map(h => ({ _source: h })) } } };
    });
    for (const level of ['log', 'warn']) t.mock.method(console, level, () => {});
});

async function send(body, token = TOKEN) {
    const res = await fetch(`${BASE}/api/chat/message`, { method: 'POST', headers: { 'Content-Type': 'application/json', ...(token ? { Authorization: `Bearer ${token}` } : {}) }, body: JSON.stringify(body) });
    if (!res.ok) return { status: res.status, events: [] };
    const text = await res.text();
    const events = text.split('\n\n').filter(Boolean).map(block => ({ event: /^event: (.*)$/m.exec(block)?.[1], data: JSON.parse(/^data: (.*)$/m.exec(block)?.[1] ?? 'null') }));
    return { status: res.status, events };
}
const meta = events => events.find(e => e.event === 'meta')?.data;
const done = events => events.find(e => e.event === 'done')?.data;

test('a general message is answered as chat, streamed word by word, without searching', async () => {
    const { events } = await send({ text: 'hi', history: [] });
    assert.equal(meta(events).mode, 'chat');
    assert.deepEqual({ route: meta(events).route.route, by: meta(events).route.by }, { route: 'chat', by: 'rule' });
    assert.equal(events.filter(e => e.event === 'token').map(e => e.data.text).join(''), 'Hello! How can I help?');
    assert.equal(done(events).mode, 'chat');
    assert.equal(searches, 0);
    assert.ok(!model.requests.includes('router'), 'a clear message needs no routing call');
    assert.deepEqual(RunModel.findById(meta(events).request_id).generation.route.route, 'chat');
});

test('a data question is answered from Wazuh: search stages, verified answer, run record notes the route', async () => {
    const { events } = await send({ text: 'show me failed logons today', history: [] });
    assert.equal(meta(events).mode, 'search');
    assert.equal(meta(events).route.by, 'rule');
    assert.ok(events.some(e => e.event === 'stage' && e.data.stage === 'searching'));
    const response = done(events).response;
    assert.equal(response.type, 'agent_response');
    assert.match(response.summary, /There were 2 failed logons\./);
    assert.ok(searches > 0);
    assert.deepEqual(RunModel.findById(response.request_id).generation.route.route, 'search');
});

test('an unclear message: the assistant says it is deciding, asks the model, and follows its choice', async () => {
    model.routerReply = 'SEARCH';
    const { events } = await send({ text: 'the firewall seems slow', history: [] });
    assert.equal(events[0].event, 'stage');
    assert.equal(events[0].data.stage, 'routing');
    assert.equal(meta(events).mode, 'search');
    assert.equal(meta(events).route.by, 'model');
    assert.ok(model.requests.includes('router'));

    model.routerReply = 'CHAT';
    const chat = await send({ text: 'the firewall seems slow', history: [] });
    assert.equal(meta(chat.events).mode, 'chat');
});

test('"Search Wazuh for this" forces a search for a message routed to chat', async () => {
    const { events } = await send({ text: 'explain what lateral movement is', history: [], force_route: 'search' });
    assert.equal(meta(events).mode, 'search');
    assert.equal(meta(events).route.by, 'user');
});

test('a search-routed message that sounds conversational is still searched (no second routing)', async () => {
    const { events } = await send({ text: 'can you check for failed logons today', history: [] });
    assert.equal(meta(events).mode, 'search');
    assert.equal(done(events).response.type, 'agent_response');
});

test('the message endpoint requires a login and a message', async () => {
    assert.equal((await send({ text: 'hi' }, null)).status, 401);
    assert.equal((await send({ text: '   ' })).status, 400);
});
