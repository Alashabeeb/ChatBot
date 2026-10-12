import { test, after, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'child_process';
import http from 'http';
import crypto from 'crypto';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { fileURLToPath } from 'url';
import Database from 'better-sqlite3';
import axios from 'axios';
import { setTestEnv, stubBackends, flushBackgroundWork, USER_ID } from './helpers.js';
import { isAggregationRequest } from '../scripts/lib/fakeAggregations.js';

setTestEnv();
const { initDatabase } = await import('../src/config/db.js');
const { captureFixtures } = await import('../src/recording/capture.js');
const { redactFixture } = await import('../src/recording/redact.js');
const { DEFAULT_QUESTIONS, fixtureFileName } = await import('../src/recording/common.js');
const { processChatQuery } = await import('../src/services/chat.service.js');
const { RunModel } = await import('../src/models/Run.js');

initDatabase();

const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'fixtures-test-'));
after(() => fs.rmSync(tmpDir, { recursive: true, force: true }));
afterEach(() => {
    delete process.env.FIXTURES;
    delete process.env.FIXTURES_DIR;
});

const backendDir = fileURLToPath(new URL('..', import.meta.url));
const QUESTION = DEFAULT_QUESTIONS[1]; // 'anything unusual on the AD servers'

const PLAN = {
    thought: 'Look for unusual events on AD servers and check their agents.',
    tools: [
        { tool: 'searchSecurityLogs', parameters: { timeRange: 'now-24h', intent: 'alerts', extractedIPs: [], minSeverity: null, cleanedSearchText: 'unusual ad servers' } },
        { tool: 'getEndpointStatus', parameters: { target: 'agents', status: 'any' } }
    ]
};
const LOGS = [
    { '@timestamp': '2026-09-16T08:00:00Z', rule: { level: 12, description: 'Multiple Windows logon failures' }, agent: { name: 'DC01', ip: '10.20.0.5' }, data: { win: { eventdata: { targetUserName: 'jdoe', ipAddress: '185.220.101.7' } } }, full_log: 'An account failed to log on. Account: jdoe Workstation: DC01 Source: 10.20.0.5' }
];
const AGENTS = [{ id: '003', name: 'DC01', status: 'active', ip: '10.20.0.5' }];

const listFixtureCalls = file => JSON.parse(fs.readFileSync(file, 'utf8'));

async function capture(t, outDir, options = {}) {
    const stubs = stubBackends(t, { llm: { plan: PLAN, report: '**Executive Summary**: 1 alert on DC01 for jdoe.' }, logs: LOGS, agents: AGENTS });
    t.mock.method(console, 'log', () => {});
    t.mock.method(console, 'warn', () => {});
    const summaries = await captureFixtures({ questions: [QUESTION], outDir, timeoutMs: 10000, log: () => {}, ...options });
    await flushBackgroundWork();
    console.log.mock.restore();
    console.warn.mock.restore();
    return { summaries, stubs, file: path.join(outDir, fixtureFileName(QUESTION)) };
}

/** In replay, any non-model network call is a failure; model calls fail as they would with no model here. */
function forbidNetwork(t) {
    const attempted = [];
    const refuse = (method) => async (url, bodyOrConfig) => {
        attempted.push({ method, url, isModel: Boolean(bodyOrConfig?.messages) });
        throw new Error(`network call attempted during replay: ${method} ${url}`);
    };
    t.mock.method(axios, 'post', refuse('POST'));
    t.mock.method(axios, 'get', refuse('GET'));
    return attempted;
}

test('capture writes one fixture per question: planner output, exact OpenSearch query, raw responses; no credentials', async (t) => {
    const outDir = path.join(tmpDir, 'capture');
    const { summaries, stubs, file } = await capture(t, outDir);

    assert.equal(summaries.length, 1);
    assert.equal(summaries[0].status, 'completed');
    const fixture = listFixtureCalls(file);

    assert.equal(fixture.question, QUESTION);
    assert.equal(fixture.status, 'completed');
    assert.equal(fixture.planner.source, 'model');
    assert.equal(fixture.planner.rawOutput, JSON.stringify(PLAN));
    assert.deepEqual(fixture.planner.tools, PLAN.tools);

    // One planned search = two OpenSearch searches (non-firewall and firewall halves) and, since Phase 5,
    // an aggregation request for each; all recorded exactly.
    const search = fixture.calls.filter(c => c.kind === 'opensearch' && !isAggregationRequest(c.request));
    assert.equal(search.length, 2);
    assert.deepEqual(search.map(c => JSON.stringify(c.request)).sort(), stubs.searchCalls.map(c => JSON.stringify(c.body)).sort(),
        'recorded queries must be exactly what was sent');
    const aggs = fixture.calls.filter(c => c.kind === 'opensearch' && isAggregationRequest(c.request));
    assert.deepEqual(aggs.map(c => JSON.stringify(c.request)).sort(), stubs.aggCalls.map(c => JSON.stringify(c.body)).sort());
    assert.ok(aggs.every(c => c.response.data.aggregations.current), 'aggregation responses recorded');
    for (const call of search) assert.equal(call.path, '/wazuh-alerts-*/_search');
    const nonFirewall = search.find(c => !JSON.stringify(c.request.query.bool.must).includes('"iptables"'));
    assert.deepEqual(nonFirewall.response.data.hits.hits.map(h => h._source), LOGS, 'raw OpenSearch response recorded');

    const wazuh = fixture.calls.filter(c => c.kind === 'wazuh');
    assert.equal(wazuh.length, 1);
    assert.equal(wazuh[0].path, '/agents');
    assert.deepEqual(wazuh[0].request, stubs.wazuhCalls[0].params);
    assert.deepEqual(wazuh[0].response.data.data.affected_items, AGENTS);

    // Credentials and hosts never recorded.
    const text = fs.readFileSync(file, 'utf8');
    const basic = Buffer.from(`${process.env.WAZUH_USER}:${process.env.WAZUH_PASSWORD}`).toString('base64');
    assert.ok(!text.includes(basic), 'Basic auth credentials must not be recorded');
    assert.ok(!text.includes('stub-wazuh-token'), 'Wazuh API token must not be recorded');
    assert.doesNotMatch(text, /Authorization/i);
    for (const base of [process.env.OPENSEARCH_URL, process.env.WAZUH_SERVER_API_URL, process.env.LLM_API_URL]) {
        assert.ok(!text.includes(base), `base URL ${base} must not be recorded`);
    }
    const auth = fixture.calls.find(c => c.kind === 'wazuh-auth');
    assert.equal(auth.response.data, '[omitted: Wazuh API token]');

    assert.equal(fixture.redaction.applied, false, 'redaction is off by default');
    assert.ok(text.includes('jdoe') && text.includes('10.20.0.5'), 'unredacted capture keeps real values');
    assert.ok(fs.existsSync(path.join(outDir, 'manifest.json')));
});

test('replay (FIXTURES=1): planner and SIEM responses come from the fixture, the same query is rebuilt, no network', async (t) => {
    const outDir = path.join(tmpDir, 'roundtrip');
    const { file } = await capture(t, outDir);
    const fixture = listFixtureCalls(file);
    axios.post.mock.restore();
    axios.get.mock.restore();

    process.env.FIXTURES = '1';
    process.env.FIXTURES_DIR = outDir;
    const attempted = forbidNetwork(t);
    t.mock.method(console, 'log', () => {});
    t.mock.method(console, 'warn', () => {});
    t.mock.method(console, 'error', () => {});

    const response = await processChatQuery(QUESTION, [], USER_ID);
    await flushBackgroundWork();
    const run = RunModel.findById(response.request_id);

    // No planner model call, no OpenSearch or Wazuh call. Only the report/memory model calls were attempted.
    assert.ok(attempted.every(a => a.isModel), `unexpected network calls: ${JSON.stringify(attempted.filter(a => !a.isModel))}`);
    assert.equal(run.planner.source, 'fixture_replay');
    assert.equal(run.planner.replayedFrom.capturedSource, 'model');
    assert.deepEqual(run.planner.tools, fixture.planner.tools);
    assert.equal(run.planner.rawOutput, fixture.planner.rawOutput);

    // The query rebuilt from the replayed plan is exactly the captured one.
    const searches = run.tools.filter(tool => tool.tool === 'searchSecurityLogs');
    const replayedQueries = searches.map(tool => JSON.stringify(tool.query)).sort();
    const recordedQueries = fixture.calls.filter(c => c.kind === 'opensearch' && !isAggregationRequest(c.request)).map(c => JSON.stringify(c.request)).sort();
    assert.equal(replayedQueries.length, 2);
    assert.deepEqual(replayedQueries, recordedQueries);
    // So are the aggregation requests, answered from the recording too.
    assert.ok(searches.every(tool => tool.aggregations.available), JSON.stringify(searches.map(s => s.aggregations)));
    assert.deepEqual(searches.map(tool => JSON.stringify(tool.aggregations.query)).sort(),
        fixture.calls.filter(c => c.kind === 'opensearch' && isAggregationRequest(c.request)).map(c => JSON.stringify(c.request)).sort());

    // Downstream data is the captured raw data.
    assert.equal(run.status, 'completed');
    assert.equal(response.total_hits, fixture.result.totalHits);
    assert.deepEqual(response.raw_logs.searchSecurityLogs, LOGS);
    assert.deepEqual(response.raw_logs.getEndpointStatus, AGENTS);
    assert.ok(!run.errors.some(e => /Fixture miss/.test(e.message)), JSON.stringify(run.errors));
    assert.match(response.footer, /Plan: replayed from fixture/);
});

test('replay fails loudly when the rebuilt query differs from the capture (no silent live call)', async (t) => {
    const outDir = path.join(tmpDir, 'diverged');
    const { file } = await capture(t, outDir);
    axios.post.mock.restore();
    axios.get.mock.restore();

    // Simulate query construction drift: the recorded query no longer matches what the code builds.
    const fixture = listFixtureCalls(file);
    fixture.calls.find(c => c.kind === 'opensearch').request.size = 50;
    fs.writeFileSync(file, JSON.stringify(fixture));

    process.env.FIXTURES = '1';
    process.env.FIXTURES_DIR = outDir;
    const attempted = forbidNetwork(t);
    t.mock.method(console, 'log', () => {});
    t.mock.method(console, 'warn', () => {});
    t.mock.method(console, 'error', () => {});

    const response = await processChatQuery(QUESTION, [], USER_ID);
    await flushBackgroundWork();
    const run = RunModel.findById(response.request_id);

    const miss = run.errors.find(e => e.stage === 'tool' && e.tool === 'searchSecurityLogs');
    assert.ok(miss, JSON.stringify(run.errors));
    assert.match(miss.message, /Fixture miss in .*opensearch call to \/wazuh-alerts-\*\/_search/);
    assert.ok(attempted.every(a => a.isModel), 'a fixture miss must not fall through to a live SIEM call');
});

test('replay with no fixture for the question fails the run instead of calling the model planner', async (t) => {
    const outDir = path.join(tmpDir, 'empty');
    fs.mkdirSync(outDir, { recursive: true });
    process.env.FIXTURES = '1';
    process.env.FIXTURES_DIR = outDir;
    const attempted = forbidNetwork(t);
    t.mock.method(console, 'log', () => {});
    t.mock.method(console, 'error', () => {});

    const error = await processChatQuery('show me failed logons today', [], USER_ID).catch(e => e);
    assert.ok(error instanceof Error);
    assert.match(error.message, /no fixture for the question "show me failed logons today"/);
    assert.equal(RunModel.findById(error.requestId).status, 'failed');
    assert.deepEqual(attempted, []);
});

test('without FIXTURES=1 the planner calls the model as before', async (t) => {
    const { llmCalls } = stubBackends(t, { llm: { plan: PLAN, report: 'r' }, logs: LOGS, agents: AGENTS });
    t.mock.method(console, 'log', () => {});
    const response = await processChatQuery(QUESTION, [], USER_ID);
    await flushBackgroundWork();
    assert.ok(llmCalls.some(m => m[0].content.includes('Planning Engine')));
    assert.equal(RunModel.findById(response.request_id).planner.source, 'model');
});

test('redaction: masks internal IPs, hostnames and usernames consistently; keeps public IPs, keys and the question', () => {
    const fixture = {
        fixtureVersion: 1,
        question: 'anything unusual on the AD servers',
        calls: [{
            kind: 'opensearch',
            response: {
                data: {
                    hits: {
                        hits: [{
                            _source: {
                                agent: { name: 'DC01.corp.example', ip: '10.20.0.5' },
                                predecoder: { hostname: 'fs02' },
                                data: { srcuser: 'CORP\\jdoe', win: { eventdata: { targetUserName: 'asmith', ipAddress: '185.220.101.7', workstationName: 'LAPTOP-77' } } },
                                full_log: 'Logon failure for asmith from 10.20.0.5 (185.220.101.7) on dc01.corp.example via LAPTOP-77; SYSTEM service; ip 192.168.1.10',
                                rule: { description: 'jdoe triggered rule' }
                            }
                        }]
                    }
                }
            }
        }],
        result: { report: 'User jdoe on DC01.corp.example and host fs02 from 172.16.4.4; secret project ACME-X' }
    };

    const out = redactFixture(fixture, { extraTerms: ['ACME-X'] });
    const text = JSON.stringify(out);

    for (const secret of ['10.20.0.5', '192.168.1.10', '172.16.4.4', 'DC01.corp.example', 'dc01.corp.example', 'fs02', 'jdoe', 'asmith', 'LAPTOP-77', 'CORP\\\\', 'ACME-X']) {
        assert.ok(!text.includes(secret), `${secret} should be masked`);
    }
    assert.ok(text.includes('185.220.101.7'), 'public IPs are kept');
    assert.ok(text.includes('SYSTEM'), 'generic account names are not masked');
    assert.equal(out.question, fixture.question);
    const source = out.calls[0].response.data.hits.hits[0]._source;
    assert.deepEqual(Object.keys(source.data.win.eventdata), ['targetUserName', 'ipAddress', 'workstationName'], 'keys untouched');
    // Consistent tokens: the same user in a field, in full_log and in the report map to one token.
    assert.equal(source.data.win.eventdata.targetUserName, source.full_log.match(/for (\S+) from/)[1]);
    assert.ok(out.result.report.includes(source.data.srcuser.split('\\')[1]));
    assert.equal(out.redaction.applied, true);
    assert.deepEqual(Object.keys(out.redaction.counts), ['internalIps', 'hosts', 'users', 'extraTerms']);
});

test('capture CLI: --help works, refuses under FIXTURES=1, and --check reports missing settings without writing anything', () => {
    const script = path.join(backendDir, 'scripts', 'captureFixtures.js');
    const emptyCwd = fs.mkdtempSync(path.join(tmpDir, 'cli-'));
    const outDir = path.join(emptyCwd, 'fixtures');
    // Strip settings inherited from this test process; backend/.env does not exist on this machine.
    const env = { ...process.env };
    for (const key of ['OPENSEARCH_URL', 'WAZUH_SERVER_API_URL', 'WAZUH_USER', 'WAZUH_PASSWORD', 'LLM_API_URL', 'FIXTURES']) delete env[key];

    const help = spawnSync(process.execPath, [script, '--help'], { cwd: emptyCwd, env, encoding: 'utf8' });
    assert.equal(help.status, 0, help.stderr);
    assert.match(help.stdout, /--redact/);

    const replaying = spawnSync(process.execPath, [script, '--out', outDir], { cwd: emptyCwd, env: { ...env, FIXTURES: '1' }, encoding: 'utf8' });
    assert.equal(replaying.status, 1);
    assert.match(replaying.stderr, /FIXTURES=1 is set/);

    const envFile = path.join(backendDir, '.env');
    if (!fs.existsSync(envFile)) {
        const check = spawnSync(process.execPath, [script, '--check', '--out', outDir], { cwd: emptyCwd, env, encoding: 'utf8' });
        assert.equal(check.status, 1, check.stdout + check.stderr);
        assert.match(check.stdout, /OPENSEARCH_URL=MISSING/);
        assert.match(check.stdout, /NOT READY/);

        const run = spawnSync(process.execPath, [script, '--out', outDir], { cwd: emptyCwd, env, encoding: 'utf8' });
        assert.equal(run.status, 1);
        assert.match(run.stderr, /Missing required settings/);
    }
    assert.ok(!fs.existsSync(outDir), 'nothing written when settings are missing');
});

test('dbReport is read-only: reports counts, date range and usernames without changing the file', () => {
    const dbPath = path.join(tmpDir, 'report.db');
    const seed = new Database(dbPath);
    seed.exec(`
        CREATE TABLE users (id TEXT PRIMARY KEY, username TEXT, role TEXT, created_at TEXT);
        CREATE TABLE messages (id TEXT PRIMARY KEY, created_at TEXT);
        CREATE TABLE memories (id TEXT PRIMARY KEY);
        INSERT INTO users VALUES ('u1', 'admin', 'admin', '2026-01-01T00:00:00Z'), ('u2', 'analyst1', 'user', '2026-02-01T00:00:00Z');
        INSERT INTO messages VALUES ('m1', '2026-03-01T10:00:00Z'), ('m2', '2026-09-15T18:30:00Z'), ('m3', '2026-05-05T00:00:00Z');
        INSERT INTO memories VALUES ('x1');
    `);
    seed.close();
    const hash = () => crypto.createHash('sha256').update(fs.readFileSync(dbPath)).digest('hex');
    const before = hash();

    const result = spawnSync(process.execPath, [path.join(backendDir, 'scripts', 'dbReport.js'), '--db', dbPath], { encoding: 'utf8' });
    assert.equal(result.status, 0, result.stderr);
    assert.match(result.stdout, /messages: 3/);
    assert.match(result.stdout, /memories: 1/);
    assert.match(result.stdout, /users:\s+2/);
    assert.match(result.stdout, /message date range: 2026-03-01T10:00:00Z -> 2026-09-15T18:30:00Z/);
    assert.match(result.stdout, /admin \(admin/);
    assert.match(result.stdout, /analyst1 \(user/);
    assert.match(result.stdout, /messages.request_id=no, runs table=no/);
    assert.equal(hash(), before, 'database file must be unchanged');
    assert.ok(!fs.existsSync(`${dbPath}-wal`), 'no WAL file created');

    const missing = spawnSync(process.execPath, [path.join(backendDir, 'scripts', 'dbReport.js'), '--db', path.join(tmpDir, 'nope.db')], { encoding: 'utf8' });
    assert.equal(missing.status, 1);
    assert.ok(!fs.existsSync(path.join(tmpDir, 'nope.db')), 'must not create a database');
});

test('no source directory is named fixtures/, quarantine/ or baseline/ (those names are gitignored everywhere)', () => {
    const offenders = [];
    const walk = dir => {
        for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
            if (!entry.isDirectory() || entry.name === 'node_modules') continue;
            const full = path.join(dir, entry.name);
            if (['fixtures', 'quarantine', 'baseline'].includes(entry.name)) offenders.push(path.relative(backendDir, full));
            else walk(full);
        }
    };
    for (const dir of ['src', 'scripts', 'test', '../evals']) walk(path.join(backendDir, dir));
    assert.deepEqual(offenders, [], 'code in these directories would never be committed');
});

test('backupDb: online backup while a writer holds uncheckpointed WAL changes; verified; never overwrites', () => {
    const dir = fs.mkdtempSync(path.join(tmpDir, 'backup-'));
    const dbPath = path.join(dir, 'soc_chatbot.db');
    const writer = new Database(dbPath);
    try {
        writer.pragma('journal_mode = WAL');
        writer.pragma('wal_autocheckpoint = 0');
        writer.exec("CREATE TABLE users (id TEXT); CREATE TABLE messages (id TEXT); INSERT INTO users VALUES ('u1'); INSERT INTO messages VALUES ('m1'), ('m2');");
        assert.ok(fs.statSync(`${dbPath}-wal`).size > 0, 'changes are still in the WAL');

        const script = path.join(backendDir, 'scripts', 'backupDb.js');
        const outPath = path.join(dir, 'backup.db');
        const result = spawnSync(process.execPath, [script, '--db', dbPath, '--out', outPath], { encoding: 'utf8' });
        assert.equal(result.status, 0, result.stdout + result.stderr);
        assert.match(result.stdout, /Backup OK/);
        assert.match(result.stdout, /messages: 2 rows/);

        const copy = new Database(outPath, { readonly: true });
        assert.equal(copy.prepare('SELECT COUNT(*) AS n FROM messages').get().n, 2);
        copy.close();

        const again = spawnSync(process.execPath, [script, '--db', dbPath, '--out', outPath], { encoding: 'utf8' });
        assert.equal(again.status, 1);
        assert.match(again.stderr, /Refusing to overwrite/);
    } finally {
        writer.close();
    }
});

test('replay CLI: a search that failed at capture and fails identically in replay counts as matched, not diverged', async (t) => {
    const fixturesDir = path.join(tmpDir, 'failed-search');
    const { file } = await capture(t, fixturesDir);
    const fixture = listFixtureCalls(file);
    const isFirewall = c => c.kind === 'opensearch' && JSON.stringify(c.request.query.bool.must).includes('"iptables"');
    const firewall = fixture.calls.find(c => isFirewall(c) && !isAggregationRequest(c.request));
    // A search that fails never sends its aggregation request, so a real capture would not contain it.
    fixture.calls = fixture.calls.filter(c => !(isFirewall(c) && isAggregationRequest(c.request)));
    delete firewall.response;
    firewall.error = { message: 'Request failed with status code 503', code: 'ERR_BAD_RESPONSE', status: 503, data: { error: 'unavailable' } };
    fs.writeFileSync(file, JSON.stringify(fixture));

    const env = { PATH: process.env.PATH, JWT_SECRET: 'baseline-test-secret-0123456789abcdefghijkl', OPENSEARCH_URL: 'http://opensearch.test', WAZUH_SERVER_API_URL: 'http://wazuh.test' };
    const run = spawnSync(process.execPath, [path.join(backendDir, 'scripts', 'replayFixtures.js'), '--dir', fixturesDir], { cwd: os.tmpdir(), env, encoding: 'utf8' });
    assert.equal(run.status, 0, run.stdout + run.stderr);
    assert.match(run.stdout, /1\/1 matched the capture/);

    // A failed search whose query changed is still a divergence (a fixture miss, never a live call).
    firewall.request.size = 999;
    fs.writeFileSync(file, JSON.stringify(fixture));
    const changed = spawnSync(process.execPath, [path.join(backendDir, 'scripts', 'replayFixtures.js'), '--dir', fixturesDir], { cwd: os.tmpdir(), env, encoding: 'utf8' });
    assert.equal(changed.status, 1, changed.stdout + changed.stderr);
    assert.match(changed.stdout, /DIVERGED/);
});

test('replay CLI: a fixture captured before Phase 5 (no aggregation requests) still matches, using sample counts', async (t) => {
    const fixturesDir = path.join(tmpDir, 'pre-phase5');
    const { file } = await capture(t, fixturesDir);
    const fixture = listFixtureCalls(file);
    fixture.calls = fixture.calls.filter(c => !(c.kind === 'opensearch' && isAggregationRequest(c.request)));
    fs.writeFileSync(file, JSON.stringify(fixture));
    const outDir = path.join(tmpDir, 'pre-phase5-out');
    const env = { PATH: process.env.PATH, JWT_SECRET: 'baseline-test-secret-0123456789abcdefghijkl', OPENSEARCH_URL: 'http://opensearch.test', WAZUH_SERVER_API_URL: 'http://wazuh.test' };
    const run = spawnSync(process.execPath, [path.join(backendDir, 'scripts', 'replayFixtures.js'), '--dir', fixturesDir, '--out', outDir], { cwd: os.tmpdir(), env, encoding: 'utf8' });
    assert.equal(run.status, 0, run.stdout + run.stderr);
    assert.match(run.stdout, /1\/1 matched the capture/);
    const record = JSON.parse(fs.readFileSync(path.join(outDir, fixtureFileName(QUESTION)), 'utf8'));
    assert.match(record.replay.report, /\*\*Counts\*\* come from the records retrieved/);

    // A recorded aggregation request that today's code no longer builds is a divergence.
    const withAggs = listFixtureCalls(path.join(path.join(tmpDir, 'pre-phase5'), fixtureFileName(QUESTION)));
    const recaptured = await capture(t, path.join(tmpDir, 'agg-changed'));
    const changed = listFixtureCalls(recaptured.file);
    changed.calls.find(c => c.kind === 'opensearch' && isAggregationRequest(c.request)).request.aggs.current.aggs.by_rule.terms.size = 7;
    fs.writeFileSync(recaptured.file, JSON.stringify(changed));
    const diverged = spawnSync(process.execPath, [path.join(backendDir, 'scripts', 'replayFixtures.js'), '--dir', path.join(tmpDir, 'agg-changed')], { cwd: os.tmpdir(), env, encoding: 'utf8' });
    assert.equal(diverged.status, 1, diverged.stdout + diverged.stderr);
    assert.match(diverged.stdout, /aggregation requests differ from capture/);
    assert.ok(withAggs.calls.length > 0);
});

test('replay CLI --allow-model --live-planner: the configured models answer; the record keeps timings, verification counts and model names', async (t) => {
    const fixturesDir = path.join(tmpDir, 'compare-src');
    await capture(t, fixturesDir);
    // A local stand-in model (never an external one): plans like the capture, reports one cited claim.
    const requests = [];
    const model = http.createServer((req, res) => {
        let body = '';
        req.on('data', d => { body += d; });
        req.on('end', () => {
            const parsed = JSON.parse(body);
            requests.push({ path: req.url, model: parsed.model, system: parsed.messages[0].content.slice(0, 40) });
            const system = parsed.messages[0].content;
            const content = system.includes('Planning Engine') ? JSON.stringify(PLAN)
                : system.includes('Reasoning Engine') ? JSON.stringify({ answer: [{ text: 'Alerts on DC01.', cite: [{ kind: 'agent', ref: 'DC01' }] }] })
                : '{"summary":"s","keyEntities":[]}';
            res.writeHead(200, { 'Content-Type': 'application/json' }).end(JSON.stringify({ choices: [{ message: { content } }] }));
        });
    });
    await new Promise(resolve => model.listen(0, '127.0.0.1', resolve));
    t.after(() => model.close());
    const base = `http://127.0.0.1:${model.address().port}`;
    const env = {
        PATH: process.env.PATH, JWT_SECRET: 'baseline-test-secret-0123456789abcdefghijkl', OPENSEARCH_URL: 'http://opensearch.test', WAZUH_SERVER_API_URL: 'http://wazuh.test',
        LLM_API_URL: `${base}/default`, PLANNER_LLM_API_URL: `${base}/planner`, PLANNER_LLM_MODEL: 'cand-planner',
        REPORT_LLM_API_URL: `${base}/report`, REPORT_LLM_MODEL: 'cand-report'
    };
    const outDir = path.join(tmpDir, 'compare-out');
    const run = await new Promise(resolve => {
        const child = spawn(process.execPath, [path.join(backendDir, 'scripts', 'replayFixtures.js'), '--dir', fixturesDir, '--out', outDir, '--allow-model', '--live-planner'], { cwd: os.tmpdir(), env });
        let output = '';
        child.stdout.on('data', d => { output += d; });
        child.stderr.on('data', d => { output += d; });
        child.on('close', status => resolve({ status, output }));
    });
    assert.equal(run.status, 0, run.output);
    assert.deepEqual([...new Set(requests.filter(r => r.path !== '/default').map(r => `${r.path} ${r.model}`))].sort(), ['/planner cand-planner', '/report cand-report']);

    const record = JSON.parse(fs.readFileSync(path.join(outDir, fixtureFileName(QUESTION)), 'utf8'));
    assert.equal(record.replay.status, 'matched', 'the live plan matched the captured searches');
    assert.equal(record.replay.livePlanner, true);
    assert.equal(record.replay.modelGenerated, true);
    assert.match(record.replay.report, /Alerts on DC01\./);
    assert.deepEqual(record.replay.models, { planner: 'cand-planner', report: 'cand-report' });
    assert.deepEqual(record.replay.grounding, { claims: 1, shown: 1, dropped: 0, droppedReasons: [] });
    assert.equal(typeof record.replay.timings.reasoningDuration, 'number');
    assert.equal(typeof record.replay.timings.planningDuration, 'number');
    assert.ok(!JSON.stringify(record).includes(base), 'model URLs are never written to the record');
});

test('replay refuses a SYNTHETIC case placed among real fixtures (synthetic cases are for the checker only)', async (t) => {
    const outDir = path.join(tmpDir, 'synthetic-guard');
    const { file } = await capture(t, outDir);
    const fixture = listFixtureCalls(file);
    fs.writeFileSync(file, JSON.stringify({ ...fixture, synthetic: true }));
    process.env.FIXTURES = '1';
    process.env.FIXTURES_DIR = outDir;
    const { loadFixtures } = await import('../src/recording/replay.js');
    assert.throws(() => loadFixtures(), /SYNTHETIC/);
});

test('replay CLI --out writes one baseline record per question: captured answer and evidence, plus the replay verdict; no model call', async (t) => {
    const fixturesDir = path.join(tmpDir, 'baseline-src');
    const { file } = await capture(t, fixturesDir);
    const fixture = listFixtureCalls(file);
    const outDir = path.join(tmpDir, 'baseline-out');

    // A model endpoint that is configured and reachable must still not be called.
    let modelRequests = 0;
    const model = http.createServer((req, res) => { modelRequests++; res.writeHead(500).end(); });
    await new Promise(resolve => model.listen(0, '127.0.0.1', resolve));
    t.after(() => model.close());
    const env = {
        PATH: process.env.PATH, JWT_SECRET: 'baseline-test-secret-0123456789abcdefghijkl', OPENSEARCH_URL: 'http://opensearch.test',
        WAZUH_SERVER_API_URL: 'http://wazuh.test', LLM_API_URL: `http://127.0.0.1:${model.address().port}/v1/chat/completions`,
        // Per-role endpoints (Phase 6) must be disabled too.
        REPORT_LLM_API_URL: `http://127.0.0.1:${model.address().port}/report`, PLANNER_LLM_API_URL: `http://127.0.0.1:${model.address().port}/planner`
    };
    const run = await new Promise(resolve => {
        const child = spawn(process.execPath, [path.join(backendDir, 'scripts', 'replayFixtures.js'), '--dir', fixturesDir, '--out', outDir], { cwd: os.tmpdir(), env });
        let output = '';
        child.stdout.on('data', d => { output += d; });
        child.stderr.on('data', d => { output += d; });
        child.on('close', status => resolve({ status, output }));
    });
    assert.equal(run.status, 0, run.output);
    assert.equal(modelRequests, 0, 'replay must not call the model unless --allow-model is given');

    const record = JSON.parse(fs.readFileSync(path.join(outDir, fixtureFileName(QUESTION)), 'utf8'));
    assert.equal(record.question, QUESTION);
    assert.equal(record.result.report, fixture.result.report, 'the baseline scores the answer production gave at capture');
    assert.deepEqual(record.calls, fixture.calls, 'evidence is the captured evidence');
    assert.equal(record.replay.status, 'matched');
    assert.deepEqual(record.replay.problems, []);
    assert.equal(record.replay.modelGenerated, false, 'no model is reachable in replay; the replayed report is the fallback');
    assert.ok(!('synthetic' in record));
    assert.ok(fs.existsSync(path.join(outDir, 'manifest.json')));
});

test('findRun is read-only and shows what is needed to turn a bad answer into a test', async (t) => {
    // A real run record, written by the real pipeline into a file database.
    const dbPath = path.join(tmpDir, 'findrun.db');
    const child = spawnSync(process.execPath, ['-e', `
        process.env.SOC_DB_PATH = ${JSON.stringify(dbPath)};
        const { initDatabase, default: db } = await import(${JSON.stringify(path.join(backendDir, 'src/config/db.js'))});
        const { RunModel } = await import(${JSON.stringify(path.join(backendDir, 'src/models/Run.js'))});
        initDatabase();
        RunModel.start({ requestId: 'req-abc', userId: 'user_admin_root', instanceId: 'i1', question: 'show me failed logons today', startedAt: '2026-10-12T08:00:00.000Z' });
        RunModel.finish('req-abc', { status: 'completed', planner: { source: 'model', tools: [] }, tools: [{ tool: 'searchSecurityLogs', totalHits: 3 }],
            reportText: 'The answer.', timings: { totalDuration: 5, reasoningDuration: 4100, reportPromptChars: 12345 },
            errors: [{ stage: 'llm', message: 'The model server returned HTTP 400: maximum context length is 8192 tokens', at: '2026-10-12T08:00:04.000Z' }], modelGenerated: true,
            generation: { planner: 'model', report: 'model', model: 'm' },
            grounding: { claims: 2, shown: 1, dropped: [{ section: 'findings', text: 'From 10.9.9.9.', reason: 'IP 10.9.9.9 is not in the evidence' }] },
            completedAt: '2026-10-12T08:00:05.000Z' });
        db.close();
    `], { encoding: 'utf8', env: { ...process.env, JWT_SECRET: 'x'.repeat(40) }, input: '' });
    assert.equal(child.status, 0, child.stderr);
    const hash = () => crypto.createHash('sha256').update(fs.readFileSync(dbPath)).digest('hex');
    const before = hash();
    const script = path.join(backendDir, 'scripts', 'findRun.js');

    const byText = spawnSync(process.execPath, [script, '--db', dbPath, '--search', 'failed logons'], { encoding: 'utf8' });
    assert.equal(byText.status, 0, byText.stderr);
    assert.match(byText.stdout, /req-abc .*show me failed logons today/);

    const byId = spawnSync(process.execPath, [script, '--db', dbPath, '--request-id', 'req-abc'], { encoding: 'utf8' });
    assert.equal(byId.status, 0, byId.stderr);
    for (const expected of [/question: show me failed logons today/, /report: model/, /The answer\./, /dropped \(1\)/, /IP 10\.9\.9\.9 is not in the evidence/, /searchSecurityLogs/,
        /errors \(1\):/, /\[llm\] The model server returned HTTP 400: maximum context length is 8192 tokens/, /model call: 4,100 ms/, /report prompt: 12,345 characters/]) {
        assert.match(byId.stdout, expected);
    }
    assert.equal(hash(), before, 'database file must be unchanged');
    assert.equal(spawnSync(process.execPath, [script, '--db', dbPath, '--request-id', 'nope'], { encoding: 'utf8' }).status, 2);
});
