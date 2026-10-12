import fs from 'fs';
import path from 'path';
import axios from 'axios';
import { OPENSEARCH_URL, WAZUH_SERVER_API_URL } from '../config/env.js';
import db, { initDatabase } from '../config/db.js';
import { processChatQuery } from '../services/chat.service.js';
import { RunModel } from '../models/Run.js';
import { modelFor, configuredModelUrls } from '../llm/models.js';
import { currentRequestId } from '../observability/runContext.js';
import { FIXTURE_VERSION, fixtureFileName, pathFromBase, mapStrings } from './common.js';
import { redactFixture } from './redact.js';

/**
 * Live capture: runs each question through the full pipeline (live model, OpenSearch, Wazuh) and
 * records, per question, the planner output and every HTTP exchange the run made.
 *
 * Never recorded, with or without --redact: request headers (they carry the Wazuh/OpenSearch
 * credentials), the Wazuh API token, and the configured base URLs (replaced by placeholders).
 */

export const CAPTURE_USER_ID = 'user_admin_root';
const REQUIRED_SETTINGS = ['OPENSEARCH_URL', 'WAZUH_SERVER_API_URL', 'WAZUH_USER', 'WAZUH_PASSWORD', 'LLM_API_URL'];

function classify(url) {
    const value = String(url);
    if (configuredModelUrls().includes(value)) return { kind: 'llm', path: '' };
    if (WAZUH_SERVER_API_URL && value.startsWith(WAZUH_SERVER_API_URL)) {
        const requestPath = pathFromBase(value, WAZUH_SERVER_API_URL);
        return { kind: requestPath.startsWith('/security/user/authenticate') ? 'wazuh-auth' : 'wazuh', path: requestPath };
    }
    if (OPENSEARCH_URL && value.startsWith(OPENSEARCH_URL)) return { kind: 'opensearch', path: pathFromBase(value, OPENSEARCH_URL) };
    return { kind: 'other', path: '(unrecognized host; URL not recorded)' };
}

const clone = value => {
    try {
        return structuredClone(value ?? null);
    } catch {
        return '[not serializable]';
    }
};

/** Wraps axios.post/get so every call made inside a run is recorded against that run's request ID. */
export function installRecorder() {
    const calls = [];
    const inFlight = new Map();
    const originals = { post: axios.post, get: axios.get };

    const record = async (method, url, payload, invoke) => {
        const requestId = currentRequestId();
        const { kind, path: requestPath } = classify(url);
        const entry = {
            requestId,
            kind,
            method,
            path: requestPath,
            request: kind === 'wazuh-auth' ? null : clone(payload),
            startedAt: new Date().toISOString()
        };
        calls.push(entry);
        inFlight.set(requestId, (inFlight.get(requestId) || 0) + 1);
        const started = Date.now();
        try {
            const response = await invoke();
            entry.response = {
                status: response.status ?? null,
                data: kind === 'wazuh-auth' ? '[omitted: Wazuh API token]' : clone(response.data)
            };
            return response;
        } catch (error) {
            entry.error = {
                message: error.message,
                code: error.code ?? null,
                status: error.response?.status ?? null,
                data: kind === 'wazuh-auth' ? null : clone(error.response?.data)
            };
            throw error;
        } finally {
            entry.durationMs = Date.now() - started;
            inFlight.set(requestId, inFlight.get(requestId) - 1);
        }
    };

    axios.post = (url, body, config) => record('POST', url, body, () => originals.post.call(axios, url, body, config));
    axios.get = (url, config) => record('GET', url, config?.params, () => originals.get.call(axios, url, config));

    return {
        calls,
        inFlightFor: requestId => inFlight.get(requestId) || 0,
        uninstall() {
            axios.post = originals.post;
            axios.get = originals.get;
        }
    };
}

async function waitUntil(predicate, timeoutMs) {
    const deadline = Date.now() + timeoutMs;
    while (!predicate() && Date.now() < deadline) {
        await new Promise(resolve => setTimeout(resolve, 100));
    }
    return predicate();
}

function scrubBaseUrls(fixture) {
    const bases = [
        [OPENSEARCH_URL, '<OPENSEARCH_URL>'],
        [WAZUH_SERVER_API_URL, '<WAZUH_SERVER_API_URL>'],
        ...configuredModelUrls().map((url, i) => [url, i === 0 ? '<LLM_API_URL>' : `<LLM_API_URL_${i + 1}>`])
    ].filter(([base]) => typeof base === 'string' && base.length > 0)
        .sort((a, b) => b[0].length - a[0].length);
    return mapStrings(fixture, text => bases.reduce((out, [base, placeholder]) => out.split(base).join(placeholder), text));
}

async function captureOne(question, { recorder, timeoutMs }) {
    const startedAt = new Date();
    let status;
    let response = null;
    let failure = null;

    const runPromise = processChatQuery(question, [], CAPTURE_USER_ID);
    runPromise.catch(() => {}); // a timed-out run may reject later
    let timer;
    const timedOut = new Promise(resolve => { timer = setTimeout(() => resolve('timeout'), timeoutMs); });
    try {
        const outcome = await Promise.race([runPromise.then(value => ({ value })), timedOut]);
        if (outcome === 'timeout') {
            status = 'timeout';
        } else {
            response = outcome.value;
            status = response.request_id ? 'completed' : 'no_run';
        }
    } catch (error) {
        status = 'failed';
        failure = error;
    } finally {
        clearTimeout(timer);
    }

    const requestId = response?.request_id ?? failure?.requestId ?? db.prepare(
        'SELECT request_id FROM runs WHERE question = ? AND started_at >= ? ORDER BY started_at DESC LIMIT 1'
    ).get(question, startedAt.toISOString())?.request_id ?? null;

    // Let background calls of this run (the memory summary) finish so they are recorded too.
    if (requestId && status !== 'timeout') {
        await waitUntil(() => recorder.inFlightFor(requestId) === 0, 60000);
    }

    const run = requestId ? RunModel.findById(requestId) : null;
    const calls = recorder.calls
        .filter(call => requestId && call.requestId === requestId)
        .map(({ requestId: _ignored, ...call }) => call);

    return {
        fixtureVersion: FIXTURE_VERSION,
        question,
        status,
        capturedAt: startedAt.toISOString(),
        requestId,
        capture: {
            durationMs: Date.now() - startedAt.getTime(),
            timeoutMs,
            model: modelFor('report').model,
            models: { planner: modelFor('planner').model, report: modelFor('report').model, default: modelFor('default').model },
            nodeVersion: process.version,
            platform: process.platform
        },
        redaction: { applied: false },
        planner: run?.planner ?? null,
        calls,
        result: {
            runStatus: run?.status ?? null,
            responseType: response?.type ?? null,
            report: run?.reportText ?? response?.summary ?? response?.text ?? null,
            modelGenerated: run?.modelGenerated ?? null,
            generation: run?.generation ?? null,
            totalHits: response?.total_hits ?? null,
            tools: run?.tools ?? [],
            timings: run?.timings ?? null,
            errors: run?.errors ?? (failure ? [{ stage: 'capture', message: failure.message }] : [])
        }
    };
}

/**
 * Captures one fixture file per question into outDir, plus manifest.json.
 * The database in use must be a scratch database: capture writes run and memory rows.
 */
export async function captureFixtures({ questions, outDir, redact = false, redactTerms = [], timeoutMs = 600000, log = console.log }) {
    if (process.env.FIXTURES === '1') {
        throw new Error('FIXTURES=1 is set, which would replay fixtures instead of capturing live. Unset it and run again.');
    }
    const missing = REQUIRED_SETTINGS.filter(name => !process.env[name]);
    if (missing.length > 0) {
        throw new Error(`Missing required settings (set them in backend/.env): ${missing.join(', ')}`);
    }

    initDatabase();
    fs.mkdirSync(outDir, { recursive: true });
    const recorder = installRecorder();
    const summaries = [];
    try {
        for (const [index, question] of questions.entries()) {
            log(`[Capture] (${index + 1}/${questions.length}) "${question}"`);
            let fixture = scrubBaseUrls(await captureOne(question, { recorder, timeoutMs }));
            if (redact) fixture = redactFixture(fixture, { extraTerms: redactTerms });

            const file = path.join(outDir, fixtureFileName(question));
            fs.writeFileSync(file, JSON.stringify(fixture, null, 2) + '\n');

            const summary = {
                question,
                file: path.basename(file),
                status: fixture.status,
                requestId: fixture.requestId,
                plannerSource: fixture.planner?.source ?? null,
                opensearchCalls: fixture.calls.filter(c => c.kind === 'opensearch').length,
                wazuhCalls: fixture.calls.filter(c => c.kind === 'wazuh').length,
                llmCalls: fixture.calls.filter(c => c.kind === 'llm').length,
                failedCalls: fixture.calls.filter(c => c.error).length,
                totalHits: fixture.result.totalHits,
                modelGenerated: fixture.result.modelGenerated,
                errors: fixture.result.errors.length,
                bytes: fs.statSync(file).size
            };
            log(`[Capture]   -> ${summary.file}: status=${summary.status} planner=${summary.plannerSource} opensearch=${summary.opensearchCalls} wazuh=${summary.wazuhCalls} llm=${summary.llmCalls} failedCalls=${summary.failedCalls} hits=${summary.totalHits} model_generated=${summary.modelGenerated} errors=${summary.errors} size=${(summary.bytes / 1024 / 1024).toFixed(2)}MB`);
            summaries.push(summary);
        }
    } finally {
        recorder.uninstall();
    }

    fs.writeFileSync(path.join(outDir, 'manifest.json'), JSON.stringify({
        fixtureVersion: FIXTURE_VERSION,
        capturedAt: new Date().toISOString(),
        redacted: redact,
        fixtures: summaries
    }, null, 2) + '\n');
    return summaries;
}
