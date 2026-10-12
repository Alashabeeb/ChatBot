import fs from 'fs';
import path from 'path';
import { createHash } from 'crypto';
import { DEFAULT_FIXTURES_DIR, FIXTURE_VERSION, normalizeQuestion, canonicalJson } from './common.js';
import { currentRunQuestion, runLog } from '../observability/runContext.js';

/**
 * Replay mode (FIXTURES=1): the planner and the OpenSearch/Wazuh clients return what was recorded by
 * scripts/captureFixtures.js instead of calling the model and the APIs. Without FIXTURES=1 nothing
 * here is used. Fixtures are read from FIXTURES_DIR, default backend/fixtures/.
 *
 * Replay never falls back to a live call: anything without a matching recording throws
 * FixtureMissError, so divergence from the capture is loud instead of silently "fixed".
 */

export class FixtureMissError extends Error {
    constructor(message) {
        super(message);
        this.name = 'FixtureMissError';
    }
}

export function fixturesEnabled() {
    return process.env.FIXTURES === '1';
}

export function fixturesDir() {
    return process.env.FIXTURES_DIR ? path.resolve(process.env.FIXTURES_DIR) : DEFAULT_FIXTURES_DIR;
}

let cache = { signature: null, byQuestion: null };

/** Loads every fixture in the directory, keyed by normalized question. Re-reads when files change. */
export function loadFixtures() {
    const dir = fixturesDir();
    if (!fs.existsSync(dir)) {
        throw new FixtureMissError(`FIXTURES=1 but the fixtures directory does not exist: ${dir}`);
    }
    const names = fs.readdirSync(dir).filter(n => n.endsWith('.json') && n !== 'manifest.json').sort();
    const signature = dir + '|' + names.map(n => {
        const stat = fs.statSync(path.join(dir, n));
        return `${n}:${stat.size}:${stat.mtimeMs}`;
    }).join('|');
    if (cache.signature === signature) return cache.byQuestion;

    const byQuestion = new Map();
    for (const name of names) {
        const fixture = JSON.parse(fs.readFileSync(path.join(dir, name), 'utf8'));
        if (fixture.fixtureVersion !== FIXTURE_VERSION) {
            throw new FixtureMissError(`${name}: unsupported fixtureVersion ${fixture.fixtureVersion} (expected ${FIXTURE_VERSION})`);
        }
        if (fixture.synthetic) {
            throw new FixtureMissError(`${name} is a SYNTHETIC case (invented data for validating evals/check.py). It must never be replayed as a fixture; move it out of ${dir}.`);
        }
        const key = normalizeQuestion(fixture.question);
        if (byQuestion.has(key)) {
            throw new FixtureMissError(`Two fixtures for the question "${fixture.question}": ${byQuestion.get(key).name} and ${name}`);
        }
        byQuestion.set(key, { name, fixture });
    }
    cache = { signature, byQuestion };
    return byQuestion;
}

function requireFixture(question) {
    const fixtures = loadFixtures();
    const entry = fixtures.get(normalizeQuestion(question));
    if (!entry) {
        const available = [...fixtures.values()].map(e => `"${e.fixture.question}"`).join(', ') || 'none';
        throw new FixtureMissError(`FIXTURES=1 but there is no fixture for the question "${question}" in ${fixturesDir()}. Available: ${available}`);
    }
    return entry;
}

const sha = text => createHash('sha256').update(text).digest('hex').slice(0, 12);

/** Replaces generateLLMPlan's model call with the planner output recorded at capture. */
export function replayPlan(question) {
    const { name, fixture } = requireFixture(question);
    const planner = fixture.planner;
    if (!planner || !Array.isArray(planner.tools)) {
        throw new FixtureMissError(`${name} has no planner output to replay (capture status: ${fixture.status})`);
    }
    runLog.info(`[Fixtures] Replaying planner output from ${name} (captured planner source: ${planner.source})`);
    return {
        tools: structuredClone(planner.tools),
        source: 'fixture_replay',
        thought: planner.thought ?? null,
        rawOutput: planner.rawOutput ?? null,
        error: planner.error ?? null,
        replayedFrom: { fixture: name, capturedAt: fixture.capturedAt, capturedSource: planner.source }
    };
}

/**
 * Replaces an OpenSearch or Wazuh HTTP call with the recorded response for the current run's question.
 * kind: 'opensearch' | 'wazuh'. requestPath: URL path after the base URL. payload: the request body
 * (OpenSearch) or query params (Wazuh), which must equal what was recorded.
 * Returns an axios-shaped { status, data }, or throws the recorded error.
 */
export function replayHttp(kind, requestPath, payload) {
    const question = currentRunQuestion();
    if (!question) {
        throw new FixtureMissError(`FIXTURES=1: ${kind} call to ${requestPath} happened outside a run, so no fixture can be selected.`);
    }
    const { name, fixture } = requireFixture(question);

    const wanted = canonicalJson(payload ?? null);
    const candidates = (fixture.calls || []).filter(c => c.kind === kind && c.path === requestPath);
    const match = candidates.find(c => canonicalJson(c.request ?? null) === wanted);
    if (!match) {
        const recorded = candidates.map(c => sha(canonicalJson(c.request ?? null))).join(', ') || 'none';
        throw new FixtureMissError(
            `Fixture miss in ${name}: no recorded ${kind} call to ${requestPath} with this request ` +
            `(request sha ${sha(wanted)}; recorded to that path: ${recorded}). ` +
            'The query built during replay differs from the one captured.'
        );
    }

    runLog.info(`[Fixtures] Replaying ${kind} ${requestPath} from ${name}`);
    if (match.error) {
        const error = new Error(match.error.message || `Recorded ${kind} request failed`);
        error.code = match.error.code ?? undefined;
        if (match.error.status !== null && match.error.status !== undefined) {
            error.response = { status: match.error.status, data: structuredClone(match.error.data ?? null) };
        }
        throw error;
    }
    return { status: match.response.status, data: structuredClone(match.response.data) };
}
