#!/usr/bin/env node
/**
 * Replays captured fixtures through the pipeline with FIXTURES=1: the planner, OpenSearch and Wazuh
 * are served from the fixtures; no model planner call and no SIEM call is made. Runs from backend/:
 *
 *   node scripts/replayFixtures.js [--dir <fixtures dir>] [--out <baseline dir>] [--allow-model]
 *
 * For each fixture it checks that every query built during replay was found in the recording and
 * that the hit count matches the capture.
 *
 * --out <dir>     write one record per question: the captured evidence and the answer production gave
 *                 at capture (result.report), plus this replay's verdict under "replay". Score the
 *                 records with: python3 ../evals/check.py <dir>. They hold real telemetry: keep the
 *                 directory out of git (baseline/ is gitignored).
 * --allow-model   let the report stage call LLM_API_URL. Off by default: the model URL is replaced with
 *                 an unreachable one, so even a backend/.env pointing at the live model is never called
 *                 and the replayed report is the "model unavailable" fallback.
 *
 * Uses a scratch database in the OS temp directory. Exit code 1 if any fixture diverged.
 */
import fs from 'fs';
import os from 'os';
import path from 'path';

const MODEL_DISABLED_URL = 'http://model-disabled-in-replay.invalid/v1/chat/completions';

function parseArgs(argv) {
    const args = { dir: null, out: null, allowModel: false };
    for (let i = 0; i < argv.length; i++) {
        const next = () => {
            if (i + 1 >= argv.length) throw new Error(`${argv[i]} needs a value`);
            return path.resolve(argv[++i]);
        };
        if (argv[i] === '--dir') args.dir = next();
        else if (argv[i] === '--out') args.out = next();
        else if (argv[i] === '--allow-model') args.allowModel = true;
        else throw new Error(`Unknown argument: ${argv[i]}`);
    }
    return args;
}

async function main() {
    const args = parseArgs(process.argv.slice(2));
    process.env.FIXTURES = '1';
    if (args.dir) process.env.FIXTURES_DIR = args.dir;
    // Set before config/env.js loads backend/.env: dotenv never overrides a variable already set.
    if (!args.allowModel) process.env.LLM_API_URL = MODEL_DISABLED_URL;
    const scratchDir = fs.mkdtempSync(path.join(os.tmpdir(), 'soc-replay-'));
    process.env.SOC_DB_PATH = path.join(scratchDir, 'replay.db');

    const { loadFixtures, fixturesDir } = await import('../src/recording/replay.js');
    const { canonicalJson } = await import('../src/recording/common.js');
    const { default: db, initDatabase } = await import('../src/config/db.js');
    const { processChatQuery } = await import('../src/services/chat.service.js');
    const { RunModel } = await import('../src/models/Run.js');

    try {
        initDatabase();
        const fixtures = [...loadFixtures().values()];
        console.log(`[Replay] ${fixtures.length} fixture(s) from ${fixturesDir()}${args.allowModel ? ' (model calls allowed)' : ' (model calls disabled)'}`);
        if (args.out) fs.mkdirSync(args.out, { recursive: true });
        const manifest = [];
        let diverged = 0;

        for (const { name, fixture } of fixtures) {
            const response = await processChatQuery(fixture.question, [], 'user_admin_root').catch(error => ({ error }));
            const requestId = response.request_id ?? response.error?.requestId;
            const run = requestId ? RunModel.findById(requestId) : null;
            const problems = [];

            if (!run) problems.push(`no run record (${response.error?.message ?? 'no request_id'})`);
            else {
                if (run.status !== 'completed') problems.push(`run ${run.status}`);
                for (const e of run.errors || []) {
                    if (/Fixture miss|FIXTURES=1/.test(e.message)) problems.push(e.message);
                }
                // A search that failed at capture is replayed as the same failure, and only when the
                // rebuilt query matches the recording exactly (anything else is a fixture miss, above).
                // So successful searches are compared query by query, and failed ones by count.
                // Aggregation requests (Phase 5) are compared separately; fixtures captured before Phase 5 have none.
                const isAggregation = c => c.request?.size === 0 && Boolean(c.request?.aggs);
                const searches = fixture.calls.filter(c => c.kind === 'opensearch' && !isAggregation(c));
                const recorded = searches.filter(c => !c.error).map(c => canonicalJson(c.request)).sort();
                const recordedFailures = searches.filter(c => c.error).length;
                const searchTools = (run.tools || []).filter(t => t.tool === 'searchSecurityLogs');
                const replayed = searchTools.filter(t => t.success && t.query).map(t => canonicalJson(t.query)).sort();
                const replayedFailures = searchTools.filter(t => !t.success && !/Fixture miss|FIXTURES=1/.test(t.error ?? '')).length;
                if (canonicalJson(recorded) !== canonicalJson(replayed)) {
                    problems.push(`OpenSearch queries differ from capture (recorded ${recorded.length}, replayed ${replayed.length})`);
                }
                if (recordedFailures !== replayedFailures) {
                    problems.push(`failed OpenSearch calls differ from capture (recorded ${recordedFailures}, replayed ${replayedFailures})`);
                }
                // An aggregation request is replayed only when it matches the recording exactly; otherwise the
                // search falls back to sample counts. So the ones answered must be exactly the ones recorded.
                const recordedAggs = fixture.calls.filter(c => c.kind === 'opensearch' && isAggregation(c) && !c.error).map(c => canonicalJson(c.request)).sort();
                const replayedAggs = searchTools.filter(t => t.aggregations?.available && t.aggregations.query).map(t => canonicalJson(t.aggregations.query)).sort();
                if (canonicalJson(recordedAggs) !== canonicalJson(replayedAggs)) {
                    problems.push(`aggregation requests differ from capture (recorded ${recordedAggs.length}, replayed ${replayedAggs.length})`);
                }
                if (fixture.result?.totalHits !== null && fixture.result?.totalHits !== undefined && response.total_hits !== fixture.result.totalHits) {
                    problems.push(`total_hits ${response.total_hits} != captured ${fixture.result.totalHits}`);
                }
            }

            if (problems.length > 0) diverged++;
            console.log(`[Replay] ${problems.length ? 'DIVERGED' : 'OK      '} ${name} request_id=${requestId ?? '-'} hits=${response.total_hits ?? '-'} report=${run?.generation?.report ?? '-'}`);
            for (const p of problems) console.log(`           - ${p}`);

            if (args.out) {
                const record = {
                    ...fixture,
                    replay: {
                        status: problems.length ? 'diverged' : 'matched',
                        problems,
                        replayedAt: new Date().toISOString(),
                        requestId: requestId ?? null,
                        modelAllowed: args.allowModel,
                        report: run?.reportText ?? response.summary ?? response.text ?? null,
                        modelGenerated: run?.modelGenerated ?? null,
                        totalHits: response.total_hits ?? null
                    }
                };
                fs.writeFileSync(path.join(args.out, name), JSON.stringify(record, null, 2) + '\n');
                manifest.push({ file: name, question: fixture.question, replay: record.replay.status, capturedAt: fixture.capturedAt });
            }
        }
        if (args.out) {
            fs.writeFileSync(path.join(args.out, 'manifest.json'), JSON.stringify({ source: fixturesDir(), replayedAt: new Date().toISOString(), records: manifest }, null, 2) + '\n');
            console.log(`[Replay] Baseline records written to ${args.out}. Score them with: python3 ../evals/check.py ${args.out}`);
        }
        console.log(`[Replay] ${fixtures.length - diverged}/${fixtures.length} matched the capture.`);
        return diverged > 0 ? 1 : 0;
    } finally {
        db.close();
        fs.rmSync(scratchDir, { recursive: true, force: true });
    }
}

main().then(
    code => process.exit(code),
    error => {
        console.error(error.message);
        process.exit(1);
    }
);
