#!/usr/bin/env node
/**
 * Replays captured fixtures through the pipeline with FIXTURES=1: the planner, OpenSearch and Wazuh
 * are served from the fixtures; no model planner call and no SIEM call is made. Runs from backend/:
 *
 *   node scripts/replayFixtures.js [--dir <fixtures dir>]
 *
 * For each fixture it checks that every query built during replay was found in the recording and
 * that the hit count matches the capture. The report stage still calls LLM_API_URL if one is set;
 * without a reachable model the report is the "model unavailable" fallback.
 * Uses a scratch database in the OS temp directory. Exit code 1 if any fixture diverged.
 */
import fs from 'fs';
import os from 'os';
import path from 'path';

function parseArgs(argv) {
    const args = { dir: null };
    for (let i = 0; i < argv.length; i++) {
        if (argv[i] === '--dir') args.dir = path.resolve(argv[++i]);
        else throw new Error(`Unknown argument: ${argv[i]}`);
    }
    return args;
}

async function main() {
    const args = parseArgs(process.argv.slice(2));
    process.env.FIXTURES = '1';
    if (args.dir) process.env.FIXTURES_DIR = args.dir;
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
        console.log(`[Replay] ${fixtures.length} fixture(s) from ${fixturesDir()}`);
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
                const recorded = fixture.calls.filter(c => c.kind === 'opensearch').map(c => canonicalJson(c.request)).sort();
                const replayed = (run.tools || []).filter(t => t.tool === 'searchSecurityLogs' && t.query).map(t => canonicalJson(t.query)).sort();
                if (canonicalJson(recorded) !== canonicalJson(replayed)) {
                    problems.push(`OpenSearch queries differ from capture (recorded ${recorded.length}, replayed ${replayed.length})`);
                }
                if (fixture.result?.totalHits !== null && fixture.result?.totalHits !== undefined && response.total_hits !== fixture.result.totalHits) {
                    problems.push(`total_hits ${response.total_hits} != captured ${fixture.result.totalHits}`);
                }
            }

            if (problems.length > 0) diverged++;
            console.log(`[Replay] ${problems.length ? 'DIVERGED' : 'OK      '} ${name} request_id=${requestId ?? '-'} hits=${response.total_hits ?? '-'} report=${run?.generation?.report ?? '-'}`);
            for (const p of problems) console.log(`           - ${p}`);
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
