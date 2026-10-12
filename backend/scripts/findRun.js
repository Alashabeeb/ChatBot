#!/usr/bin/env node
/**
 * Finds a run record, read-only, to turn a bad answer into a test (docs/ADDING_TEST_CASES.md). Opens
 * the database with SQLite's read-only flag: safe while the backend runs. From backend/:
 *
 *   node scripts/findRun.js --search "failed logons"     latest runs whose question contains the text
 *   node scripts/findRun.js --request-id <id>            one run in full: question, plan, searches,
 *                                                        report, and every claim verification dropped
 *   --db <path>                                          default: data/soc_chatbot.db
 *
 * Exit codes: 0 found, 2 nothing found, 1 error. The output holds the question and report text, and
 * claims the model made: treat it like the answers themselves.
 */
import path from 'path';
import { fileURLToPath } from 'url';
import Database from 'better-sqlite3';

const BACKEND_DIR = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const parse = value => { try { return value ? JSON.parse(value) : null; } catch { return null; } };

function parseArgs(argv) {
    const args = { db: path.join(BACKEND_DIR, 'data', 'soc_chatbot.db'), search: null, requestId: null };
    for (let i = 0; i < argv.length; i++) {
        const next = () => argv[++i] ?? (() => { throw new Error(`${argv[i - 1]} needs a value`); })();
        if (argv[i] === '--db') args.db = path.resolve(next());
        else if (argv[i] === '--search') args.search = next();
        else if (argv[i] === '--request-id') args.requestId = next();
        else throw new Error(`Unknown argument: ${argv[i]}`);
    }
    if (!args.search && !args.requestId) throw new Error('Give --search <text> or --request-id <id>');
    return args;
}

function main() {
    const args = parseArgs(process.argv.slice(2));
    const db = new Database(args.db, { readonly: true, fileMustExist: true });
    db.pragma('query_only = ON');
    try {
        if (args.search) {
            const rows = db.prepare("SELECT request_id, started_at, status, question FROM runs WHERE question LIKE ? ESCAPE '\\' ORDER BY started_at DESC LIMIT 20")
                .all(`%${args.search.replace(/[\\%_]/g, c => `\\${c}`)}%`);
            for (const r of rows) console.log(`${r.request_id}  ${r.started_at}  ${r.status.padEnd(10)}  ${r.question}`);
            if (rows.length === 0) console.log('No run matches.');
            return rows.length ? 0 : 2;
        }
        const row = db.prepare('SELECT * FROM runs WHERE request_id = ?').get(args.requestId);
        if (!row) {
            console.log(`No run with request_id ${args.requestId}.`);
            return 2;
        }
        const generation = parse(row.generation_json) ?? {};
        const planner = parse(row.planner_json) ?? {};
        const tools = parse(row.tools_json) ?? [];
        const grounding = parse(row.grounding_json);
        console.log(`request_id: ${row.request_id}\nstarted:    ${row.started_at}\nstatus:     ${row.status}\nquestion: ${row.question}`);
        console.log(`planner: ${generation.planner ?? planner.source ?? '-'}   report: ${generation.report ?? '-'}   models: ${JSON.stringify(generation.models ?? generation.model ?? null)}`);
        console.log('\nsearches and tools:');
        for (const t of tools) console.log(`  - ${t.tool}${t.parameters?.sourceScope ? ` (${t.parameters.sourceScope})` : ''}: ${t.success === false ? `FAILED ${t.error}` : `${t.totalHits ?? t.total ?? '-'} hit(s)`}${t.parameters?.timeRange ? `, window ${t.parameters.timeRange}` : ''}`);
        const errors = parse(row.errors_json) ?? [];
        if (errors.length) {
            console.log(`\nerrors (${errors.length}):`);
            for (const e of errors) console.log(`  - [${e.stage}] ${e.message}${e.at ? `  (${e.at})` : ''}`);
        }
        const timings = parse(row.timings_json) ?? {};
        const ms = v => (typeof v === 'number' ? `${v.toLocaleString('en-US')} ms` : '-');
        console.log(`\ntimings: total ${ms(timings.totalDuration)}; planning ${ms(timings.planningDuration)}; searches ${ms(timings.executionDuration)}; model call: ${ms(timings.reasoningDuration)}${typeof timings.reportPromptChars === 'number' ? `; report prompt: ${timings.reportPromptChars.toLocaleString('en-US')} characters` : ''}`);
        if (grounding) {
            console.log(`\nverification: ${grounding.claims} claim(s), ${grounding.shown} shown, dropped (${grounding.dropped?.length ?? 0}):`);
            for (const d of grounding.dropped ?? []) console.log(`  - [${d.section}] ${d.reason}\n      "${d.text}"`);
            if (grounding.parseError) console.log(`  model output was not the required JSON: ${grounding.parseError}`);
        }
        console.log(`\nreport:\n${row.report_text ?? '(none)'}`);
        return 0;
    } finally {
        db.close();
    }
}

try {
    process.exit(main());
} catch (error) {
    console.error(error.message);
    process.exit(1);
}
