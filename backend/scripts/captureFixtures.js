#!/usr/bin/env node
/**
 * Captures replay fixtures by running questions through the full live pipeline.
 * Run on the backend host (it needs the model, OpenSearch and Wazuh), from backend/:
 *
 *   node scripts/captureFixtures.js --check        verify settings, touch nothing
 *   node scripts/captureFixtures.js                capture the default questions into fixtures/
 *
 * Options:
 *   --out <dir>              output directory (default: backend/fixtures, which is gitignored)
 *   --questions-file <file>  one question per line (default: the four built-in questions)
 *   --timeout-ms <ms>        give up waiting on a question after this long (default: 600000)
 *   --redact                 mask internal IPs, hostnames and usernames (default: off)
 *   --redact-term <text>     with --redact, also mask this exact text; repeatable (e.g. the AD domain)
 *   --help
 *
 * Uses a fresh scratch database in the OS temp directory, deleted afterwards: the real
 * backend/data/soc_chatbot.db is never opened, migrated or written.
 * Exit codes: 0 all questions completed, 2 at least one did not, 1 setup error.
 */
import fs from 'fs';
import os from 'os';
import path from 'path';
import dotenv from 'dotenv';
import { BACKEND_DIR, DEFAULT_FIXTURES_DIR, DEFAULT_QUESTIONS } from '../src/recording/common.js';

const USAGE = fs.readFileSync(new URL(import.meta.url), 'utf8').split('*/')[0].replace(/^#!.*\n\/\*\*\n?/, '').replace(/^ \* ?/gm, '');

function parseArgs(argv) {
    const args = { out: DEFAULT_FIXTURES_DIR, questionsFile: null, timeoutMs: 600000, redact: false, redactTerms: [], check: false, help: false };
    for (let i = 0; i < argv.length; i++) {
        const arg = argv[i];
        const next = () => {
            if (i + 1 >= argv.length) throw new Error(`${arg} needs a value`);
            return argv[++i];
        };
        if (arg === '--help' || arg === '-h') args.help = true;
        else if (arg === '--check') args.check = true;
        else if (arg === '--redact') args.redact = true;
        else if (arg === '--redact-term') args.redactTerms.push(next());
        else if (arg === '--out') args.out = path.resolve(next());
        else if (arg === '--questions-file') args.questionsFile = path.resolve(next());
        else if (arg === '--timeout-ms') args.timeoutMs = Number(next());
        else throw new Error(`Unknown argument: ${arg}`);
    }
    if (!Number.isFinite(args.timeoutMs) || args.timeoutMs <= 0) throw new Error('--timeout-ms must be a positive number');
    if (args.redactTerms.length > 0 && !args.redact) throw new Error('--redact-term only applies with --redact');
    return args;
}

function loadQuestions(file) {
    if (!file) return DEFAULT_QUESTIONS;
    const questions = fs.readFileSync(file, 'utf8').split(/\r?\n/).map(q => q.trim()).filter(q => q && !q.startsWith('#'));
    if (questions.length === 0) throw new Error(`No questions in ${file}`);
    return questions;
}

function gitignoreCovers(outDir) {
    const rel = path.relative(BACKEND_DIR, outDir);
    if (rel.startsWith('..') || path.isAbsolute(rel)) return false;
    const ignore = path.join(BACKEND_DIR, '.gitignore');
    const top = rel.split(path.sep)[0];
    return fs.existsSync(ignore) && fs.readFileSync(ignore, 'utf8').split(/\r?\n/).some(line => line.trim() === `${top}/`);
}

async function main() {
    const args = parseArgs(process.argv.slice(2));
    if (args.help) {
        console.log(USAGE);
        return 0;
    }
    if (process.env.FIXTURES === '1') {
        console.error('FIXTURES=1 is set, which would replay fixtures instead of capturing live. Unset it and run again.');
        return 1;
    }

    // Load backend/.env regardless of the current directory.
    dotenv.config({ path: path.join(BACKEND_DIR, '.env') });
    const questions = loadQuestions(args.questionsFile);
    const required = ['OPENSEARCH_URL', 'WAZUH_SERVER_API_URL', 'WAZUH_USER', 'WAZUH_PASSWORD', 'LLM_API_URL'];
    const missing = required.filter(name => !process.env[name]);

    if (!gitignoreCovers(args.out)) {
        console.warn(`WARNING: ${args.out} is not covered by backend/.gitignore. Fixtures contain real security telemetry; keep them out of any repository.`);
    }

    if (args.check) {
        console.log(`Settings (values not shown): ${required.map(name => `${name}=${process.env[name] ? 'set' : 'MISSING'}`).join(' ')}`);
        console.log(`Output directory: ${args.out}`);
        console.log(`Questions (${questions.length}): ${questions.map(q => `"${q}"`).join(', ')}`);
        console.log(`Redaction: ${args.redact ? `on${args.redactTerms.length ? ` (+${args.redactTerms.length} extra term(s))` : ''}` : 'off'}`);
        console.log(missing.length ? `NOT READY: missing ${missing.join(', ')}` : 'READY');
        return missing.length ? 1 : 0;
    }
    if (missing.length > 0) {
        console.error(`Missing required settings (set them in backend/.env): ${missing.join(', ')}`);
        return 1;
    }

    // Scratch database, set before any backend module opens one.
    const scratchDir = fs.mkdtempSync(path.join(os.tmpdir(), 'soc-capture-'));
    process.env.SOC_DB_PATH = path.join(scratchDir, 'capture.db');

    const { captureFixtures } = await import('../src/recording/capture.js');
    const { default: db } = await import('../src/config/db.js');
    try {
        console.log(`[Capture] ${questions.length} question(s) -> ${args.out} (redaction ${args.redact ? 'ON' : 'off'}, timeout ${args.timeoutMs}ms per question)`);
        const summaries = await captureFixtures({ questions, outDir: args.out, redact: args.redact, redactTerms: args.redactTerms, timeoutMs: args.timeoutMs });
        const incomplete = summaries.filter(s => s.status !== 'completed');
        console.log(`[Capture] Done: ${summaries.length - incomplete.length}/${summaries.length} completed. Manifest: ${path.join(args.out, 'manifest.json')}`);
        for (const s of incomplete) console.log(`[Capture] NOT COMPLETED: "${s.question}" status=${s.status}`);
        return incomplete.length > 0 ? 2 : 0;
    } finally {
        try {
            db.close();
            fs.rmSync(scratchDir, { recursive: true, force: true });
        } catch (error) {
            console.warn(`[Capture] Could not remove scratch database ${scratchDir}: ${error.message}`);
        }
    }
}

main().then(
    code => process.exit(code),
    error => {
        console.error(error.message);
        process.exit(1);
    }
);
