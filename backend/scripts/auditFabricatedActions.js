#!/usr/bin/env node
/**
 * Read-only audit of saved chat messages for text produced by fabricated tool results:
 *   - blockIpAction:   "IP_BLOCKED" / "...to the firewall blocklist." (no IP was ever blocked)
 *   - checkProcessList: "unknown_miner" (hard-coded fake process, returned for every endpoint)
 *   - lookupThreatIntel mock: "Mock threat intelligence response ..." / "Real integration pending"
 *
 * Usage (from backend/):
 *   node scripts/auditFabricatedActions.js [--db <path>]     default: data/soc_chatbot.db
 *
 * Opens the database with SQLite's read-only flag (and query_only), so it cannot modify, migrate
 * or create anything. Safe while the backend is running.
 * Exit codes: 0 no matches, 2 matches found, 1 error.
 */
import path from 'path';
import { fileURLToPath } from 'url';
import Database from 'better-sqlite3';

const BACKEND_DIR = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

const SIGNATURES = [
    { name: 'IP_BLOCKED', pattern: /IP_BLOCKED/ },
    { name: 'blocklist', pattern: /blocklist/i },
    { name: 'unknown_miner', pattern: /unknown_miner/i },
    { name: 'threat-intel mock', pattern: /Mock threat intelligence response|Real integration pending/i }
];
const TEXT_COLUMNS = ['text', 'summary', 'raw_logs'];

function parseArgs(argv) {
    let dbPath = path.join(BACKEND_DIR, 'data', 'soc_chatbot.db');
    for (let i = 0; i < argv.length; i++) {
        if (argv[i] === '--db') dbPath = path.resolve(argv[++i]);
        else throw new Error(`Unknown argument: ${argv[i]}`);
    }
    return dbPath;
}

function snippet(value, index, length) {
    const start = Math.max(0, index - 60);
    const end = Math.min(value.length, index + length + 60);
    return `…${value.slice(start, end).replace(/\s+/g, ' ')}…`;
}

function main() {
    const dbPath = parseArgs(process.argv.slice(2));
    const db = new Database(dbPath, { readonly: true, fileMustExist: true });
    try {
        db.pragma('query_only = ON');
        const columnsOf = table => db.prepare(`PRAGMA table_info(${table})`).all().map(c => c.name);
        const messageColumns = columnsOf('messages');
        if (messageColumns.length === 0) throw new Error('No messages table in this database.');
        const searched = TEXT_COLUMNS.filter(c => messageColumns.includes(c));
        const hasUsers = columnsOf('users').includes('username');

        const select = ['m.id', 'm.created_at', 'm.user_id', ...searched.map(c => `m.${c}`)];
        if (messageColumns.includes('session_id')) select.push('m.session_id');
        if (hasUsers) select.push('u.username');
        const rows = db.prepare(`
            SELECT ${select.join(', ')} FROM messages m
            ${hasUsers ? 'LEFT JOIN users u ON u.id = m.user_id' : ''}
            ORDER BY m.created_at
        `).all();

        console.log(`Database: ${dbPath} (opened read-only)`);
        console.log(`Searched messages.${searched.join(', messages.')} for: ${SIGNATURES.map(s => s.name).join(', ')}`);
        console.log('');

        let matched = 0;
        for (const row of rows) {
            const hits = [];
            for (const column of searched) {
                const value = row[column];
                if (typeof value !== 'string' || !value) continue;
                for (const { name, pattern } of SIGNATURES) {
                    const m = value.match(pattern);
                    if (m) hits.push({ name, column, text: snippet(value, m.index, m[0].length) });
                }
            }
            if (hits.length === 0) continue;
            matched++;
            const user = row.username ? `${row.username} (${row.user_id})` : row.user_id;
            const session = row.session_id ? `  session=${row.session_id}` : '';
            console.log(`${row.created_at}  user=${user}  message=${row.id}${session}  matched: ${[...new Set(hits.map(h => h.name))].join(', ')}`);
            for (const h of hits) console.log(`    [${h.name}] ${h.column}: ${h.text}`);
        }

        console.log('');
        if (matched === 0) {
            console.log('No fabricated-action text found.');
            return 0;
        }
        console.log(`${matched} message(s) matched.`);
        console.log('Note: "blocklist" also matches legitimate advice (e.g. "consider adding this IP to the blocklist"). Review those snippets by hand; IP_BLOCKED, unknown_miner and the threat-intel mock text are definite.');
        return 2;
    } finally {
        db.close();
    }
}

try {
    process.exitCode = main();
} catch (error) {
    console.error(`AUDIT FAILED: ${error.message}`);
    process.exitCode = 1;
}
