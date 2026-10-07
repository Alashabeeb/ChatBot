#!/usr/bin/env node
/**
 * Quarantines records contaminated by the old lookupThreatIntel mock, and by the fabricated
 * blockIpAction / checkProcessList results (IP_BLOCKED, "added … to the firewall blocklist",
 * unknown_miner) that were live between Push 25 and the Phase 0 hotfix.
 *
 * Before the fix, lookupThreatIntel returned fabricated data
 *   { malicious: false, threatScore: 10, tags: ['scanner'],
 *     message: 'Mock threat intelligence response for <ip>. Real integration pending.' }
 * which reached saved reports (messages table → chat history → model) and memories
 * (memories table → planner context and searchMemory tool).
 *
 * Contaminated rows are copied to a separate quarantine database and then removed from the
 * main database, so a copy of the main database never carries them. Nothing is deleted
 * outright; --restore puts rows back.
 *
 * Usage (from backend/):
 *   node scripts/purgeMockThreatIntel.js                 dry run: list matches, exit 2 if any, 0 if clean
 *   node scripts/purgeMockThreatIntel.js --apply         quarantine matches, then re-scan
 *   node scripts/purgeMockThreatIntel.js --restore       move quarantined rows back
 * Options:
 *   --db <path>          main database (default: backend/data/soc_chatbot.db)
 *   --quarantine <path>  quarantine database (default: backend/quarantine/<db name>.quarantine.db)
 *   --signature-only     only act on exact mock signatures, not paraphrases
 *
 * Stop the backend server before --apply or --restore.
 */
import Database from 'better-sqlite3';
import path from 'path';
import fs from 'fs';
import { fileURLToPath } from 'url';

const BACKEND_DIR = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const DEFAULT_DB = path.join(BACKEND_DIR, 'data', 'soc_chatbot.db');

/**
 * 'signature': the mock's own fields and text, or runtime text only produced alongside it.
 * 'paraphrase': the model restating the mock's verdict in its own words. No threat intel
 * source has ever been connected, so any such claim is unsupported.
 */
export const PATTERNS = [
    { tier: 'signature', name: 'mock-message', pattern: /mock threat intelligence response/i },
    { tier: 'signature', name: 'integration-pending', pattern: /real integration pending/i },
    { tier: 'signature', name: 'threatScore-field', pattern: /\bthreatScore\b/i },
    { tier: 'signature', name: 'malicious-field', pattern: /["']?\bmalicious["']?\s*[:=]\s*(true|false)\b/i },
    { tier: 'signature', name: 'scanner-tags-field', pattern: /["']?\btags["']?\s*[:=]\s*\[[^\]]*["']scanner["']/i },
    { tier: 'signature', name: 'claimed-intel-search', pattern: /searched the database and intelligence sources/i },
    // Bounded by length, not by '.', because IP addresses contain dots.
    // The fabricated "action" tools (F-42): blockIpAction's fake confirmation, checkProcessList's fake process.
    { tier: 'signature', name: 'ip-blocked-action', pattern: /\bIP_BLOCKED\b/ },
    { tier: 'signature', name: 'blocklist-success', pattern: /successfully added\b[^\n]{0,60}?\bto the firewall blocklist/i },
    { tier: 'signature', name: 'unknown-miner', pattern: /\bunknown_miner\b/i },
    { tier: 'paraphrase', name: 'threat-score', pattern: /\bthreat\s+score\b/i },
    { tier: 'paraphrase', name: 'tagged-scanner', pattern: /\b(tagged|flagged|classified|identified|listed|labell?ed)\s+(as\s+)?(an?\s+)?["']?scanner\b/i },
    { tier: 'paraphrase', name: 'not-malicious-verdict', pattern: /\b(not|non-?)\s*malicious\b/i },
    { tier: 'paraphrase', name: 'threat-intel-result', pattern: /\bthreat\s+intel(ligence)?\s+(indicates|shows|reports|suggests|confirms|lookup\s+(shows|returned|indicates)|response|results?\b)/i },
    { tier: 'paraphrase', name: 'mock-mention', pattern: /\bmock\b/i },
    // A reworded claim that an IP was blocked. No blocking capability has ever existed, so any such claim
    // is unsupported. Narrow on purpose: "the firewall blocked 42 connections" is real activity, not this.
    { tier: 'paraphrase', name: 'claimed-ip-block', pattern: /\b(?:IP|address)\b[^\n]{0,40}?\b(?:has been|was|is now)\s+(?:successfully\s+)?blocked\b/i }
];

// Tables whose contents are fed back to the model. Table and column names are fixed here,
// never taken from input, so they are safe to interpolate into SQL.
export const TARGETS = [
    { table: 'messages', columns: ['text', 'summary', 'raw_logs'] },
    { table: 'memories', columns: ['content'] }
];

export function defaultQuarantinePath(dbPath) {
    const name = path.basename(dbPath, path.extname(dbPath));
    return path.join(BACKEND_DIR, 'quarantine', `${name}.quarantine.db`);
}

function matchRow(row, columns, patterns) {
    const matches = [];
    for (const column of columns) {
        const value = row[column];
        if (typeof value !== 'string' || !value) continue;
        for (const { tier, name, pattern } of patterns) {
            const m = value.match(pattern);
            if (m) {
                const start = Math.max(0, m.index - 40);
                matches.push({ tier, name, column, snippet: value.slice(start, m.index + m[0].length + 40).replace(/\s+/g, ' ') });
            }
        }
    }
    return matches;
}

export function scan(db, { signatureOnly = false } = {}) {
    const patterns = signatureOnly ? PATTERNS.filter(p => p.tier === 'signature') : PATTERNS;
    const hits = [];
    for (const { table, columns } of TARGETS) {
        for (const row of db.prepare(`SELECT * FROM main.${table}`).iterate()) {
            const matches = matchRow(row, columns, patterns);
            if (matches.length > 0) hits.push({ table, id: row.id, row, matches });
        }
    }
    return hits;
}

export function attachQuarantine(db, quarantinePath) {
    fs.mkdirSync(path.dirname(quarantinePath), { recursive: true });
    db.prepare('ATTACH DATABASE ? AS quarantine').run(quarantinePath);
    db.exec(`
        CREATE TABLE IF NOT EXISTS quarantine.records (
            source_table TEXT NOT NULL,
            source_id TEXT NOT NULL,
            matched TEXT NOT NULL,
            row_json TEXT NOT NULL,
            quarantined_at TEXT NOT NULL,
            PRIMARY KEY (source_table, source_id)
        );
    `);
}

export function quarantineHits(db, hits) {
    const now = new Date().toISOString();
    const insert = db.prepare(`
        INSERT OR IGNORE INTO quarantine.records (source_table, source_id, matched, row_json, quarantined_at)
        VALUES (?, ?, ?, ?, ?)
    `);
    const inQuarantine = db.prepare('SELECT 1 FROM quarantine.records WHERE source_table = ? AND source_id = ?');

    // Two separate commits: copy first, then remove. Cross-database transactions are not atomic
    // in WAL mode, so an interruption may leave a row in both places, but never in neither.
    db.transaction(() => {
        for (const hit of hits) {
            insert.run(hit.table, hit.id, JSON.stringify(hit.matches), JSON.stringify(hit.row), now);
        }
    })();

    let moved = 0;
    db.transaction(() => {
        for (const hit of hits) {
            if (!inQuarantine.get(hit.table, hit.id)) {
                throw new Error(`Refusing to remove ${hit.table}/${hit.id}: not present in quarantine.`);
            }
            moved += db.prepare(`DELETE FROM main.${hit.table} WHERE id = ?`).run(hit.id).changes;
        }
    })();
    return moved;
}

export function restoreQuarantined(db) {
    const records = db.prepare('SELECT source_table, source_id, row_json FROM quarantine.records').all();
    const remove = db.prepare('DELETE FROM quarantine.records WHERE source_table = ? AND source_id = ?');
    const restored = [];
    const failed = [];

    for (const record of records) {
        const target = TARGETS.find(t => t.table === record.source_table);
        if (!target) {
            failed.push({ ...record, error: 'unknown table' });
            continue;
        }
        const tableColumns = new Set(db.prepare(`PRAGMA main.table_info(${target.table})`).all().map(c => c.name));
        const row = JSON.parse(record.row_json);
        const columns = Object.keys(row).filter(c => tableColumns.has(c));
        try {
            db.transaction(() => {
                const result = db.prepare(`INSERT INTO main.${target.table} (${columns.join(', ')}) VALUES (${columns.map(() => '?').join(', ')})`)
                    .run(...columns.map(c => row[c]));
                if (result.changes !== 1) throw new Error('row not inserted');
                remove.run(record.source_table, record.source_id);
            })();
            restored.push(record);
        } catch (error) {
            failed.push({ source_table: record.source_table, source_id: record.source_id, error: error.message });
        }
    }
    return { restored, failed };
}

function parseArgs(argv) {
    const args = { apply: false, restore: false, signatureOnly: false, db: DEFAULT_DB, quarantine: null };
    for (let i = 0; i < argv.length; i++) {
        const arg = argv[i];
        if (arg === '--apply') args.apply = true;
        else if (arg === '--restore') args.restore = true;
        else if (arg === '--signature-only') args.signatureOnly = true;
        else if (arg === '--db') args.db = path.resolve(argv[++i]);
        else if (arg === '--quarantine') args.quarantine = path.resolve(argv[++i]);
        else throw new Error(`Unknown argument: ${arg}`);
    }
    if (args.apply && args.restore) throw new Error('--apply and --restore are mutually exclusive.');
    args.quarantine ??= defaultQuarantinePath(args.db);
    return args;
}

function printHits(hits) {
    for (const hit of hits) {
        const created = hit.row.created_at || '';
        const user = hit.row.user_id || '';
        console.log(`  ${hit.table}/${hit.id}  user=${user}  created=${created}`);
        for (const m of hit.matches) {
            console.log(`    [${m.tier}] ${m.name} in ${m.column}: …${m.snippet}…`);
        }
    }
}

function main() {
    const args = parseArgs(process.argv.slice(2));
    if (!fs.existsSync(args.db)) {
        console.error(`Database not found: ${args.db}`);
        process.exit(1);
    }
    // Existence is checked above. Not using fileMustExist: its open flags also stop ATTACH from creating the quarantine file.
    const db = new Database(args.db);
    db.pragma('foreign_keys = ON');

    try {
        if (args.restore) {
            if (!fs.existsSync(args.quarantine)) {
                console.log(`No quarantine database at ${args.quarantine}. Nothing to restore.`);
                return 0;
            }
            attachQuarantine(db, args.quarantine);
            const { restored, failed } = restoreQuarantined(db);
            console.log(`Restored ${restored.length} record(s) from ${args.quarantine}.`);
            for (const f of failed) console.log(`  FAILED ${f.source_table}/${f.source_id}: ${f.error}`);
            return failed.length > 0 ? 1 : 0;
        }

        const hits = scan(db, args);
        console.log(`Scanned ${args.db} (${args.signatureOnly ? 'signatures only' : 'signatures + paraphrases'}).`);
        if (hits.length === 0) {
            console.log('Clean: no mock threat intel found.');
            return 0;
        }
        console.log(`Found ${hits.length} contaminated record(s):`);
        printHits(hits);

        if (!args.apply) {
            console.log('\nDry run. Re-run with --apply to quarantine these records.');
            return 2;
        }

        attachQuarantine(db, args.quarantine);
        const moved = quarantineHits(db, hits);
        console.log(`\nQuarantined ${moved} record(s) to ${args.quarantine}.`);

        const remaining = scan(db, args);
        if (remaining.length > 0) {
            console.log(`WARNING: ${remaining.length} contaminated record(s) remain.`);
            return 2;
        }
        console.log('Re-scan clean.');
        return 0;
    } finally {
        db.close();
    }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
    try {
        process.exitCode = main();
    } catch (error) {
        console.error(error.message);
        process.exitCode = 1;
    }
}
