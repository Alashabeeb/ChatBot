#!/usr/bin/env node
/**
 * Read-only report on the backend database. Opens it with SQLite's read-only flag, so it cannot
 * modify, migrate or create anything. Safe to run while the backend is running. From backend/:
 *
 *   node scripts/dbReport.js [--db <path>]      default: data/soc_chatbot.db
 *
 * Prints row counts for messages, memories and users, the message date range, the usernames, and
 * whether the run-logging migration (messages.request_id, runs table) has already been applied.
 */
import path from 'path';
import { fileURLToPath } from 'url';
import Database from 'better-sqlite3';

const BACKEND_DIR = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

function parseArgs(argv) {
    let dbPath = path.join(BACKEND_DIR, 'data', 'soc_chatbot.db');
    for (let i = 0; i < argv.length; i++) {
        if (argv[i] === '--db') dbPath = path.resolve(argv[++i]);
        else throw new Error(`Unknown argument: ${argv[i]}`);
    }
    return dbPath;
}

function main() {
    const dbPath = parseArgs(process.argv.slice(2));
    const db = new Database(dbPath, { readonly: true, fileMustExist: true });
    try {
        db.pragma('query_only = ON');
        const hasTable = name => Boolean(db.prepare("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?").get(name));
        const count = table => (hasTable(table) ? db.prepare(`SELECT COUNT(*) AS n FROM ${table}`).get().n : '(table missing)');

        console.log(`Database: ${dbPath} (opened read-only)`);
        console.log(`messages: ${count('messages')}`);
        console.log(`memories: ${count('memories')}`);
        console.log(`users:    ${count('users')}`);

        if (hasTable('messages')) {
            const range = db.prepare('SELECT MIN(created_at) AS first, MAX(created_at) AS last FROM messages').get();
            console.log(`message date range: ${range.first ?? '(none)'} -> ${range.last ?? '(none)'}`);
        }
        if (hasTable('users')) {
            const users = db.prepare('SELECT username, role, created_at FROM users ORDER BY created_at').all();
            console.log('usernames:');
            for (const u of users) console.log(`  ${u.username} (${u.role}, created ${u.created_at})`);
        }

        const migrated = hasTable('messages') && db.prepare('PRAGMA table_info(messages)').all().some(c => c.name === 'request_id');
        console.log(`run-logging migration applied: messages.request_id=${migrated ? 'yes' : 'no'}, runs table=${hasTable('runs') ? `yes (${count('runs')} rows)` : 'no'}`);
    } finally {
        db.close();
    }
}

try {
    main();
} catch (error) {
    console.error(error.message);
    process.exit(1);
}
