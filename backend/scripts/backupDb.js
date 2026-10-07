#!/usr/bin/env node
/**
 * Online backup of the backend database using SQLite's backup API. Safe while the backend is
 * running: the source is opened read-only and the copy includes changes still in the WAL file.
 * From backend/:
 *
 *   node scripts/backupDb.js [--db <path>] [--out <backup file>]
 *
 * Default --db: data/soc_chatbot.db. Default --out: soc_chatbot.backup-<YYYYMMDD-HHMMSS>.db next to it.
 * Refuses to overwrite an existing file. Verifies the copy (integrity_check, table list) before
 * reporting success. Exit code 0 only if the backup verified.
 */
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import Database from 'better-sqlite3';

const BACKEND_DIR = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

function timestamp(date = new Date()) {
    const pad = n => String(n).padStart(2, '0');
    return `${date.getFullYear()}${pad(date.getMonth() + 1)}${pad(date.getDate())}-${pad(date.getHours())}${pad(date.getMinutes())}${pad(date.getSeconds())}`;
}

function parseArgs(argv) {
    let dbPath = path.join(BACKEND_DIR, 'data', 'soc_chatbot.db');
    let outPath = null;
    for (let i = 0; i < argv.length; i++) {
        if (argv[i] === '--db') dbPath = path.resolve(argv[++i]);
        else if (argv[i] === '--out') outPath = path.resolve(argv[++i]);
        else throw new Error(`Unknown argument: ${argv[i]}`);
    }
    outPath ??= path.join(path.dirname(dbPath), `${path.basename(dbPath, path.extname(dbPath))}.backup-${timestamp()}.db`);
    return { dbPath, outPath };
}

const tables = db => db.prepare("SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name").all().map(r => r.name);

async function main() {
    const { dbPath, outPath } = parseArgs(process.argv.slice(2));
    if (fs.existsSync(outPath)) throw new Error(`Refusing to overwrite existing file: ${outPath}`);

    const source = new Database(dbPath, { readonly: true, fileMustExist: true });
    let sourceTables;
    try {
        sourceTables = tables(source);
        await source.backup(outPath);
    } finally {
        source.close();
    }

    const copy = new Database(outPath, { readonly: true, fileMustExist: true });
    try {
        const integrity = copy.pragma('integrity_check', { simple: true });
        if (integrity !== 'ok') throw new Error(`Backup failed integrity_check: ${integrity}`);
        const copyTables = tables(copy);
        if (JSON.stringify(copyTables) !== JSON.stringify(sourceTables)) {
            throw new Error(`Backup table list differs from source: ${copyTables.join(',')} vs ${sourceTables.join(',')}`);
        }
        console.log(`Backup OK: ${outPath}`);
        console.log(`  size: ${fs.statSync(outPath).size} bytes, integrity_check: ok`);
        for (const table of copyTables) {
            console.log(`  ${table}: ${copy.prepare(`SELECT COUNT(*) AS n FROM "${table}"`).get().n} rows`);
        }
    } finally {
        copy.close();
    }
}

main().then(
    () => process.exit(0),
    error => {
        console.error(`BACKUP FAILED: ${error.message}`);
        process.exit(1);
    }
);
