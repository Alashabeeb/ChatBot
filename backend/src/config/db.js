import Database from 'better-sqlite3';
import path from 'path';
import fs from 'fs';
import bcrypt from 'bcryptjs';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Data directory path: backend/data
const dataDir = path.resolve(__dirname, '../../data');

// SOC_DB_PATH overrides the default file (tests use ':memory:').
const dbPath = process.env.SOC_DB_PATH || path.join(dataDir, 'soc_chatbot.db');
if (!process.env.SOC_DB_PATH && !fs.existsSync(dataDir)) {
    fs.mkdirSync(dataDir, { recursive: true });
}
const db = new Database(dbPath);

import { ADMIN_INITIAL_USER, ADMIN_INITIAL_PASSWORD, PUBLISHED_DEFAULT_ADMIN_PASSWORD } from './env.js';

// Enable WAL mode & Foreign Keys for fast concurrency and data integrity
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

/**
 * The first version of `runs` had no instance_id column and a status CHECK without 'interrupted'.
 * SQLite cannot alter a CHECK constraint, so rebuild that table in place, keeping its rows.
 */
function migrateRunsTableWithoutInstanceId() {
    const columns = db.prepare('PRAGMA table_info(runs)').all().map(c => c.name);
    if (columns.length === 0 || columns.includes('instance_id')) return;

    console.log('[Database] Migrating runs table: adding instance_id and the interrupted status.');
    db.transaction(() => {
        db.exec('ALTER TABLE runs RENAME TO runs_pre_instance');
        db.exec('DROP INDEX IF EXISTS idx_runs_user_started');
        db.exec('DROP INDEX IF EXISTS idx_runs_status');
        db.exec(`
            CREATE TABLE runs (
                request_id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                instance_id TEXT,
                status TEXT NOT NULL CHECK(status IN ('running', 'completed', 'failed', 'interrupted')),
                question TEXT NOT NULL,
                planner_json TEXT,
                tools_json TEXT,
                report_text TEXT,
                timings_json TEXT,
                errors_json TEXT,
                model_generated INTEGER,
                generation_json TEXT,
                started_at TEXT NOT NULL,
                completed_at TEXT
            );
        `);
        db.exec(`
            INSERT INTO runs (request_id, user_id, instance_id, status, question, planner_json, tools_json, report_text,
                              timings_json, errors_json, model_generated, generation_json, started_at, completed_at)
            SELECT request_id, user_id, NULL, status, question, planner_json, tools_json, report_text,
                   timings_json, errors_json, model_generated, generation_json, started_at, completed_at
            FROM runs_pre_instance
        `);
        db.exec('DROP TABLE runs_pre_instance');
    })();
}

export function initDatabase() {
    console.log(`[Database] Initializing SQLite database at: ${dbPath}`);

    // 1. Users Table
    db.exec(`
        CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            username TEXT UNIQUE NOT NULL COLLATE NOCASE,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL CHECK(role IN ('admin', 'user')),
            created_at TEXT NOT NULL
        );
    `);

    // Forced password change (F-08b). Added after the table existed, so migrate in place.
    const userColumns = db.prepare('PRAGMA table_info(users)').all().map(c => c.name);
    if (!userColumns.includes('must_change_password')) {
        db.exec('ALTER TABLE users ADD COLUMN must_change_password INTEGER NOT NULL DEFAULT 0');
    }
    // An existing admin still on the published default password must change it at next login.
    const seededAdmin = db.prepare("SELECT password_hash, must_change_password FROM users WHERE id = 'user_admin_root'").get();
    if (seededAdmin && !seededAdmin.must_change_password && bcrypt.compareSync(PUBLISHED_DEFAULT_ADMIN_PASSWORD, seededAdmin.password_hash)) {
        db.prepare("UPDATE users SET must_change_password = 1 WHERE id = 'user_admin_root'").run();
        console.log('[Database] Default admin still uses the published default password: a change is required at next login.');
    }

    // 2. Chat Sessions Table
    db.exec(`
        CREATE TABLE IF NOT EXISTS sessions (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            title TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );
    `);

    // 3. Messages Table
    db.exec(`
        CREATE TABLE IF NOT EXISTS messages (
            id TEXT PRIMARY KEY,
            session_id TEXT NOT NULL,
            user_id TEXT NOT NULL,
            role TEXT NOT NULL,
            type TEXT NOT NULL,
            text TEXT,
            summary TEXT,
            raw_logs TEXT,
            total_hits INTEGER,
            is_new INTEGER DEFAULT 0,
            created_at TEXT NOT NULL,
            FOREIGN KEY (session_id) REFERENCES sessions(id) ON DELETE CASCADE,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );
    `);

    // Links a saved report to its run record. Added after the table existed, so migrate in place.
    const messageColumns = db.prepare('PRAGMA table_info(messages)').all().map(c => c.name);
    if (!messageColumns.includes('request_id')) {
        db.exec('ALTER TABLE messages ADD COLUMN request_id TEXT');
    }
    db.exec('CREATE INDEX IF NOT EXISTS idx_messages_request_id ON messages(request_id)');

    // 4. Agent Memories Table (Persistent Long-Term Memory)
    db.exec(`
        CREATE TABLE IF NOT EXISTS memories (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            category TEXT NOT NULL,
            term_type TEXT NOT NULL,
            content TEXT NOT NULL,
            relevance_score INTEGER DEFAULT 50,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );
    `);
    // 5. Quick Queries Table (User-specific custom queries)
    db.exec(`
        CREATE TABLE IF NOT EXISTS quick_queries (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            label TEXT NOT NULL,
            prompt TEXT NOT NULL,
            icon_name TEXT DEFAULT 'MessageSquare',
            created_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );
    `);

    // 6. Agent Run Records (one row per runAgentWorkflow execution)
    // No foreign key to users: run records are an audit trail and must survive user deletion.
    // Stores metadata and counts only, never raw SIEM logs.
    // status 'interrupted': the server instance that owned the run stopped before it finished.
    migrateRunsTableWithoutInstanceId();
    db.exec(`
        CREATE TABLE IF NOT EXISTS runs (
            request_id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            instance_id TEXT,
            status TEXT NOT NULL CHECK(status IN ('running', 'completed', 'failed', 'interrupted')),
            question TEXT NOT NULL,
            planner_json TEXT,
            tools_json TEXT,
            report_text TEXT,
            timings_json TEXT,
            errors_json TEXT,
            model_generated INTEGER,
            generation_json TEXT,
            started_at TEXT NOT NULL,
            completed_at TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_runs_user_started ON runs(user_id, started_at);
        CREATE INDEX IF NOT EXISTS idx_runs_status ON runs(status, instance_id);
    `);

    // 7. Seed Default Admin User if no admin exists
    const adminCheck = db.prepare("SELECT id, username FROM users WHERE role = 'admin'").get();
    if (!adminCheck) {
        const adminId = 'user_admin_root';
        const passwordHash = bcrypt.hashSync(ADMIN_INITIAL_PASSWORD, 10);
        const createdAt = new Date().toISOString();

        db.prepare(`
            INSERT INTO users (id, username, password_hash, role, created_at, must_change_password)
            VALUES (?, ?, ?, 'admin', ?, 1)
        `).run(adminId, ADMIN_INITIAL_USER, passwordHash, createdAt);

        console.log(`[Database] 👑 Default admin user seeded successfully (username: '${ADMIN_INITIAL_USER}').`);
    } else {
        console.log(`[Database] Administrator user already exists.`);
    }

    console.log(`[Database] All tables and indexes verified.`);
}

export default db;
