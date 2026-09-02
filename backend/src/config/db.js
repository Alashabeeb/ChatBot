import Database from 'better-sqlite3';
import path from 'path';
import fs from 'fs';
import bcrypt from 'bcryptjs';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Data directory path: backend/data
const dataDir = path.resolve(__dirname, '../../data');
if (!fs.existsSync(dataDir)) {
    fs.mkdirSync(dataDir, { recursive: true });
}

const dbPath = path.join(dataDir, 'soc_chatbot.db');
const db = new Database(dbPath);

import { ADMIN_INITIAL_USER, ADMIN_INITIAL_PASSWORD } from './env.js';

// Enable WAL mode & Foreign Keys for fast concurrency and data integrity
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

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

    // 6. Seed Default Admin User if no admin exists
    const adminCheck = db.prepare("SELECT id, username FROM users WHERE role = 'admin'").get();
    if (!adminCheck) {
        const adminId = 'user_admin_root';
        const passwordHash = bcrypt.hashSync(ADMIN_INITIAL_PASSWORD, 10);
        const createdAt = new Date().toISOString();

        db.prepare(`
            INSERT INTO users (id, username, password_hash, role, created_at)
            VALUES (?, ?, ?, 'admin', ?)
        `).run(adminId, ADMIN_INITIAL_USER, passwordHash, createdAt);

        console.log(`[Database] 👑 Default admin user seeded successfully (username: '${ADMIN_INITIAL_USER}').`);
    } else {
        console.log(`[Database] Administrator user already exists.`);
    }

    console.log(`[Database] All tables and indexes verified.`);
}

export default db;
