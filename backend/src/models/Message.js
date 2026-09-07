import { randomUUID } from 'crypto';
import db from '../config/db.js';

export class MessageModel {
    static create({ id, sessionId, userId, role, type = 'text', text = '', summary = '', rawLogs = null, totalHits = 0, isNew = 0 }) {
        const msgId = id || 'msg_' + randomUUID();
        const now = new Date().toISOString();
        const rawLogsJson = rawLogs ? (typeof rawLogs === 'string' ? rawLogs : JSON.stringify(rawLogs)) : null;

        db.prepare(`
            INSERT INTO messages (id, session_id, user_id, role, type, text, summary, raw_logs, total_hits, is_new, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `).run(msgId, sessionId, userId, role, type, text || '', summary || '', rawLogsJson, totalHits || 0, isNew ? 1 : 0, now);

        // Update session's updated_at timestamp
        db.prepare(`
            UPDATE sessions
            SET updated_at = ?
            WHERE id = ?
        `).run(now, sessionId);

        return {
            id: msgId,
            session_id: sessionId,
            user_id: userId,
            role,
            type,
            text,
            summary,
            raw_logs: rawLogs,
            total_hits: totalHits,
            created_at: now
        };
    }

    static listBySessionId(sessionId, userId) {
        const rows = db.prepare(`
            SELECT id, session_id, user_id, role, type, text, summary, total_hits, created_at
            FROM messages
            WHERE session_id = ? AND user_id = ?
            ORDER BY created_at ASC
        `).all(sessionId, userId);

        return rows.map(row => ({
            id: row.id,
            sessionId: row.session_id,
            userId: row.user_id,
            role: row.role,
            type: row.type,
            text: row.text,
            summary: row.summary,
            total_hits: row.total_hits,
            timestamp: row.created_at
        }));
    }

    static getRawLogsById(msgId, userId) {
        const row = db.prepare(`
            SELECT raw_logs
            FROM messages
            WHERE id = ? AND user_id = ?
        `).get(msgId, userId);
        
        if (!row || !row.raw_logs) return [];
        try {
            return JSON.parse(row.raw_logs);
        } catch(e) {
            return [];
        }
    }
}
