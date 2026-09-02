import { randomUUID } from 'crypto';
import db from '../config/db.js';

export class SessionModel {
    static create({ id, userId, title }) {
        const sessionId = id || 'sess_' + randomUUID();
        const now = new Date().toISOString();
        const sessionTitle = title || 'New Security Investigation';

        db.prepare(`
            INSERT INTO sessions (id, user_id, title, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?)
        `).run(sessionId, userId, sessionTitle, now, now);

        return {
            id: sessionId,
            userId,
            title: sessionTitle,
            createdAt: now,
            updatedAt: now
        };
    }

    static listByUserId(userId) {
        return db.prepare(`
            SELECT id, user_id, title, created_at, updated_at
            FROM sessions
            WHERE user_id = ?
            ORDER BY updated_at DESC
        `).all(userId);
    }

    static findById(id, userId) {
        return db.prepare(`
            SELECT id, user_id, title, created_at, updated_at
            FROM sessions
            WHERE id = ? AND user_id = ?
        `).get(id, userId);
    }

    static updateTitle(id, userId, title) {
        const now = new Date().toISOString();
        db.prepare(`
            UPDATE sessions
            SET title = ?, updated_at = ?
            WHERE id = ? AND user_id = ?
        `).run(title, now, id, userId);
    }

    static delete(id, userId) {
        const res = db.prepare(`
            DELETE FROM sessions
            WHERE id = ? AND user_id = ?
        `).run(id, userId);
        return res.changes > 0;
    }

    static clearAllByUserId(userId) {
        db.prepare(`
            DELETE FROM sessions
            WHERE user_id = ?
        `).run(userId);
    }
}
