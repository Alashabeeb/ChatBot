import { MemoryProvider } from './MemoryProvider.interface.js';
import db from '../../config/db.js';

/**
 * SQLite-backed Memory Provider for persistent agent memory across restarts.
 */
export class SqliteMemoryProvider extends MemoryProvider {
    async connect() {
        console.log("[SqliteMemoryProvider] Connected to SQLite memory store.");
    }

    async findMemories(userId, filters = {}) {
        let query = 'SELECT id, user_id, category, term_type, content, relevance_score, created_at, updated_at FROM memories WHERE user_id = ?';
        const params = [userId];

        if (filters.category) {
            query += ' AND category = ?';
            params.push(filters.category);
        }

        if (filters.termType) {
            query += ' AND term_type = ?';
            params.push(filters.termType);
        }

        query += ' ORDER BY relevance_score DESC, created_at DESC';

        const rows = db.prepare(query).all(...params);

        return rows.map(row => {
            let parsedContent = row.content;
            try {
                parsedContent = JSON.parse(row.content);
            } catch (e) {
                // keep string if not json
            }

            return {
                id: row.id,
                userId: row.user_id,
                category: row.category,
                termType: row.term_type,
                content: parsedContent,
                relevanceScore: row.relevance_score,
                createdAt: row.created_at,
                updatedAt: row.updated_at
            };
        });
    }

    async saveMemory(memoryRecord) {
        const { id, userId, category, termType, content, relevanceScore } = memoryRecord;
        const now = new Date().toISOString();
        const contentStr = typeof content === 'string' ? content : JSON.stringify(content);

        db.prepare(`
            INSERT INTO memories (id, user_id, category, term_type, content, relevance_score, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        `).run(id, userId, category, termType, contentStr, relevanceScore || 50, now, now);

        return id;
    }

    async deleteMemory(memoryId, userId) {
        const res = db.prepare('DELETE FROM memories WHERE id = ? AND user_id = ?').run(memoryId, userId);
        return res.changes > 0;
    }
}
