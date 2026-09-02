import { randomUUID } from 'crypto';
import bcrypt from 'bcryptjs';
import db from '../config/db.js';

export class UserModel {
    static create({ username, password, role = 'user' }) {
        if (!username || typeof username !== 'string' || username.trim().length < 3) {
            throw new Error('Username must be at least 3 characters long.');
        }

        if (!password || typeof password !== 'string' || password.length < 6) {
            throw new Error('Password must be at least 6 characters long.');
        }

        const validRoles = ['admin', 'user'];
        const userRole = validRoles.includes(role) ? role : 'user';
        const cleanUsername = username.trim();

        // Check if username already exists
        const existing = db.prepare('SELECT id FROM users WHERE username = ? COLLATE NOCASE').get(cleanUsername);
        if (existing) {
            throw new Error(`Username '${cleanUsername}' already exists.`);
        }

        const id = 'user_' + randomUUID();
        const passwordHash = bcrypt.hashSync(password, 10);
        const createdAt = new Date().toISOString();

        db.prepare(`
            INSERT INTO users (id, username, password_hash, role, created_at)
            VALUES (?, ?, ?, ?, ?)
        `).run(id, cleanUsername, passwordHash, userRole, createdAt);

        return {
            id,
            username: cleanUsername,
            role: userRole,
            created_at: createdAt
        };
    }

    static findByUsername(username) {
        if (!username) return null;
        return db.prepare('SELECT * FROM users WHERE username = ? COLLATE NOCASE').get(username.trim());
    }

    static findById(id) {
        if (!id) return null;
        return db.prepare('SELECT id, username, role, created_at FROM users WHERE id = ?').get(id);
    }

    static listAll() {
        return db.prepare('SELECT id, username, role, created_at FROM users ORDER BY created_at DESC').all();
    }

    static delete(id, requestingAdminId) {
        if (!id) throw new Error('User ID is required.');
        if (id === requestingAdminId) {
            throw new Error('Admins cannot delete their own active account.');
        }

        const targetUser = db.prepare('SELECT id, username, role FROM users WHERE id = ?').get(id);
        if (!targetUser) {
            throw new Error('User not found.');
        }

        db.prepare('DELETE FROM users WHERE id = ?').run(id);
        return { success: true, deletedUsername: targetUser.username };
    }

    static verifyPassword(plainPassword, passwordHash) {
        if (!plainPassword || !passwordHash) return false;
        return bcrypt.compareSync(plainPassword, passwordHash);
    }
}
