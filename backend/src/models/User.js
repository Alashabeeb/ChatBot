import { randomUUID } from 'crypto';
import bcrypt from 'bcryptjs';
import db from '../config/db.js';
import { PUBLISHED_DEFAULT_ADMIN_PASSWORD } from '../config/env.js';

export const MIN_PASSWORD_LENGTH = 12;

/** Returns a reason the new password is unacceptable, or null if it's fine. */
export function passwordProblem(newPassword, { username, currentPassword } = {}) {
    if (typeof newPassword !== 'string' || newPassword.length < MIN_PASSWORD_LENGTH) {
        return `The new password must be at least ${MIN_PASSWORD_LENGTH} characters long.`;
    }
    if (newPassword === currentPassword) return 'The new password must be different from the current one.';
    if (newPassword === PUBLISHED_DEFAULT_ADMIN_PASSWORD) return 'That is the published default password. Choose another.';
    if (username && newPassword.toLowerCase().includes(username.toLowerCase())) return 'The new password must not contain your username.';
    if (new Set(newPassword).size < 6) return 'The new password is too repetitive. Use a mix of characters, or a few unrelated words.';
    return null;
}

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
        return db.prepare('SELECT id, username, role, created_at, must_change_password FROM users WHERE id = ?').get(id);
    }

    /** Verifies the current password, applies the policy, stores the new hash and clears the flag. */
    static changePassword(id, currentPassword, newPassword) {
        const user = db.prepare('SELECT id, username, password_hash FROM users WHERE id = ?').get(id);
        if (!user) throw Object.assign(new Error('User not found.'), { status: 404 });
        if (!UserModel.verifyPassword(currentPassword, user.password_hash)) {
            throw Object.assign(new Error('The current password is incorrect.'), { status: 400 });
        }
        const problem = passwordProblem(newPassword, { username: user.username, currentPassword });
        if (problem) throw Object.assign(new Error(problem), { status: 400 });
        db.prepare('UPDATE users SET password_hash = ?, must_change_password = 0 WHERE id = ?').run(bcrypt.hashSync(newPassword, 10), id);
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
