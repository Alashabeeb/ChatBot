import jwt from 'jsonwebtoken';
import { JWT_SECRET } from '../config/env.js';
import { UserModel } from '../models/User.js';

// While a password change is required, only these endpoints are reachable (F-08b).
const ALLOWED_DURING_PASSWORD_CHANGE = new Set(['/api/auth/me', '/api/auth/change-password']);
const pathOf = url => (url || '').split('?')[0].replace(/\/+$/, '');

export function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.startsWith('Bearer ') ? authHeader.split(' ')[1] : null;

    if (!token) {
        return res.status(401).json({
            type: 'error',
            error: 'Authentication required. No authorization token provided.'
        });
    }

    let decoded;
    try {
        decoded = jwt.verify(token, JWT_SECRET);
    } catch (err) {
        return res.status(403).json({
            type: 'error',
            error: 'Invalid or expired session token. Please log in again.'
        });
    }

    // F-24: the token proves who signed in; the database decides whether that account still exists
    // and what it may do. A deleted user is refused, and the role is never taken from the token.
    const user = UserModel.findById(decoded.id);
    if (!user) {
        return res.status(401).json({
            type: 'error',
            error: 'This account no longer exists. Please log in again.'
        });
    }
    req.user = {
        id: user.id,
        username: user.username,
        role: user.role,
        mustChangePassword: user.must_change_password === 1
    };

    if (req.user.mustChangePassword && !ALLOWED_DURING_PASSWORD_CHANGE.has(pathOf(req.originalUrl))) {
        return res.status(403).json({
            type: 'error',
            code: 'PASSWORD_CHANGE_REQUIRED',
            error: 'You must change your password before continuing.'
        });
    }
    next();
}

export function requireAdmin(req, res, next) {
    if (!req.user || req.user.role !== 'admin') {
        return res.status(403).json({
            type: 'error',
            error: 'Access denied: Admin privileges are required to perform this action.'
        });
    }
    next();
}
