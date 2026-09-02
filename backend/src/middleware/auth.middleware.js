import jwt from 'jsonwebtoken';
import { JWT_SECRET } from '../config/env.js';

export function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.startsWith('Bearer ') ? authHeader.split(' ')[1] : null;

    if (!token) {
        return res.status(401).json({
            type: 'error',
            error: 'Authentication required. No authorization token provided.'
        });
    }

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        req.user = {
            id: decoded.id,
            username: decoded.username,
            role: decoded.role
        };
        next();
    } catch (err) {
        return res.status(403).json({
            type: 'error',
            error: 'Invalid or expired session token. Please log in again.'
        });
    }
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
