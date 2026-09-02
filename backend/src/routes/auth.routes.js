import { Router } from 'express';
import {
    login,
    getMe,
    listUsers,
    createUser,
    deleteUser
} from '../controllers/auth.controller.js';
import { authenticateToken, requireAdmin } from '../middleware/auth.middleware.js';

const router = Router();

// Public route (Sign-In)
router.post('/login', login);

// Authenticated self-inspection
router.get('/me', authenticateToken, getMe);

// Admin-only User Management routes
router.get('/users', authenticateToken, requireAdmin, listUsers);
router.post('/users', authenticateToken, requireAdmin, createUser);
router.delete('/users/:id', authenticateToken, requireAdmin, deleteUser);

export default router;
