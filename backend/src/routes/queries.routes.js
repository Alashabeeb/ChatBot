import express from 'express';
import crypto from 'crypto';
import db from '../config/db.js';
import { authenticateToken } from '../middleware/auth.middleware.js';

const router = express.Router();

// Apply auth middleware to all routes in this file
router.use(authenticateToken);

// [GET] Fetch all quick queries for the logged-in user
router.get('/', (req, res) => {
    try {
        const queries = db.prepare(`
            SELECT id, label, prompt, icon_name, created_at 
            FROM quick_queries 
            WHERE user_id = ? 
            ORDER BY created_at ASC
        `).all(req.user.id);

        res.json({ success: true, queries });
    } catch (error) {
        console.error('[Queries Route Error - GET]:', error);
        res.status(500).json({ success: false, error: 'Failed to fetch quick queries' });
    }
});

// [POST] Create a new quick query
router.post('/', (req, res) => {
    try {
        const { label, prompt, icon_name = 'MessageSquare' } = req.body;
        
        if (!label || !prompt) {
            return res.status(400).json({ success: false, error: 'Label and prompt are required' });
        }

        const id = `qq_${crypto.randomUUID()}`;
        const created_at = new Date().toISOString();

        db.prepare(`
            INSERT INTO quick_queries (id, user_id, label, prompt, icon_name, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
        `).run(id, req.user.id, label, prompt, icon_name, created_at);

        res.json({ 
            success: true, 
            query: { id, label, prompt, icon_name, created_at } 
        });
    } catch (error) {
        console.error('[Queries Route Error - POST]:', error);
        res.status(500).json({ success: false, error: 'Failed to create quick query' });
    }
});

// [PUT] Update an existing quick query
router.put('/:id', (req, res) => {
    try {
        const { id } = req.params;
        const { label, prompt, icon_name } = req.body;

        if (!label || !prompt) {
            return res.status(400).json({ success: false, error: 'Label and prompt are required' });
        }

        const result = db.prepare(`
            UPDATE quick_queries 
            SET label = ?, prompt = ?, icon_name = ?
            WHERE id = ? AND user_id = ?
        `).run(label, prompt, icon_name || 'MessageSquare', id, req.user.id);

        if (result.changes === 0) {
            return res.status(404).json({ success: false, error: 'Query not found or not authorized' });
        }

        res.json({ success: true });
    } catch (error) {
        console.error('[Queries Route Error - PUT]:', error);
        res.status(500).json({ success: false, error: 'Failed to update quick query' });
    }
});

// [DELETE] Delete a quick query
router.delete('/:id', (req, res) => {
    try {
        const { id } = req.params;

        const result = db.prepare(`
            DELETE FROM quick_queries 
            WHERE id = ? AND user_id = ?
        `).run(id, req.user.id);

        if (result.changes === 0) {
            return res.status(404).json({ success: false, error: 'Query not found or not authorized' });
        }

        res.json({ success: true });
    } catch (error) {
        console.error('[Queries Route Error - DELETE]:', error);
        res.status(500).json({ success: false, error: 'Failed to delete quick query' });
    }
});

export default router;
