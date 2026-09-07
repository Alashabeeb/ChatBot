import { Router } from 'express';
import {
    listSessions,
    createSession,
    getSessionMessages,
    saveSessionMessage,
    getMessageLogs,
    deleteSession,
    clearAllSessions
} from '../controllers/session.controller.js';
import { authenticateToken } from '../middleware/auth.middleware.js';

const router = Router();

// All session routes require authentication
router.use(authenticateToken);

router.get('/', listSessions);
router.post('/', createSession);
router.delete('/', clearAllSessions);

router.get('/:id/messages', getSessionMessages);
router.post('/:id/messages', saveSessionMessage);
router.get('/messages/:msgId/logs', getMessageLogs);
router.delete('/:id', deleteSession);

export default router;
