import { SessionModel } from '../models/Session.js';
import { MessageModel } from '../models/Message.js';

export async function listSessions(req, res) {
    try {
        const sessions = SessionModel.listByUserId(req.user.id);
        return res.json({ success: true, sessions });
    } catch (error) {
        return res.status(500).json({ type: 'error', error: error.message });
    }
}

export async function createSession(req, res) {
    try {
        const { id, title } = req.body;
        const session = SessionModel.create({
            id,
            userId: req.user.id,
            title: title || 'New Security Investigation'
        });
        return res.status(201).json({ success: true, session });
    } catch (error) {
        return res.status(500).json({ type: 'error', error: error.message });
    }
}

export async function getSessionMessages(req, res) {
    try {
        const { id } = req.params;
        const messages = MessageModel.listBySessionId(id, req.user.id);
        return res.json({ success: true, messages });
    } catch (error) {
        return res.status(500).json({ type: 'error', error: error.message });
    }
}

export async function saveSessionMessage(req, res) {
    try {
        const { id: sessionId } = req.params;
        const { id: msgId, role, type, text, summary, rawLogs, totalHits, isNew } = req.body;

        // Ensure session exists or create it
        let session = SessionModel.findById(sessionId, req.user.id);
        if (!session) {
            let sessionTitle = text ? (text.length > 40 ? text.substring(0, 37) + '...' : text) : 'Investigation';
            sessionTitle = sessionTitle.charAt(0).toUpperCase() + sessionTitle.slice(1);
            session = SessionModel.create({
                id: sessionId,
                userId: req.user.id,
                title: sessionTitle
            });
        }

        const message = MessageModel.create({
            id: msgId,
            sessionId,
            userId: req.user.id,
            role,
            type: type || 'text',
            text: text || '',
            summary: summary || '',
            rawLogs: rawLogs || null,
            totalHits: totalHits || 0,
            isNew: isNew ? 1 : 0
        });

        return res.status(201).json({ success: true, message });
    } catch (error) {
        return res.status(500).json({ type: 'error', error: error.message });
    }
}

export async function deleteSession(req, res) {
    try {
        const { id } = req.params;
        const deleted = SessionModel.delete(id, req.user.id);
        return res.json({ success: deleted });
    } catch (error) {
        return res.status(500).json({ type: 'error', error: error.message });
    }
}

export async function clearAllSessions(req, res) {
    try {
        SessionModel.clearAllByUserId(req.user.id);
        return res.json({ success: true });
    } catch (error) {
        return res.status(500).json({ type: 'error', error: error.message });
    }
}
