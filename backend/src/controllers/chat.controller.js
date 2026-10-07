import { processChatQuery } from '../services/chat.service.js';
import { sanitizeChatHistory } from '../utils/history.util.js';

export async function handleChat(req, res) {
    const { text, history: rawHistory = [] } = req.body;

    try {
        const userId = req.user?.id || 'default_user_1';

        // History comes from the client and is untrusted: only user/assistant turns may reach the model.
        const { history, dropped } = sanitizeChatHistory(rawHistory);
        if (dropped > 0) {
            console.warn(`[Chat] Dropped ${dropped} history entr${dropped === 1 ? 'y' : 'ies'} with a disallowed role or malformed content (user ${userId}).`);
        }

        const responseData = await processChatQuery(text, history, userId);
        return res.json(responseData);
    } catch (error) {
        console.error(`${error.requestId ? `[req:${error.requestId}] ` : ''}Controller Error:`, error.message);
        res.status(500).json({
            type: 'text',
            request_id: error.requestId || null,
            text: `⚠️ System Error: ${error.message}. Please ensure backend connections (Ports 9200, 55000) are reachable.`
        });
    }
}
