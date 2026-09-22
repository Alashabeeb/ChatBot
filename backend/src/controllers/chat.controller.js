import { processChatQuery } from '../services/chat.service.js';

export async function handleChat(req, res) {
    const { text, history = [] } = req.body;

    try {
        const userId = req.user?.id || 'default_user_1';
        const responseData = await processChatQuery(text, history, userId);
        return res.json(responseData);
    } catch (error) {
        console.error('Controller Error:', error.message);
        res.status(error.statusCode || 500).json({
            type: 'error',
            error: error.statusCode
                ? error.message
                : `System error: ${error.message}. Please ensure backend connections (Ports 9200, 55000) are reachable.`
        });
    }
}
