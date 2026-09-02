import { processChatQuery } from '../services/chat.service.js';

export async function handleChat(req, res) {
    const { text, sources, history = [] } = req.body;

    try {
        if (!sources || (!sources.includes('wazuh') && !sources.includes('all'))) {
            return res.json({
                type: 'text',
                text: 'Please select Wazuh from the Agents dropdown to query security data.'
            });
        }

        const userId = req.user?.id || 'default_user_1';
        const responseData = await processChatQuery(text, sources, history, userId);
        return res.json(responseData);
    } catch (error) {
        console.error('Controller Error:', error.message);
        res.status(500).json({
            type: 'text',
            text: `⚠️ System Error: ${error.message}. Please ensure backend connections (Ports 9200, 55000) are reachable.`
        });
    }
}
