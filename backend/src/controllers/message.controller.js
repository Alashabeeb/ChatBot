import { CHAT_MAX_MESSAGE_CHARS } from '../config/env.js';
import { sanitizeChatHistory } from '../utils/history.util.js';
import { routeMessage, routeByRules } from '../services/router.service.js';
import { openEventStream, runChatStream } from './assistant.controller.js';
import { runSearchStream } from './chat.controller.js';

/**
 * POST /api/chat/message — one endpoint for every message. The assistant decides whether it needs the
 * organisation's security data (router.service.js), then streams the answer either way:
 *   stage { stage: 'routing', label }   only when the model is asked to decide (unclear messages)
 *   meta  { request_id, mode: 'chat' | 'search', route: { route, by, reason } }
 *   then the chat events (token, error, done) or the search events (stage, report, error, done).
 * Body: { text, history, follow_up_of?, force_route?: 'search' | 'chat' } (force_route: the analyst's
 * "Search Wazuh for this" correction).
 */
export async function handleMessage(req, res) {
    const text = typeof req.body?.text === 'string' ? req.body.text.trim() : '';
    if (!text) return res.status(400).json({ type: 'error', error: 'Please enter a message.' });
    if (text.length > CHAT_MAX_MESSAGE_CHARS) {
        return res.status(413).json({ type: 'error', error: `That message is too long (${text.length.toLocaleString('en-US')} characters; the limit is ${CHAT_MAX_MESSAGE_CHARS.toLocaleString('en-US')}).` });
    }
    const userId = req.user?.id || 'default_user_1';
    const { history, dropped } = sanitizeChatHistory(req.body?.history ?? []);
    const followUpOf = typeof req.body?.follow_up_of === 'string' ? req.body.follow_up_of : null;
    const forceRoute = ['search', 'chat'].includes(req.body?.force_route) ? req.body.force_route : null;

    const { send, signal } = openEventStream(req, res);
    if (!forceRoute && !followUpOf && !routeByRules(text, history)) {
        send('stage', { stage: 'routing', label: 'Working out whether this needs your Wazuh data' });
    }
    const route = await routeMessage(text, history, { userId, followUpOf, forceRoute });
    console.log(`[Router] ${route.route} (${route.by}: ${route.reason})`);

    if (route.route === 'chat') await runChatStream({ text, history, dropped, userId, send, signal, route });
    else await runSearchStream({ text, history, userId, followUpOf, send, signal, route });
    if (!res.writableEnded) res.end();
}
