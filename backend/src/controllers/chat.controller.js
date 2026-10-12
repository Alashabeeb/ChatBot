import { processChatQuery } from '../services/chat.service.js';
import { sanitizeChatHistory } from '../utils/history.util.js';
import { openEventStream } from './assistant.controller.js';

export async function handleChat(req, res) {
    const { text, history: rawHistory = [] } = req.body;

    try {
        const userId = req.user?.id || 'default_user_1';

        // History comes from the client and is untrusted: only user/assistant turns may reach the model.
        const { history, dropped } = sanitizeChatHistory(rawHistory);
        if (dropped > 0) {
            console.warn(`[Chat] Dropped ${dropped} history entr${dropped === 1 ? 'y' : 'ies'} with a disallowed role or malformed content (user ${userId}).`);
        }

        const followUpOf = typeof req.body.follow_up_of === 'string' ? req.body.follow_up_of : null;
        const responseData = await processChatQuery(text, history, userId, { followUpOf });
        return res.json(responseData);
    } catch (error) {
        console.error(`${error.requestId ? `[req:${error.requestId}] ` : ''}Controller Error:`, error.message);
        res.status(error.statusCode || 500).json({
            type: 'error',
            request_id: error.requestId || null,
            error: error.statusCode
                ? error.message
                : `System error: ${error.message}. Please ensure backend connections (Ports 9200, 55000) are reachable.`
        });
    }
}

/**
 * POST /api/chat/search/stream — Search Wazuh, streamed as server-sent events (Phase 7):
 *   meta   { request_id, mode: 'search' }   when the run starts
 *   stage  { stage, label }                 planning | reading | searching | analysing | verifying, as each actually starts
 *   report { markdown }                     the answer so far: the code-written header first, then each
 *                                           statement as soon as it has passed verification
 *   error  { message }                      the run failed
 *   done   { response }                     last: exactly what POST /api/chat returns
 * Nothing unverified is ever sent. If the browser goes away, the model request is cancelled.
 */
export async function handleSearchStream(req, res) {
    const text = typeof req.body?.text === 'string' ? req.body.text : '';
    const userId = req.user?.id || 'default_user_1';
    const { history, dropped } = sanitizeChatHistory(req.body?.history ?? []);
    if (dropped > 0) console.warn(`[Chat] Dropped ${dropped} history entr${dropped === 1 ? 'y' : 'ies'} with a disallowed role or malformed content (user ${userId}).`);
    const followUpOf = typeof req.body?.follow_up_of === 'string' ? req.body.follow_up_of : null;
    const { send, signal } = openEventStream(req, res);
    await runSearchStream({ text, history, userId, followUpOf, send, signal });
    if (!res.writableEnded) res.end();
}

/**
 * A Search Wazuh answer, streamed into an open event stream (meta, stage, report, error, done).
 * route: the routing decision, when the assistant chose to search itself (POST /api/chat/message);
 * the message is then searched even if it sounds conversational.
 */
export async function runSearchStream({ text, history, userId, followUpOf = null, send, signal, route = null }) {
    try {
        const response = await processChatQuery(text, history, userId, { followUpOf, emit: send, signal, route, forceSearch: Boolean(route) });
        send('done', { response });
    } catch (error) {
        console.error(`${error.requestId ? `[req:${error.requestId}] ` : ''}Search stream error:`, error.message);
        send('error', { message: `System error: ${error.message}.`, request_id: error.requestId ?? null });
    }
}
