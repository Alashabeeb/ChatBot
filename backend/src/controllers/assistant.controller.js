import { randomUUID } from 'crypto';
import {
    LLM_CHAT_MAX_TOKENS,
    LLM_CHAT_TEMPERATURE,
    LLM_STREAM_FIRST_TOKEN_TIMEOUT_MS,
    LLM_STREAM_IDLE_TIMEOUT_MS,
    LLM_CHAT_HISTORY_CHAR_BUDGET,
    CHAT_MAX_MESSAGE_CHARS
} from '../config/env.js';
import { modelFor } from '../llm/models.js';
import { streamChatCompletion } from '../llm/streamChat.js';
import { buildChatMessages, looksLikeDataQuestion } from '../services/assistant.service.js';
import { sanitizeChatHistory } from '../utils/history.util.js';
import { RunModel } from '../models/Run.js';
import { SERVER_INSTANCE_ID } from '../observability/instance.js';
import { withRunScope, runLog, recordRunError, currentRunErrors } from '../observability/runContext.js';

const USER_MESSAGES = {
    model_unavailable: 'The AI model is unavailable right now, so nothing was generated. Please try again in a moment.',
    model_timeout: 'The AI model did not respond in time, so nothing was generated. It may be busy; please try again.',
    model_timeout_partial: 'The AI model stopped responding, so this answer is incomplete.'
};

/**
 * POST /api/chat/stream — general chat with the model, streamed as server-sent events:
 *   meta  { request_id, mode }            first, always
 *   token { text }                        each piece of the answer as it is generated
 *   error { code, message }               model unavailable or timed out (honest, user-facing)
 *   done  { request_id, model_generated, truncated, finish_reason, suggest_search, mode }   last, always
 * The model is never told it can see live data, and every chat is a run record (generation.mode 'chat').
 */
export async function handleChatStream(req, res) {
    const text = typeof req.body?.text === 'string' ? req.body.text.trim() : '';
    if (!text) {
        return res.status(400).json({ type: 'error', error: 'Please enter a message.' });
    }
    if (text.length > CHAT_MAX_MESSAGE_CHARS) {
        return res.status(413).json({ type: 'error', error: `That message is too long (${text.length.toLocaleString('en-US')} characters; the limit is ${CHAT_MAX_MESSAGE_CHARS.toLocaleString('en-US')}).` });
    }

    const userId = req.user?.id || 'default_user_1';
    const { history, dropped } = sanitizeChatHistory(req.body.history ?? []);
    const requestId = randomUUID();

    return withRunScope(requestId, async () => {
        if (dropped > 0) runLog.warn(`[Chat] Dropped ${dropped} history entr${dropped === 1 ? 'y' : 'ies'} with a disallowed role or malformed content.`);
        const started = Date.now();
        try {
            RunModel.start({ requestId, userId, instanceId: SERVER_INSTANCE_ID, question: text, startedAt: new Date(started).toISOString() });
        } catch (error) {
            runLog.error(`[Run Record] Failed to create run record: ${error.message}`);
        }

        res.writeHead(200, {
            'Content-Type': 'text/event-stream; charset=utf-8',
            'Cache-Control': 'no-cache, no-transform',
            Connection: 'keep-alive',
            'X-Accel-Buffering': 'no'
        });
        const send = (event, data) => {
            if (!res.writableEnded && !res.destroyed) res.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`);
        };

        // If the browser goes away (Stop, closed tab), cancel the model request too.
        const upstream = new AbortController();
        res.on('close', () => { if (!res.writableEnded) upstream.abort(); });

        send('meta', { request_id: requestId, mode: 'chat' });

        let answer = '';
        let finishReason = null;
        let firstTokenMs = null;
        let failure = null;
        try {
            const result = await streamChatCompletion({
                messages: buildChatMessages({ text, history, historyCharBudget: LLM_CHAT_HISTORY_CHAR_BUDGET }),
                maxTokens: LLM_CHAT_MAX_TOKENS,
                temperature: LLM_CHAT_TEMPERATURE,
                signal: upstream.signal,
                firstTokenTimeoutMs: LLM_STREAM_FIRST_TOKEN_TIMEOUT_MS,
                idleTimeoutMs: LLM_STREAM_IDLE_TIMEOUT_MS,
                onToken: piece => send('token', { text: piece })
            });
            ({ text: answer, finishReason, firstTokenMs } = result);
        } catch (error) {
            failure = error;
            answer = error.partialText || '';
            firstTokenMs = error.firstTokenMs ?? null;
            recordRunError(error.code === 'aborted' ? 'client' : 'llm', error.message);
            if (error.code !== 'aborted') {
                runLog.warn(`[Chat] Model stream failed (${error.code}): ${error.message}`);
                const key = error.code === 'model_timeout' && answer ? 'model_timeout_partial' : error.code;
                send('error', { code: error.code, message: USER_MESSAGES[key] || USER_MESSAGES.model_unavailable });
            }
        }

        const modelGenerated = answer.length > 0;
        const truncated = finishReason === 'length' || (Boolean(failure) && modelGenerated);
        const stopped = failure?.code === 'aborted';
        const report = stopped ? 'stopped' : !modelGenerated ? 'fallback_model_unavailable' : truncated ? 'model_truncated' : 'model';
        const generation = { mode: 'chat', planner: null, report, model: modelFor('default').model };

        send('done', {
            request_id: requestId,
            mode: 'chat',
            model_generated: modelGenerated,
            truncated,
            finish_reason: finishReason,
            suggest_search: looksLikeDataQuestion(text)
        });
        if (!res.writableEnded) res.end();

        try {
            RunModel.finish(requestId, {
                status: !stopped && failure && !modelGenerated ? 'failed' : 'completed',
                planner: null,
                tools: [],
                reportText: answer,
                timings: { firstTokenMs, totalDuration: Date.now() - started },
                errors: currentRunErrors(),
                modelGenerated,
                generation,
                completedAt: new Date().toISOString()
            });
        } catch (error) {
            runLog.error(`[Run Record] Failed to finalize run record: ${error.message}`);
        }
        runLog.info(`[Chat Complete] RequestID: ${requestId} | report=${report} first_token_ms=${firstTokenMs} total_ms=${Date.now() - started}`);
    }, { question: text });
}
