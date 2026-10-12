import { modelFor, authorizationHeaders } from './models.js';

/**
 * A failure while streaming from the model. `code` is one of:
 *   model_unavailable  connection refused/reset, HTTP error, unreadable reply
 *   model_timeout      no first token within firstTokenTimeoutMs, or silence for idleTimeoutMs mid-answer
 *   aborted            the caller cancelled (the browser stopped the request)
 * `partialText` holds whatever the model produced before the failure, and `firstTokenMs` when its
 * first token arrived (null if none did).
 */
export class ModelStreamError extends Error {
    constructor(code, message) {
        super(message);
        this.name = 'ModelStreamError';
        this.code = code;
        this.partialText = '';
        this.firstTokenMs = null;
    }
}

/**
 * Streams a chat completion from the default model's OpenAI-compatible endpoint (LLM_API_URL), calling onToken for
 * each piece of text as it arrives. Servers that ignore `stream: true` and return plain JSON work too.
 * Resolves to { text, finishReason, firstTokenMs }; rejects with ModelStreamError.
 */
export async function streamChatCompletion({
    messages,
    maxTokens,
    temperature,
    signal,
    firstTokenTimeoutMs,
    idleTimeoutMs,
    totalTimeoutMs = null,
    role = 'default',
    onToken = () => {}
}) {
    const controller = new AbortController();
    const started = Date.now();
    let text = '';
    let finishReason = null;
    let firstTokenMs = null;

    const fail = (code, message) => {
        const error = new ModelStreamError(code, message);
        error.partialText = text;
        error.firstTokenMs = firstTokenMs;
        return error;
    };
    let timer;
    const armTimeout = (ms, message) => {
        clearTimeout(timer);
        timer = setTimeout(() => controller.abort(fail('model_timeout', message)), ms);
    };
    const onCallerAbort = () => controller.abort(fail('aborted', 'The request was cancelled.'));
    if (signal?.aborted) onCallerAbort();
    signal?.addEventListener('abort', onCallerAbort, { once: true });

    const emit = piece => {
        if (!piece) return;
        if (firstTokenMs === null) firstTokenMs = Date.now() - started;
        text += piece;
        onToken(piece);
    };

    armTimeout(firstTokenTimeoutMs, `The model did not start answering within ${Math.round(firstTokenTimeoutMs / 1000)} seconds.`);
    // A hard deadline for the whole answer, whatever the pace of the tokens (used for search reports).
    const totalTimer = totalTimeoutMs ? setTimeout(() => controller.abort(fail('model_timeout', `The model did not finish within ${Math.round(totalTimeoutMs / 1000)} seconds.`)), totalTimeoutMs) : null;
    try {
        const config = modelFor(role);
        const response = await fetch(config.url, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', Accept: 'text/event-stream', ...authorizationHeaders(config) },
            body: JSON.stringify({ model: config.model, messages, stream: true, max_tokens: maxTokens, temperature }),
            signal: controller.signal
        });
        if (!response.ok) {
            throw fail('model_unavailable', `The model server returned HTTP ${response.status}.`);
        }

        if (!(response.headers.get('content-type') || '').includes('text/event-stream')) {
            const json = await response.json();
            emit(json?.choices?.[0]?.message?.content ?? '');
            finishReason = json?.choices?.[0]?.finish_reason ?? null;
            return { text, finishReason, firstTokenMs };
        }

        const decoder = new TextDecoder();
        let buffer = '';
        for await (const chunk of response.body) {
            buffer += decoder.decode(chunk, { stream: true });
            const events = buffer.split(/\r?\n\r?\n/);
            buffer = events.pop();
            for (const event of events) {
                const data = event.split(/\r?\n/).filter(l => l.startsWith('data:')).map(l => l.slice(5).trimStart()).join('\n');
                if (!data) continue;
                if (data === '[DONE]') return { text, finishReason, firstTokenMs };
                let parsed;
                try {
                    parsed = JSON.parse(data);
                } catch {
                    continue; // tolerate keep-alive or non-JSON lines
                }
                const choice = parsed?.choices?.[0];
                emit(choice?.delta?.content ?? '');
                if (choice?.finish_reason) finishReason = choice.finish_reason;
            }
            if (firstTokenMs !== null) {
                armTimeout(idleTimeoutMs, `The model stopped responding for ${Math.round(idleTimeoutMs / 1000)} seconds.`);
            }
        }
        return { text, finishReason, firstTokenMs };
    } catch (error) {
        if (controller.signal.aborted && controller.signal.reason instanceof ModelStreamError) {
            const reason = controller.signal.reason;
            reason.partialText = text;          // tokens may have arrived after the abort was triggered
            reason.firstTokenMs = firstTokenMs;
            throw reason;
        }
        if (error instanceof ModelStreamError) throw error;
        throw fail('model_unavailable', `Could not reach the model: ${error.cause?.code || error.message}.`);
    } finally {
        clearTimeout(timer);
        clearTimeout(totalTimer);
        signal?.removeEventListener('abort', onCallerAbort);
    }
}
