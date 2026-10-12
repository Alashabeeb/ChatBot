import axios from 'axios';
import { LLM_DEFAULT_TIMEOUT_MS } from '../config/env.js';
import { runLog, recordRunError } from '../observability/runContext.js';
import { modelFor, authorizationHeaders, DEFAULT_MODEL_NAME } from './models.js';

/** The default model's name. Per-role models come from modelFor() (src/llm/models.js). */
export const MODEL_NAME = DEFAULT_MODEL_NAME;

const CHAT_ROLES = new Set(['user', 'assistant']);

/**
 * Handles communication with the Foundation-sec-8B model.
 * options.timeout (ms) bounds the whole call (F-03); a missing or invalid value falls back to
 * LLM_DEFAULT_TIMEOUT_MS, never to "wait forever". History entries that aren't { role: 'user' |
 * 'assistant', content: string } are skipped (F-22): only systemInstruction has system authority.
 * options.role ('planner' | 'report' | 'default') picks the model (src/llm/models.js).
 * Returns the reply text, or null on any failure (callers fall back).
 */
export async function askFoundation(prompt, systemInstruction, conversationHistory = [], options = {}) {
    try {
        const { maxTokens } = options;
        const config = modelFor(options.role);
        const timeout = Number.isFinite(options.timeout) && options.timeout > 0 ? options.timeout : LLM_DEFAULT_TIMEOUT_MS;
        const messages = buildModelMessages(prompt, systemInstruction, conversationHistory);

        const requestBody = {
            model: config.model,
            messages
        };
        if (maxTokens) requestBody.max_tokens = maxTokens;

        // timeout: no response in time. signal: hard deadline for the whole call, body included.
        const response = await axios.post(config.url, requestBody, { timeout, signal: AbortSignal.timeout(timeout), headers: authorizationHeaders(config) });
        
        return response.data.choices[0].message.content.trim();
    } catch (error) {
        // The server's explanation, if it sent one (e.g. "maximum context length…"), goes into the run record.
        const body = error.response?.data;
        const detail = body ? (typeof body === 'string' ? body : JSON.stringify(body)).replace(/\s+/g, ' ').trim().slice(0, 300) : '';
        const message = detail ? `${error.message}: ${detail}` : error.message;
        runLog.warn(`Model request failed (${options.role ?? 'default'}: ${modelFor(options.role).model}).`, message);
        recordRunError('llm', message);
        return null;
    }
}

/**
 * [system, ...history (user/assistant strings only, F-22), user]: the messages every model call sends.
 * Shared by askFoundation and the streamed search report, so both send exactly the same request.
 */
export function buildModelMessages(prompt, systemInstruction, conversationHistory = []) {
    const messages = [{ role: 'system', content: systemInstruction }];
    for (const msg of Array.isArray(conversationHistory) ? conversationHistory : []) {
        if (msg && CHAT_ROLES.has(msg.role) && typeof msg.content === 'string') {
            messages.push({ role: msg.role, content: msg.content });
        }
    }
    messages.push({ role: 'user', content: prompt });
    return messages;
}

/**
 * Safely extracts JSON from an LLM response that might contain markdown blocks or leading/trailing text.
 */
export function extractJSON(text) {
    if (!text) return null;
    try {
        // Find the first { or [ and the last } or ]
        const start = text.indexOf('{');
        const end = text.lastIndexOf('}');
        
        if (start === -1 || end === -1 || start > end) {
            // Try array brackets if object braces are missing
            const arrStart = text.indexOf('[');
            const arrEnd = text.lastIndexOf(']');
            if (arrStart !== -1 && arrEnd !== -1 && arrStart < arrEnd) {
                 return JSON.parse(text.substring(arrStart, arrEnd + 1));
            }
            throw new Error("No JSON object or array found in text.");
        }
        
        return JSON.parse(text.substring(start, end + 1));
    } catch (e) {
        throw new Error(`Failed to extract JSON from response: ${e.message}`);
    }
}
