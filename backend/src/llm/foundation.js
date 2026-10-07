import axios from 'axios';
import { LLM_API_URL, LLM_DEFAULT_TIMEOUT_MS } from '../config/env.js';
import { runLog, recordRunError } from '../observability/runContext.js';

export const MODEL_NAME = 'foundation-sec-8b-instruct';

const CHAT_ROLES = new Set(['user', 'assistant']);

/**
 * Handles communication with the Foundation-sec-8B model.
 * options.timeout (ms) bounds the whole call (F-03); a missing or invalid value falls back to
 * LLM_DEFAULT_TIMEOUT_MS, never to "wait forever". History entries that aren't { role: 'user' |
 * 'assistant', content: string } are skipped (F-22): only systemInstruction has system authority.
 * Returns the reply text, or null on any failure (callers fall back).
 */
export async function askFoundation(prompt, systemInstruction, conversationHistory = [], options = {}) {
    try {
        const { maxTokens } = options;
        const timeout = Number.isFinite(options.timeout) && options.timeout > 0 ? options.timeout : LLM_DEFAULT_TIMEOUT_MS;
        const messages = [
            { role: "system", content: systemInstruction }
        ];

        for (const msg of Array.isArray(conversationHistory) ? conversationHistory : []) {
            if (msg && CHAT_ROLES.has(msg.role) && typeof msg.content === 'string') {
                messages.push({ role: msg.role, content: msg.content });
            }
        }

        messages.push({ role: "user", content: prompt });

        const requestBody = {
            model: MODEL_NAME,
            messages
        };
        if (maxTokens) requestBody.max_tokens = maxTokens;

        // timeout: no response in time. signal: hard deadline for the whole call, body included.
        const response = await axios.post(LLM_API_URL, requestBody, { timeout, signal: AbortSignal.timeout(timeout) });
        
        return response.data.choices[0].message.content.trim();
    } catch (error) {
        runLog.warn('Foundation-sec-8B request failed.', error.message);
        recordRunError('llm', error.message);
        return null;
    }
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
