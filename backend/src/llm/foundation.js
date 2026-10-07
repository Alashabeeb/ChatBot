import axios from 'axios';
import { LLM_API_URL } from '../config/env.js';
import { runLog, recordRunError } from '../observability/runContext.js';

export const MODEL_NAME = 'foundation-sec-8b-instruct';

/**
 * Handles communication with the Foundation-sec-8B model.
 */
export async function askFoundation(prompt, systemInstruction, conversationHistory = []) {
    try {
        const messages = [
            { role: "system", content: systemInstruction }
        ];

        for (const msg of conversationHistory) {
            messages.push({ role: msg.role, content: msg.content });
        }

        messages.push({ role: "user", content: prompt });

        const response = await axios.post(LLM_API_URL, {
            model: MODEL_NAME,
            messages
        }, { timeout: 0 });
        
        return response.data.choices[0].message.content.trim();
    } catch (error) {
        runLog.warn("Foundation-sec-8B Unreachable. Falling back to rule-based logic.", error.message);
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
