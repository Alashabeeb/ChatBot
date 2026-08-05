import axios from 'axios';
import { LLM_API_URL } from '../config/env.js';

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
            model: 'foundation-sec-8b-instruct',
            messages
        }, { timeout: 0 });
        
        return response.data.choices[0].message.content.trim();
    } catch (error) {
        console.warn("Foundation-sec-8B Unreachable. Falling back to rule-based logic.", error.message);
        return null;
    }
}
