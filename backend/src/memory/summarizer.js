import { askFoundation } from '../llm/foundation.js';
import { SYSTEM_PROMPTS } from '../llm/prompts.js';

/**
 * Compresses long conversations or investigations into concise summaries using the LLM.
 */
export async function summarizeInvestigation(userRequest, finalResponse, evidence) {
    const prompt = `User Request: "${userRequest}"\n\nFinal Response:\n${finalResponse}\n\nEvidence Summary:\n${JSON.stringify(evidence.summary)}`;
    
    // Call LLM to summarize
    const summary = await askFoundation(prompt, SYSTEM_PROMPTS.MEMORY_SUMMARIZATION_PROMPT);
    return summary || "Investigation summarized implicitly.";
}
