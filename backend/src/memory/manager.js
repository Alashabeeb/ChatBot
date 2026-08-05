import { retrieveRelevantMemories } from './retriever.js';
import { writeMemory } from './writer.js';
import { summarizeInvestigation } from './summarizer.js';

/**
 * Memory Manager
 * High-level orchestration for memory tasks.
 */
export const memoryManager = {
    retrieve: retrieveRelevantMemories,
    write: writeMemory,
    summarize: summarizeInvestigation
};
