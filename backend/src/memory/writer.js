import { memoryGateway } from './gateway.js';
import { MemoryRecord } from './models.js';

/**
 * Handles saving memory while enforcing short/long term policies.
 */
export async function writeMemory(userId, category, content, policies = {}) {
    // Default policies
    const isImportant = policies.isImportant || false;
    const termType = isImportant ? 'long-term' : 'short-term';
    const relevance = isImportant ? 80 : 50;

    const record = new MemoryRecord(userId, category, termType, content, relevance);
    await memoryGateway.saveMemory(record);
    
    console.log(`[Memory Writer] Saved ${termType} memory for user ${userId} in category ${category}.`);
    return record.id;
}
