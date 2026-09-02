import { SqliteMemoryProvider } from './providers/SqliteMemoryProvider.js';

/**
 * Memory Gateway
 * Ensures all memory operations are routed securely to the active Memory Provider.
 * Enforces user isolation.
 */
class MemoryGateway {
    constructor() {
        this.provider = new SqliteMemoryProvider();
        this.provider.connect();
    }

    async getMemories(userId, filters = {}) {
        if (!userId) throw new Error("MemoryGateway: userId is required.");
        return await this.provider.findMemories(userId, filters);
    }

    async saveMemory(memoryRecord) {
        if (!memoryRecord.userId) throw new Error("MemoryGateway: userId is required to save memory.");
        return await this.provider.saveMemory(memoryRecord);
    }
}

// Singleton Gateway
export const memoryGateway = new MemoryGateway();
