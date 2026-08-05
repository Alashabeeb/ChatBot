import { MapProvider } from './providers/MapProvider.js';

/**
 * Memory Gateway
 * Ensures all memory operations are routed securely to the active Memory Provider.
 * Enforces user isolation.
 */
class MemoryGateway {
    constructor() {
        // Hardcoded to MapProvider for Phase 4. Can be injected later.
        this.provider = new MapProvider();
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
