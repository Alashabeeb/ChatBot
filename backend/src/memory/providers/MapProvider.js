import { MemoryProvider } from './MemoryProvider.interface.js';

/**
 * Local in-memory Map implementation for development phase.
 */
export class MapProvider extends MemoryProvider {
    constructor() {
        super();
        this.store = new Map(); // Key: userId, Value: Array of MemoryRecords
    }

    async connect() {
        console.log("[MapProvider] Connected to local in-memory storage.");
    }

    async findMemories(userId, filters = {}) {
        const userMemories = this.store.get(userId) || [];
        
        return userMemories.filter(mem => {
            let match = true;
            if (filters.category && mem.category !== filters.category) match = false;
            if (filters.termType && mem.termType !== filters.termType) match = false;
            return match;
        });
    }

    async saveMemory(memoryRecord) {
        const userId = memoryRecord.userId;
        if (!this.store.has(userId)) {
            this.store.set(userId, []);
        }
        this.store.get(userId).push(memoryRecord);
        return memoryRecord.id;
    }

    async deleteMemory(memoryId, userId) {
        if (!this.store.has(userId)) return false;
        
        const memories = this.store.get(userId);
        const initialLength = memories.length;
        this.store.set(userId, memories.filter(m => m.id !== memoryId));
        
        return this.store.get(userId).length < initialLength;
    }
}
