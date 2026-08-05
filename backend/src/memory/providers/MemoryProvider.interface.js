/**
 * MemoryProvider Interface
 * All storage implementations (PostgreSQL, Redis, VectorDB, Map) must implement these methods.
 */
export class MemoryProvider {
    /**
     * Initializes the provider (e.g., connecting to a DB).
     */
    async connect() {
        throw new Error("Method 'connect()' must be implemented.");
    }

    /**
     * @param {string} userId 
     * @param {Object} filters - e.g. { category, termType }
     * @returns {Promise<Array>}
     */
    async findMemories(userId, filters = {}) {
        throw new Error("Method 'findMemories()' must be implemented.");
    }

    /**
     * @param {Object} memoryRecord - Instance of MemoryRecord
     */
    async saveMemory(memoryRecord) {
        throw new Error("Method 'saveMemory()' must be implemented.");
    }

    /**
     * @param {string} memoryId 
     * @param {string} userId 
     */
    async deleteMemory(memoryId, userId) {
        throw new Error("Method 'deleteMemory()' must be implemented.");
    }
}
