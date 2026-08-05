import { randomUUID } from 'crypto';

export class MemoryRecord {
    constructor(userId, category, termType, content, relevanceScore = 50) {
        this.id = randomUUID();
        this.userId = userId;
        this.category = category; // "conversation", "investigation", "case", "preference", "query"
        this.termType = termType; // "short-term", "long-term"
        this.content = content;
        this.relevanceScore = relevanceScore;
        this.createdAt = new Date().toISOString();
        this.updatedAt = this.createdAt;
    }
}
