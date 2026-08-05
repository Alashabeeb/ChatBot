import { memoryGateway } from './gateway.js';

/**
 * Retrieves and ranks memory for the LLM context.
 */
export async function retrieveRelevantMemories(userId, currentQuery) {
    // 1. Fetch short-term memory (recent conversations)
    const shortTerm = await memoryGateway.getMemories(userId, { termType: 'short-term' });
    
    // 2. Fetch long-term memory (preferences and past investigations)
    const longTerm = await memoryGateway.getMemories(userId, { termType: 'long-term' });

    // 3. Ranking Algorithm (Simplified for Phase 4)
    // - Sort by relevanceScore
    // - Prioritize recent short-term memories
    // - Filter long-term by keyword matching against currentQuery
    
    const queryLower = currentQuery.toLowerCase();
    
    const rankedLongTerm = longTerm.filter(mem => {
        // Simple keyword heuristic for mock Phase 4 ranking
        const contentStr = JSON.stringify(mem.content).toLowerCase();
        // Return if it matches any word in the query (naive search)
        const queryWords = queryLower.split(' ').filter(w => w.length > 4);
        return queryWords.some(w => contentStr.includes(w)) || mem.category === 'preference';
    }).sort((a, b) => b.relevanceScore - a.relevanceScore);

    // Combine
    return {
        shortTerm: shortTerm.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt)),
        longTerm: rankedLongTerm
    };
}
