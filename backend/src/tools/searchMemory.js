import { memoryManager } from '../memory/manager.js';

export const searchMemoryTool = {
    name: 'searchMemory',
    description: 'Searches the user\'s personal memory store for past investigations, conversations, and preferences. Use this tool when the user refers to past context like "Have we investigated this IP before?" or "What did we find yesterday?".',
    parameters: {
        type: 'object',
        properties: {
            query: { 
                type: 'string', 
                description: 'The keyword or topic to search for in memory (e.g., an IP address, a threat actor, or a previous question).'
            }
        },
        required: ['query']
    },
    execute: async (params, context) => {
        // The userId must be extracted from the context object passed by the executor
        const userId = context?.userId;
        if (!userId) {
            throw new Error("searchMemory requires a userId in the execution context.");
        }

        const { query } = params;
        const results = await memoryManager.retrieve(userId, query);
        
        // Return only the top longTerm hits for the planner/reasoner
        return results.longTerm.slice(0, 3).map(mem => mem.content);
    }
};
