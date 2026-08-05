export const MemorySchema = {
    type: "object",
    properties: {
        id: { type: "string" },
        userId: { type: "string", description: "Mandatory for isolation." },
        category: { 
            type: "string", 
            enum: ["conversation", "investigation", "case", "preference", "query"] 
        },
        termType: { 
            type: "string", 
            enum: ["short-term", "long-term"],
            description: "Short-term decays quickly or is summarized. Long-term persists indefinitely."
        },
        relevanceScore: { 
            type: "number", 
            description: "Base ranking score for retrieval sorting (0-100)." 
        },
        content: { type: "object", description: "The actual payload. Structure depends on category." },
        createdAt: { type: "string", format: "date-time" },
        updatedAt: { type: "string", format: "date-time" }
    },
    required: ["id", "userId", "category", "termType", "relevanceScore", "content", "createdAt"]
};
