export const ConversationSchema = {
    type: "object",
    properties: {
        summary: { type: "string" },
        keyEntities: { type: "array", items: { type: "string" } },
        resolved: { type: "boolean" },
        messages: { 
            type: "array", 
            items: { 
                type: "object",
                properties: {
                    role: { type: "string" },
                    content: { type: "string" }
                }
            } 
        }
    },
    required: ["summary", "keyEntities"]
};
