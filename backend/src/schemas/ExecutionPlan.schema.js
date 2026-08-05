/**
 * The single contract for planner output in Phase 3.
 * The LLM MUST return a JSON object matching this schema.
 */
export const ExecutionPlanSchema = {
    type: "object",
    properties: {
        thought: {
            type: "string",
            description: "The LLM's reasoning for why these tools were chosen based on the user's request."
        },
        tools: {
            type: "array",
            description: "An ordered array of tools to execute. Can be empty if no tools are needed.",
            items: {
                type: "object",
                properties: {
                    tool: {
                        type: "string",
                        description: "The exact name of the tool to execute from the Tool Registry."
                    },
                    parameters: {
                        type: "object",
                        description: "The arguments to pass to the tool, matching the tool's parameter schema."
                    }
                },
                required: ["tool", "parameters"]
            }
        }
    },
    required: ["thought", "tools"]
};

/**
 * Validates a parsed JSON plan against the ExecutionPlan schema and registered tools.
 * Returns true if valid, throws an error if invalid.
 */
export function validateExecutionPlan(plan, registry) {
    if (!plan || typeof plan !== 'object') {
        throw new Error("Execution plan is not a valid JSON object.");
    }
    if (typeof plan.thought !== 'string') {
        throw new Error("Execution plan missing required string field 'thought'.");
    }
    if (!Array.isArray(plan.tools)) {
        throw new Error("Execution plan missing required array field 'tools'.");
    }
    
    for (const item of plan.tools) {
        if (typeof item.tool !== 'string') {
            throw new Error("Tool instruction missing required string field 'tool'.");
        }
        if (typeof item.parameters !== 'object') {
            throw new Error(`Tool instruction '${item.tool}' missing required object field 'parameters'.`);
        }
        if (!registry.hasTool(item.tool)) {
            throw new Error(`Planner attempted to use unregistered tool: '${item.tool}'.`);
        }
        // Detailed parameter schema validation could be added here later using Ajv or similar
    }

    return true;
}
