/**
 * Core Registry for the AI SOC Copilot Platform.
 * Manages tools, models, prompts, and plugins.
 * The registry stores only metadata and references, knowing nothing about internal tool business logic.
 */
class Registry {
    constructor() {
        this.tools = new Map();
    }

    /**
     * Registers a tool.
     * @param {Object} tool - The tool object. Must conform to the standard interface: { name, description, parameters, execute }
     */
    registerTool(tool) {
        if (!tool.name || typeof tool.name !== 'string') {
            throw new Error("Tool registration failed: 'name' must be a valid string.");
        }
        if (typeof tool.execute !== 'function') {
            throw new Error(`Tool registration failed: Tool '${tool.name}' must have an 'execute' function.`);
        }
        this.tools.set(tool.name, tool);
    }

    /**
     * Retrieves a tool by name.
     */
    getTool(name) {
        return this.tools.get(name);
    }

    /**
     * Lists all registered tools (useful for LLM prompting).
     */
    listTools() {
        return Array.from(this.tools.values()).map(tool => ({
            name: tool.name,
            description: tool.description,
            parameters: tool.parameters
        }));
    }

    /**
     * Validates if a tool exists.
     */
    hasTool(name) {
        return this.tools.has(name);
    }
}

// Export a singleton instance of the registry
const registry = new Registry();
export default registry;
