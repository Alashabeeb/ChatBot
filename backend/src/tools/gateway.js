import registry from '../llm/registry.js';

/**
 * Tool Gateway
 * The only point of entry for executing capability tools.
 * It enforces standardized responses, handles execution time tracking, and catches all errors.
 * No business logic lives here.
 */
export async function executeTool(toolName, parameters, context = null) {
    const startTime = Date.now();

    const standardResponse = {
        success: false,
        tool: toolName,
        executionTime: 0,
        data: {},
        error: null
    };

    if (!registry.hasTool(toolName)) {
        standardResponse.error = `Tool '${toolName}' not found in registry.`;
        standardResponse.executionTime = Date.now() - startTime;
        console.error(`[Gateway Error] ${standardResponse.error}`);
        return standardResponse;
    }

    const tool = registry.getTool(toolName);

    try {
        console.log(`[Gateway Executing] Tool: ${toolName} | Params:`, JSON.stringify(parameters));
        
        // Execute the capability
        const result = await tool.execute(parameters, context);
        
        standardResponse.success = true;
        standardResponse.data = result;
        
        console.log(`[Gateway Success] Tool: ${toolName} completed in ${Date.now() - startTime}ms.`);
    } catch (error) {
        standardResponse.error = error.message;
        console.error(`[Gateway Failure] Tool: ${toolName} failed in ${Date.now() - startTime}ms. Error: ${error.message}`);
    }

    standardResponse.executionTime = Date.now() - startTime;
    return standardResponse;
}
