import registry from '../llm/registry.js';
import { runLog, recordRunError } from '../observability/runContext.js';

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
        parameters,
        executionTime: 0,
        data: {},
        error: null
    };

    if (!registry.hasTool(toolName)) {
        standardResponse.error = `Tool '${toolName}' not found in registry.`;
        standardResponse.executionTime = Date.now() - startTime;
        runLog.error(`[Gateway Error] ${standardResponse.error}`);
        recordRunError('tool', standardResponse.error, { tool: toolName });
        return standardResponse;
    }

    const tool = registry.getTool(toolName);

    try {
        runLog.info(`[Gateway Executing] Tool: ${toolName} | Params:`, JSON.stringify(parameters));
        
        // Execute the capability
        const result = await tool.execute(parameters, context);
        
        standardResponse.success = true;
        standardResponse.data = result;
        
        runLog.info(`[Gateway Success] Tool: ${toolName} completed in ${Date.now() - startTime}ms.`);
    } catch (error) {
        standardResponse.error = error.message;
        runLog.error(`[Gateway Failure] Tool: ${toolName} failed in ${Date.now() - startTime}ms. Error: ${error.message}`);
        recordRunError('tool', error.message, { tool: toolName });
    }

    standardResponse.executionTime = Date.now() - startTime;
    return standardResponse;
}
