import registry from '../llm/registry.js';
import { runLog, recordRunError } from '../observability/runContext.js';
import { canonicalJson } from '../recording/common.js';

/**
 * An approval-gated tool runs only when the call carries context.approval for exactly this tool and
 * these parameters, with who approved it. Nothing in the planner/runtime path ever sets it.
 */
function hasMatchingApproval(toolName, parameters, context) {
    const approval = context?.approval;
    return Boolean(approval)
        && approval.tool === toolName
        && typeof approval.approvedBy === 'string' && approval.approvedBy.length > 0
        && canonicalJson(approval.parameters ?? null) === canonicalJson(parameters ?? null);
}

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

    if (tool.requiresHumanApproval && !hasMatchingApproval(toolName, parameters, context)) {
        standardResponse.error = `Tool '${toolName}' requires human approval for these exact parameters; refused.`;
        standardResponse.executionTime = Date.now() - startTime;
        runLog.error(`[Gateway Refused] ${standardResponse.error}`);
        recordRunError('tool', standardResponse.error, { tool: toolName });
        return standardResponse;
    }

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
