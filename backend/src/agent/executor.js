import { executeTool } from '../tools/gateway.js';

/**
 * Executes a plan (array of tool instructions).
 * Can run independent tools in parallel.
 */
export async function executePlan(plan, context) {
    console.log(`[Executor] Executing plan with ${plan.length} instructions...`);
    
    // For Phase 2, we execute all tools in parallel as they are independent.
    // In future phases, we might need a DAG scheduler for dependent tools.
    const executionPromises = plan.map(async (instruction) => {
        const result = await executeTool(instruction.tool, instruction.parameters, context);
        context.addToolResult(result);
        return result;
    });

    await Promise.all(executionPromises);
    console.log(`[Executor] Plan execution complete.`);
}
