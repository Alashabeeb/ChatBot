import { executeTool } from '../tools/gateway.js';
import { runLog } from '../observability/runContext.js';

/**
 * Executes a plan (array of tool instructions).
 * Can run independent tools in parallel.
 */
export async function executePlan(plan, context) {
    runLog.info(`[Executor] Executing plan with ${plan.length} instructions...`);
    
    // For Phase 2, we execute all tools in parallel as they are independent.
    // In future phases, we might need a DAG scheduler for dependent tools.
    const executionPromises = plan.map(async (instruction, planIndex) => {
        const result = await executeTool(instruction.tool, instruction.parameters, context);
        // Results arrive in completion order; planIndex keeps the plan's order recoverable.
        result.planIndex = planIndex;
        context.addToolResult(result);
        return result;
    });

    await Promise.all(executionPromises);
    runLog.info(`[Executor] Plan execution complete.`);
}
