import { randomUUID } from 'crypto';
import { runLog } from '../observability/runContext.js';

/**
 * Maintains the execution context during a single user request.
 * Request-scoped only. Persistent memory to be added in later phases.
 */
export class AgentContext {
    constructor(userRequest, conversationHistory = [], userId = 'default_user_1', requestId = randomUUID()) {
        this.requestId = requestId;
        this.userId = userId;
        this.userRequest = userRequest;
        this.conversationHistory = conversationHistory;
        this.executionStart = Date.now();
        this.toolResults = [];
        this.errors = [];

        runLog.info(`[Context Initialized] RequestID: ${this.requestId}`);
    }

    addToolResult(result) {
        this.toolResults.push(result);
        if (!result.success && result.error) {
            this.errors.push(result.error);
        }
    }

    getEvidence() {
        return this.toolResults;
    }

    getDuration() {
        return Date.now() - this.executionStart;
    }
}
