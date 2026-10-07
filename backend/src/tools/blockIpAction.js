export const BLOCKING_UNAVAILABLE_REASON = 'Blocking is not implemented: no firewall integration is connected, so nothing was blocked.';

/**
 * A state-changing action. requiresHumanApproval means:
 *   - the registry never offers it to the planner, and a model plan naming it is rejected;
 *   - the tool gateway refuses to run it unless the call carries an explicit human approval
 *     for exactly this tool and these parameters.
 * The planner can therefore never trigger it on its own judgement. And until a real firewall
 * integration exists, even an approved call blocks nothing and says so.
 */
export const blockIpActionTool = {
    name: 'blockIpAction',
    requiresHumanApproval: true,
    description: 'Blocks an IP address on the firewall. Requires explicit human approval; never available to the planner.',
    parameters: {
        type: 'object',
        properties: {
            ipAddress: { type: 'string', description: 'The exact IPv4 or IPv6 address to block.' },
            reason: { type: 'string', description: 'The justification for blocking this IP.' }
        },
        required: ['ipAddress', 'reason']
    },
    execute: async (params) => ({
        available: false,
        blocked: false,
        ipAddress: params?.ipAddress ?? null,
        reason: BLOCKING_UNAVAILABLE_REASON
    })
};
