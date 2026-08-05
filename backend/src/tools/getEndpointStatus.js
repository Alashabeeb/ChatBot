import { getEndpointStatus as wazuhEndpointStatus, getManagerStatus as wazuhManagerStatus } from '../integrations/wazuh.integration.js';

export const getEndpointStatusTool = {
    name: 'getEndpointStatus',
    description: 'Retrieves inventory and status of endpoints/agents or the manager itself from the underlying security system.',
    parameters: {
        type: 'object',
        properties: {
            target: { 
                type: 'string', 
                description: 'The target infrastructure to check. Use "manager" for the central SIEM server status, or "agents" for endpoints.',
                enum: ['manager', 'agents'],
                default: 'agents'
            },
            status: { 
                type: 'string', 
                description: 'Filter agents by connection status. "active" for connected, "disconnected" for offline.',
                enum: ['active', 'disconnected', 'any'],
                default: 'any'
            }
        },
        required: ['target']
    },
    execute: async (params) => {
        const { target, status } = params;
        
        if (target === 'manager') {
            return await wazuhManagerStatus();
        } else {
            let wqlStatus = '';
            if (status === 'disconnected') wqlStatus = 'status=disconnected';
            else if (status === 'active') wqlStatus = 'status=active';
            
            return await wazuhEndpointStatus(wqlStatus);
        }
    }
};
