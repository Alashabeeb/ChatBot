import { getEndpointStatus as wazuhEndpointStatus, getManagerStatus as wazuhManagerStatus } from '../integrations/wazuh.integration.js';

export const getEndpointStatusTool = {
    name: 'getEndpointStatus',
    description: 'Retrieves inventory and status of endpoints/agents or the manager itself from the underlying security system.',
    parameters: {
        type: 'object',
        properties: {
            target: { type: 'string', description: '"manager" or "agents"' },
            status: { type: 'string', description: 'Filter by "active", "disconnected", etc. (optional)' }
        }
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
