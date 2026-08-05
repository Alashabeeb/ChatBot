export const lookupThreatIntelTool = {
    name: 'lookupThreatIntel',
    description: 'Looks up indicators of compromise (IOCs) such as IPs or domains in threat intelligence databases.',
    parameters: {
        type: 'object',
        properties: {
            indicator: { 
                type: 'string', 
                description: 'The exact Indicator of Compromise (IOC) to look up. This must be a valid IP address, domain name, or file hash.'
            },
            type: { 
                type: 'string', 
                description: 'The type of indicator provided.',
                enum: ['ip', 'domain', 'hash']
            }
        },
        required: ['indicator', 'type']
    },
    execute: async (params) => {
        const { indicator } = params;
        // Mock response for Phase 2
        return {
            indicator,
            malicious: false,
            threatScore: 10,
            tags: ['scanner'],
            message: `Mock threat intelligence response for ${indicator}. Real integration pending.`
        };
    }
};
