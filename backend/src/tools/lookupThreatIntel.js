export const lookupThreatIntelTool = {
    name: 'lookupThreatIntel',
    description: 'Looks up indicators of compromise (IOCs) such as IPs or domains in threat intelligence databases.',
    parameters: {
        type: 'object',
        properties: {
            indicator: { type: 'string', description: 'The IP address, domain, or hash to lookup' },
            type: { type: 'string', description: '"ip", "domain", or "hash"' }
        }
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
