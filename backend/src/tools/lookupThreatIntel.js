export const THREAT_INTEL_UNAVAILABLE_REASON = 'No threat intelligence source is configured.';

export const lookupThreatIntelTool = {
    name: 'lookupThreatIntel',
    description: 'Looks up indicators of compromise (IOCs) such as IPs or domains in threat intelligence databases. No threat intelligence source is configured yet, so this currently returns an explicit "unavailable" result with no verdict.',
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
        const { indicator, type } = params;
        // No provider is integrated. Report that explicitly rather than returning a verdict,
        // so the absence of a lookup can never be read as a clean (or dirty) result.
        // A real provider must return { available: true, source, ... } to count as evidence.
        return {
            available: false,
            indicator,
            type,
            reason: THREAT_INTEL_UNAVAILABLE_REASON
        };
    }
};
