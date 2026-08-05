import { searchSecurityLogs as osSearchLogs } from '../integrations/opensearch.integration.js';

export const searchSecurityLogsTool = {
    name: 'searchSecurityLogs',
    description: 'Searches underlying data lakes or SIEM indexes for security logs matching specific criteria.',
    parameters: {
        type: 'object',
        properties: {
            timeRange: { type: 'string', description: 'Elasticsearch Date Math string (e.g. now-24h)' },
            lteTime: { type: 'string', description: 'End time (optional)' },
            minSeverity: { type: 'number', description: 'Minimum severity level (optional)' },
            extractedIPs: { type: 'array', items: { type: 'string' }, description: 'Array of IP addresses to filter on' },
            intent: { type: 'string', description: 'Pre-parsed intent if applicable' },
            cleanedSearchText: { type: 'string', description: 'Free-text search string' }
        }
    },
    execute: async (params) => {
        // Forward parameters to the capability provider (OpenSearch in this phase)
        return await osSearchLogs(params);
    }
};
