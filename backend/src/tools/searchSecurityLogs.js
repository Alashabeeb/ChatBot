import { searchSecurityLogs as osSearchLogs } from '../integrations/opensearch.integration.js';

export const searchSecurityLogsTool = {
    name: 'searchSecurityLogs',
    description: 'Searches underlying data lakes or SIEM indexes for security logs matching specific criteria.',
    parameters: {
        type: 'object',
        properties: {
            timeRange: { 
                type: 'string', 
                description: 'The start time for the search. Must be an Elasticsearch Date Math string (e.g., "now-24h", "now-7d", "now-1h") or an ISO-8601 timestamp.',
                default: 'now-24h'
            },
            lteTime: { 
                type: 'string', 
                description: 'The end time for the search. Only provide if searching a strict historical window (e.g. an ISO-8601 string). Usually null.',
                nullable: true
            },
            minSeverity: { 
                type: 'number', 
                description: 'Minimum alert severity (e.g., 7 for High, 12 for Critical). Provide only if user specifically requested severe alerts.',
                nullable: true
            },
            extractedIPs: { 
                type: 'array', 
                items: { type: 'string' }, 
                description: 'Array of specific IP addresses to filter the logs by. Leave empty if no specific IP was requested.',
                default: []
            },
            intent: { 
                type: 'string', 
                description: 'Pre-categorized intent. Use "brute_force" for login failures, "vulnerabilities" for CVEs, or "alerts" as default.',
                enum: ['brute_force', 'vulnerabilities', 'alerts'],
                default: 'alerts'
            },
            cleanedSearchText: { 
                type: 'string', 
                description: 'A free-text keyword string to match against log descriptions. Remove stop-words and time references.',
                default: ''
            },
            sourceScope: {
                type: 'string',
                description: 'Internal source scope. Use "firewall" for Wazuh firewall signals, "non_firewall" for other Wazuh alerts, or "all" when no source split is required.',
                enum: ['all', 'firewall', 'non_firewall'],
                default: 'all'
            }
        },
        required: ['timeRange', 'intent']
    },
    execute: async (params) => {
        // Forward parameters to the capability provider (OpenSearch in this phase)
        return await osSearchLogs(params);
    }
};
