export const PROCESS_DATA_UNAVAILABLE_REASON = 'Process inspection is not implemented: no endpoint process data source is connected.';

/**
 * Read-only. Until a real process data source (for example Wazuh syscollector) is wired in, this
 * reports that explicitly instead of returning a process list. The runtime treats it as an
 * unavailable source: never evidence, and noted in the report.
 */
export const checkProcessListTool = {
    name: 'checkProcessList',
    description: 'Checks the running processes on a specific endpoint. Not connected to a process data source yet: currently returns an explicit "unavailable" result with no process list.',
    parameters: {
        type: 'object',
        properties: {
            endpointId: { type: 'string', description: 'The Agent ID or Hostname to query.' }
        },
        required: ['endpointId']
    },
    execute: async (params) => ({
        available: false,
        endpointId: params?.endpointId ?? null,
        reason: PROCESS_DATA_UNAVAILABLE_REASON
    })
};
