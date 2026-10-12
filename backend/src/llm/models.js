/**
 * Which model each role uses (Phase 6). Every role defaults to LLM_API_URL and the current model, so
 * with no new settings nothing changes. Any field can be overridden per role:
 *
 *   LLM_API_URL, LLM_MODEL, LLM_API_KEY                         default (memory, conversation, chat)
 *   PLANNER_LLM_API_URL, PLANNER_LLM_MODEL, PLANNER_LLM_API_KEY  the planner
 *   REPORT_LLM_API_URL, REPORT_LLM_MODEL, REPORT_LLM_API_KEY     the Search Wazuh report
 *
 * A key is only sent to the endpoint it belongs to: a role with its own URL uses its own key or none,
 * never the default endpoint's key. Read at call time, so a replay or comparison can switch models.
 */
export const DEFAULT_MODEL_NAME = 'foundation-sec-8b-instruct';
const PREFIX = { planner: 'PLANNER_', report: 'REPORT_' };
const value = name => (process.env[name] && process.env[name].trim()) || null;

export function modelFor(role = 'default') {
    const prefix = PREFIX[role];
    const ownUrl = prefix ? value(`${prefix}LLM_API_URL`) : null;
    return {
        role,
        url: ownUrl ?? value('LLM_API_URL'),
        model: (prefix && value(`${prefix}LLM_MODEL`)) ?? value('LLM_MODEL') ?? DEFAULT_MODEL_NAME,
        apiKey: ownUrl ? value(`${prefix}LLM_API_KEY`) : value('LLM_API_KEY')
    };
}

/** Every distinct model URL configured, e.g. to recognise model calls when recording fixtures. */
export const configuredModelUrls = () => [...new Set(['default', 'planner', 'report'].map(role => modelFor(role).url).filter(Boolean))];

export const authorizationHeaders = config => (config.apiKey ? { Authorization: `Bearer ${config.apiKey}` } : {});
