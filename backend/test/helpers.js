import axios from 'axios';

export const USER_ID = 'user_admin_root';

/** Call before dynamically importing app modules: config/env.js and config/db.js read these at import time. */
export function setTestEnv() {
    process.env.SOC_DB_PATH = ':memory:';
    process.env.JWT_SECRET = 'test-jwt-secret';
    process.env.LLM_API_URL = 'http://llm.test/v1/chat/completions';
    process.env.OPENSEARCH_URL = 'http://opensearch.test';
    process.env.WAZUH_SERVER_API_URL = 'http://wazuh.test';
    process.env.WAZUH_USER = 'test';
    process.env.WAZUH_PASSWORD = 'test';
}

export function llmReply(content) {
    return { data: { choices: [{ message: { content } }] } };
}

/**
 * askFoundation sends [system(systemInstruction), ...conversationHistory, user(prompt)],
 * so its exact arguments can be recovered from each outgoing request.
 */
export function askFoundationArgs(messages) {
    return {
        systemInstruction: messages[0],
        conversationHistory: messages.slice(1, -1),
        prompt: messages.at(-1)
    };
}

/**
 * Stubs the LLM and OpenSearch HTTP calls.
 * - llm: 'down' makes every model call fail; 'hang' makes every model call wait forever (a server that
 *   accepts the connection but never answers); otherwise { plan, report } replies
 *   (plan: object sent as JSON, or null for an unparseable reply; report: text, default echoes the prompt).
 * - logs: OpenSearch hits, or a function (url, body) => hits to vary them per query.
 * - firewallLogs: hits for the firewall half of each search (default none). Every planned search
 *   runs twice (firewall / non_firewall scope); the two queries are mutually exclusive, so the
 *   stub never returns the same records to both.
 * - agents: Wazuh GET /agents affected_items.
 * Returns { llmCalls, searchCalls, wazuhCalls }: messages arrays sent to the model, { url, body } sent to
 * OpenSearch, and { url, params } sent to the Wazuh API.
 */
export const isFirewallScopeQuery = body => JSON.stringify(body?.query?.bool?.must ?? []).includes('"iptables"');

export function stubBackends(t, { llm = {}, logs = [], firewallLogs = [], agents = [] } = {}) {
    const llmCalls = [];
    const searchCalls = [];
    const wazuhCalls = [];
    t.mock.method(axios, 'get', async (url, config = {}) => {
        wazuhCalls.push({ url, params: structuredClone(config.params) });
        return { status: 200, data: { data: { affected_items: agents, total_affected_items: agents.length } } };
    });
    t.mock.method(axios, 'post', async (url, body) => {
        if (String(url).includes('/security/user/authenticate')) {
            return { status: 200, data: 'stub-wazuh-token' };
        }
        if (body?.messages) {
            llmCalls.push(body.messages);
            if (llm === 'down') {
                throw new Error('connect ECONNREFUSED llm.test');
            }
            if (llm === 'hang') {
                return new Promise(() => {});
            }
            const system = body.messages[0].content;
            if (system.includes('Planning Engine')) {
                return llmReply(llm.plan ? JSON.stringify(llm.plan) : 'not a plan');
            }
            if (system.includes('Memory Engine')) {
                return llmReply('{"summary":"test investigation","keyEntities":[]}');
            }
            return llmReply(llm.report ?? `Echoed prompt:\n${body.messages.at(-1).content}`);
        }
        // Deep copy: the recorded body must be what was sent, not an object mutated later.
        searchCalls.push({ url, body: structuredClone(body) });
        const scoped = isFirewallScopeQuery(body) ? firewallLogs : logs;
        const hits = typeof scoped === 'function' ? scoped(url, body) : scoped;
        return { status: 200, data: { hits: { total: { value: hits.length }, hits: hits.map(l => ({ _source: l })) } } };
    });
    return { llmCalls, searchCalls, wazuhCalls };
}

export const SAMPLE_LOG = {
    '@timestamp': '2026-09-16T08:00:00Z',
    rule: { level: 5, description: 'sshd: authentication failed' },
    data: { srcip: '10.0.0.5', srcuser: 'root' },
    agent: { name: 'web-01' }
};

export const SEARCH_PLAN = {
    thought: 'Search authentication failures.',
    tools: [{ tool: 'searchSecurityLogs', parameters: { timeRange: 'now-24h', intent: 'brute_force', extractedIPs: [], minSeverity: null, cleanedSearchText: '' } }]
};

// The runtime writes memory in the background after returning; let it finish while stubs are active.
export const flushBackgroundWork = () => new Promise(resolve => setTimeout(resolve, 50));
