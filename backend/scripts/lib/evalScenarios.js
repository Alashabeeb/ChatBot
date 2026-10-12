import { isAggregationRequest, fakeAggregationResponse } from './fakeAggregations.js';
/**
 * Invented scenarios for evals: the telemetry behind the SYNTHETIC cases (makeSyntheticEvalCases.js)
 * and the grounded-pipeline evaluation (evalSyntheticPipeline.js). Nothing here is real data.
 */
export const FIXED_TIME = '2026-10-12T09:00:00.000Z';
const hit = (ruleId, description, level, mitre, agent, extra = {}) => ({
    '@timestamp': '2026-10-12T08:30:00.000Z',
    rule: { id: ruleId, level, description, ...(mitre ? { mitre: { id: mitre } } : {}) },
    agent: { name: agent.name, id: agent.id },
    ...extra
});
const times = (n, make) => Array.from({ length: n }, make);

const AG = {
    dc01: { id: '003', name: 'DC01' },
    web01: { id: '001', name: 'web-01' },
    web02: { id: '002', name: 'web-02' },
    fw01: { id: '004', name: 'fw-01' },
    adfs01: { id: '005', name: 'ADFS01' }
};

export const SCENARIOS = {
    'top-alerts-week': {
        question: 'what are the top alerts this week',
        plan: [
            { tool: 'searchSecurityLogs', parameters: { timeRange: 'now-7d', intent: 'alerts', extractedIPs: [], minSeverity: null, cleanedSearchText: '' } },
            { tool: 'getEndpointStatus', parameters: { target: 'agents', status: 'any' } }
        ],
        logs: [
            ...times(6, () => hit('60122', 'Windows logon failure', 5, ['T1110'], AG.dc01, { data: { win: { eventdata: { ipAddress: '185.220.101.7', targetUserName: 'jdoe' } } } })),
            ...times(3, () => hit('5710', 'sshd: attempt to login using a non-existent user', 5, ['T1110.001'], AG.web01, { data: { srcip: '45.155.205.233', srcuser: 'admin' } })),
            ...times(2, () => hit('550', 'Integrity checksum changed', 7, ['T1565.001'], AG.web01, { syscheck: { path: '/etc/passwd' } })),
            hit('31151', 'Multiple web server 400 error codes from same source ip', 10, null, AG.web02, { data: { srcip: '203.0.113.50' } })
        ],
        firewallLogs: [hit('4101', 'Firewall drop event', 5, null, AG.fw01, { data: { srcip: '198.51.100.23' } })],
        agents: [
            { id: '001', name: 'web-01', status: 'active', ip: '10.20.0.11' },
            { id: '002', name: 'web-02', status: 'disconnected', ip: '10.20.0.12' },
            { id: '003', name: 'DC01', status: 'active', ip: '10.20.0.5' },
            { id: '004', name: 'fw-01', status: 'active', ip: '10.20.0.1' }
        ]
    },
    'failed-logons-today-empty': {
        question: 'show me failed logons today',
        plan: [{ tool: 'searchSecurityLogs', parameters: { timeRange: 'now-24h', intent: 'brute_force', extractedIPs: [], minSeverity: null, cleanedSearchText: '' } }],
        logs: [],
        firewallLogs: [],
        agents: []
    },
    'ad-servers-firewall-down': {
        question: 'anything unusual on the AD servers',
        plan: [
            { tool: 'searchSecurityLogs', parameters: { timeRange: 'now-24h', intent: 'alerts', extractedIPs: [], minSeverity: null, cleanedSearchText: 'ad servers' } },
            { tool: 'getEndpointStatus', parameters: { target: 'agents', status: 'any' } }
        ],
        logs: [
            ...times(4, () => hit('60122', 'Windows logon failure', 5, ['T1110'], AG.dc01, { data: { win: { eventdata: { ipAddress: '10.20.0.77', targetUserName: 'svc_backup' } } } })),
            hit('60204', 'Multiple Windows logon failures', 10, ['T1110'], AG.dc01, { data: { win: { eventdata: { ipAddress: '10.20.0.77', targetUserName: 'svc_backup' } } } })
        ],
        firewallError: true,
        agents: [
            { id: '003', name: 'DC01', status: 'active', ip: '10.20.0.5' },
            { id: '005', name: 'ADFS01', status: 'active', ip: '10.20.0.6' }
        ]
    },
    'right-now-sampled': {
        question: 'what is going on right now',
        plan: [{ tool: 'searchSecurityLogs', parameters: { timeRange: 'now-1h', intent: 'alerts', extractedIPs: [], minSeverity: 7, cleanedSearchText: '' } }],
        // A full page: the search returns its 200 most recent records out of 1,500 matches.
        logs: [
            ...times(160, () => hit('5710', 'sshd: attempt to login using a non-existent user', 8, ['T1110.001'], AG.web01, { data: { srcip: '45.155.205.233' } })),
            ...times(40, () => hit('550', 'Integrity checksum changed', 7, ['T1565.001'], AG.web01))
        ],
        logsTotal: 1500,
        // What the aggregation request sees: every one of the 1,500 matches.
        aggLogs: [
            ...times(1200, () => hit('5710', 'sshd: attempt to login using a non-existent user', 8, ['T1110.001'], AG.web01, { data: { srcip: '45.155.205.233' } })),
            ...times(300, () => hit('550', 'Integrity checksum changed', 7, ['T1565.001'], AG.web01))
        ],
        previousLogs: times(40, () => hit('5710', 'sshd: attempt to login using a non-existent user', 8, ['T1110.001'], AG.web01, { data: { srcip: '45.155.205.233' } })),
        firewallLogs: [],
        agents: []
    }
};
// The same scenario as captured before Phase 5: no aggregation requests, so counts are only bounded.
SCENARIOS['right-now-sampled-pre-phase5'] = { ...SCENARIOS['right-now-sampled'], preAggregation: true };
// Last week, rule 60122 barely fired: this week's 6 is a measurable change.
SCENARIOS['top-alerts-week'].previousLogs = [hit('60122', 'Windows logon failure', 5, ['T1110'], AG.dc01, { data: { win: { eventdata: { ipAddress: '185.220.101.7', targetUserName: 'jdoe' } } } })];

export function stubHttp(axios, scenario, { report }) {
    const isFirewall = body => JSON.stringify(body?.query?.bool?.must ?? []).includes('"iptables"');
    const reply = content => ({ status: 200, data: { choices: [{ message: { content } }] } });
    axios.get = async () => ({ status: 200, data: { data: { affected_items: scenario.agents, total_affected_items: scenario.agents.length } } });
    axios.post = async (url, body) => {
        if (String(url).includes('/security/user/authenticate')) return { status: 200, data: 'synthetic-token' };
        if (body?.messages) {
            const system = body.messages[0].content;
            if (system.includes('Planning Engine')) return reply(JSON.stringify({ thought: 'synthetic plan', tools: scenario.plan }));
            if (system.includes('Memory Engine')) return reply('{"summary":"synthetic","keyEntities":[]}');
            return reply(typeof report === 'function' ? report(body) : report);
        }
        if (isAggregationRequest(body)) {
            // Before Phase 5 there was no aggregation request; in the pipeline that is the same as it failing.
            if (scenario.preAggregation) throw new Error('synthetic: no aggregation recorded (pre-Phase 5)');
            const current = isFirewall(body) ? scenario.firewallLogs : (scenario.aggLogs ?? scenario.logs);
            return fakeAggregationResponse(body, { current: current ?? [], previous: isFirewall(body) ? [] : (scenario.previousLogs ?? []) });
        }
        if (isFirewall(body) && scenario.firewallError) {
            const error = new Error('Request failed with status code 503');
            error.response = { status: 503, data: { error: 'synthetic: firewall index unavailable' } };
            throw error;
        }
        const hits = isFirewall(body) ? scenario.firewallLogs : scenario.logs;
        const total = isFirewall(body) ? hits.length : (scenario.logsTotal ?? hits.length);
        return { status: 200, data: { hits: { total: { value: total }, hits: hits.map(h => ({ _source: h })) } } };
    };
}

/** Removes the aggregation requests from a capture, to reproduce a fixture recorded before Phase 5. */
export function withoutAggregations(fixture) {
    fixture.calls = fixture.calls.filter(c => !(c.kind === 'opensearch' && isAggregationRequest(c.request)));
    return fixture;
}

export function normalize(fixture) {
    fixture.capturedAt = FIXED_TIME;
    fixture.requestId = 'synthetic';
    fixture.capture = { ...fixture.capture, durationMs: 0, nodeVersion: 'synthetic', platform: 'synthetic' };
    for (const call of fixture.calls) {
        call.startedAt = FIXED_TIME;
        call.durationMs = 0;
    }
    fixture.result.timings = null;
    for (const error of fixture.result.errors || []) if (error.at) error.at = FIXED_TIME;
    for (const tool of fixture.result.tools || []) tool.executionTimeMs = 0;
    return fixture;
}

