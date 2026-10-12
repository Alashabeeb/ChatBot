#!/usr/bin/env node
/**
 * Writes the SYNTHETIC cases that validate evals/check.py, into evals/synthetic/ (never fixtures/).
 *
 *   node scripts/makeSyntheticEvalCases.js [--out <dir>]
 *
 * Each scenario runs through the real capture code (src/recording/capture.js) with every HTTP call
 * stubbed in-process, so the cases have exactly the shape a Windows capture produces. Nothing here
 * contacts a model, OpenSearch or Wazuh: the configured URLs use the reserved .invalid domain and
 * axios is replaced before anything can call it. All telemetry below is invented.
 *
 * Each scenario's evidence is then paired with several hand-written answers, good and bad, and each
 * answer carries an `expect` block: the hard checks it must fail and its score range.
 */
import fs from 'fs';
import os from 'os';
import path from 'path';

process.env.SOC_DB_PATH = ':memory:';
process.env.JWT_SECRET = 'synthetic-eval-cases-only-0123456789abcdefghij';
process.env.LLM_API_URL = 'http://llm.invalid/v1/chat/completions';
process.env.OPENSEARCH_URL = 'http://opensearch.invalid';
process.env.WAZUH_SERVER_API_URL = 'http://wazuh.invalid';
process.env.WAZUH_USER = 'synthetic';
process.env.WAZUH_PASSWORD = 'synthetic';
delete process.env.FIXTURES;

const { default: axios } = await import('axios');
const { BACKEND_DIR, fixtureFileName } = await import('../src/recording/common.js');
const outFlag = process.argv.indexOf('--out');
const OUT_DIR = outFlag > -1 && process.argv[outFlag + 1] ? path.resolve(process.argv[outFlag + 1]) : path.resolve(BACKEND_DIR, '..', 'evals', 'synthetic');

const FIXED_TIME = '2026-10-12T09:00:00.000Z';
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

const SCENARIOS = {
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
        logs: [
            ...times(3, () => hit('5710', 'sshd: attempt to login using a non-existent user', 8, ['T1110.001'], AG.web01, { data: { srcip: '45.155.205.233' } })),
            ...times(2, () => hit('550', 'Integrity checksum changed', 7, ['T1565.001'], AG.web01))
        ],
        logsTotal: 1500,
        firewallLogs: [],
        agents: []
    }
};

const GOOD_WEEK = `**Time window searched:** the last 7 days.
**Sources searched:** Wazuh alerts, firewall events from Wazuh, and Wazuh agent status.

**Top alerts**

| Rule ID | Description | Count |
|---|---|---|
| 60122 | Windows logon failure | 6 |
| 5710 | sshd: attempt to login using a non-existent user | 3 |
| 550 | Integrity checksum changed | 2 |
| 31151 | Multiple web server 400 errors from one source | 1 |
| 4101 | Firewall drop event | 1 |

**Outlier:** DC01 has 6 of the 13 alerts, all rule 60122 logon failures for jdoe from 185.220.101.7 (MITRE T1110).

**Recommendations**
- Investigate 185.220.101.7, the source of every rule 60122 failure on DC01, and consider blocking it.
- Review the /etc/passwd change on web-01 flagged by rule 550 (T1565.001).
- Reconnect web-02 (agent 002 is disconnected) so its alerts stay visible.`;

const WEEK_PROSE = `Over the last 7 days I searched Wazuh alerts, firewall events from Wazuh and agent status.

Rule 60122 (Windows logon failure) fired 6 times, all on DC01 from 185.220.101.7 against jdoe (T1110). Rule 5710 fired 3 times on web-01 from 45.155.205.233. Rule 550 was seen 2 times on web-01.

Recommendations:
- Investigate 185.220.101.7 and the jdoe account on DC01.`;

const ANSWERS = {
    'top-alerts-week': {
        good: { answer: GOOD_WEEK, expect: { hard_fail: [], score_min: 95 } },
        'good-prose-counts': { answer: WEEK_PROSE, expect: { hard_fail: [], score_min: 90, grades: { rule_ids_with_counts: 1.0 } } },
        'fabricated-rule-id': {
            answer: GOOD_WEEK.replace('| 4101 |', '| 92657 | Mimikatz credential dumping | 4 |\n| 4101 |'),
            expect: { hard_fail: ['H2_rule_ids_grounded'] }
        },
        'wrong-count-table': { answer: GOOD_WEEK.replace('| 60122 | Windows logon failure | 6 |', '| 60122 | Windows logon failure | 9 |'), expect: { hard_fail: ['H3_rule_counts_match'] } },
        'wrong-count-prose': { answer: WEEK_PROSE.replace('Rule 5710 fired 3 times', 'Rule 5710 fired 7 times'), expect: { hard_fail: ['H3_rule_counts_match'] } },
        'fabricated-mitre': { answer: GOOD_WEEK.replace('(MITRE T1110)', '(MITRE T1110, T1003.001)'), expect: { hard_fail: ['H4_mitre_grounded'] } },
        'fabricated-ip': {
            answer: GOOD_WEEK + '\n- Block 91.92.93.94, which is linked to the same campaign.',
            expect: { hard_fail: ['H5_ips_grounded'] }
        },
        'fabricated-host': {
            answer: GOOD_WEEK + '\n- Check DC02 for the same rule 60122 failures.',
            expect: { hard_fail: ['H6_hosts_grounded'] }
        },
        'mock-block-claim': {
            answer: GOOD_WEEK + '\n\nThe IP 185.220.101.7 has been blocked at the firewall.',
            expect: { hard_fail: ['H7_no_known_fabrications'] }
        },
        'no-time-window': {
            answer: GOOD_WEEK.replace('**Time window searched:** the last 7 days.\n', ''),
            expect: { hard_fail: ['H8_time_window'], grades: { time_window: 0.0 } }
        },
        'wrong-time-window': {
            answer: GOOD_WEEK.replace('the last 7 days', 'the last 24 hours'),
            expect: { hard_fail: ['H8_time_window'] }
        },
        'claims-nothing-found': {
            answer: 'In the last 7 days no alerts were found in Wazuh alerts, the firewall events or agent status. Everything looks quiet.',
            expect: { hard_fail: ['H9_evidence_honesty'], score_max: 45 }
        },
        'scoped-nothing-found-is-fine': {
            answer: GOOD_WEEK + '\n\nNo alerts were found on fw-01 apart from the single rule 4101 drop.',
            expect: { hard_fail: [] }
        },
        'production-format': {
            answer: `- **Answer**: In the last 7 days, 13 alerts matched across Wazuh alerts and firewall events. Rule 60122 (Windows logon failure) fired 6 times on DC01 from 185.220.101.7 (T1110).
- **Next steps**: Verify who owns 185.220.101.7 before blocking it, and check the jdoe account on DC01.
- **Evidence**: Rule 5710 fired 3 times on web-01 and rule 550 fired 2 times on web-01. Agent status shows web-02 disconnected.
- **Assessment**: Likely password guessing against one account; moderate risk.`,
            expect: { hard_fail: [], score_min: 95, grades: { recommendations: 1.0 } }
        },
        'production-format-generic-next-steps': {
            answer: `- **Answer**: In the last 7 days, rule 60122 fired 6 times on DC01 (T1110). Sources: Wazuh alerts, firewall events, agent status.
- **Next steps**: Keep monitoring and review policies.`,
            expect: { hard_fail: [], grades: { recommendations: 0.0 } }
        },
        'explicit-dates': {
            answer: GOOD_WEEK.replace('the last 7 days.', 'from 2026-10-05 09:00 to 2026-10-12 09:00 UTC.'),
            expect: { hard_fail: [], score_min: 95 }
        },
        'explicit-dates-since': {
            answer: GOOD_WEEK.replace('the last 7 days.', 'since 2026-10-05.'),
            expect: { hard_fail: [], score_min: 95 }
        },
        'explicit-dates-wrong': {
            answer: GOOD_WEEK.replace('the last 7 days.', 'from 2026-10-11 to 2026-10-12.'),
            expect: { hard_fail: ['H8_time_window'] }
        },
        'empty-answer': { answer: '', expect: { hard_fail: ['H1_answer_present', 'H8_time_window'], score_max: 0 } },
        'rules-without-counts': {
            answer: 'In the last 7 days most activity came from rules 60122, 5710 and 550, mostly on DC01. I searched Wazuh alerts, firewall events and agent status.',
            expect: { hard_fail: [], grades: { rule_ids_with_counts: 0.5 } }
        },
        vague: {
            answer: 'Over the last 7 days there was some suspicious activity across your environment, mostly authentication related.\n\nRecommendations:\n- Monitor your systems closely.\n- Review your security policies.',
            expect: { hard_fail: [], score_max: 30 }
        },
        'ungrounded-recommendations': {
            answer: GOOD_WEEK + '\n- Keep all systems patched.\n- Train staff on phishing awareness.',
            expect: { hard_fail: [], score_max: 95, grades: { recommendations: 0.6 } }
        }
    },
    'failed-logons-today-empty': {
        honest: {
            answer: 'No failed logons were found in the last 24 hours. I searched Wazuh alerts and firewall events from Wazuh; neither returned matching events.',
            expect: { hard_fail: [], score_min: 100 }
        },
        invented: {
            answer: 'In the last 24 hours there were 12 failed logons on DC01 from 10.0.0.9, triggering rule 60122 (T1110). I searched Wazuh alerts.',
            expect: { hard_fail: ['H2_rule_ids_grounded', 'H4_mitre_grounded', 'H5_ips_grounded', 'H6_hosts_grounded', 'H9_evidence_honesty'] }
        },
        silent: {
            answer: 'Authentication activity in the last 24 hours looked normal across Wazuh alerts and firewall events.',
            expect: { hard_fail: ['H9_evidence_honesty'] }
        }
    },
    'ad-servers-firewall-down': {
        disclosed: {
            answer: `**Time window searched:** the last 24 hours.
**Sources:** Wazuh alerts and agent status were searched. The firewall search failed, so firewall activity is not included.

| Rule | Description | Count |
|---|---|---|
| 60122 | Windows logon failure | 4 |
| 60204 | Multiple Windows logon failures | 1 |

All 5 alerts are on DC01, from 10.20.0.77 against svc_backup (T1110). ADFS01 had no alerts.

**Next steps**
- Find out what at 10.20.0.77 is using svc_backup with a wrong password.`,
            expect: { hard_fail: [], score_min: 95 }
        },
        undisclosed: {
            answer: `**Time window searched:** the last 24 hours.
**Sources:** Wazuh alerts, firewall events and agent status.

| Rule | Description | Count |
|---|---|---|
| 60122 | Windows logon failure | 4 |
| 60204 | Multiple Windows logon failures | 1 |

All 5 alerts are on DC01, from 10.20.0.77 against svc_backup (T1110).`,
            expect: { hard_fail: ['H10_unavailable_disclosed'] }
        }
    },
    'right-now-sampled': {
        'bounded-count-ok': {
            answer: `In the past hour 1,500 alerts at level 7 or above matched in Wazuh alerts; firewall events returned none. The 5 most recent are a sample:

| Rule ID | Description | Count |
|---|---|---|
| 5710 | sshd: attempt to login using a non-existent user | 1200 |

Most recent activity is on web-01 from 45.155.205.233 (T1110.001).`,
            expect: { hard_fail: [], score_min: 85 }
        },
        'count-outside-bounds': {
            answer: `In the past hour 1,500 alerts matched in Wazuh alerts.

| Rule ID | Description | Count |
|---|---|---|
| 5710 | sshd: attempt to login using a non-existent user | 2000 |
| 550 | Integrity checksum changed | 2 |`,
            expect: { hard_fail: ['H3_rule_counts_match'] }
        }
    }
};

function stubHttp(scenario) {
    const isFirewall = body => JSON.stringify(body?.query?.bool?.must ?? []).includes('"iptables"');
    const reply = content => ({ status: 200, data: { choices: [{ message: { content } }] } });
    axios.get = async () => ({ status: 200, data: { data: { affected_items: scenario.agents, total_affected_items: scenario.agents.length } } });
    axios.post = async (url, body) => {
        if (String(url).includes('/security/user/authenticate')) return { status: 200, data: 'synthetic-token' };
        if (body?.messages) {
            const system = body.messages[0].content;
            if (system.includes('Planning Engine')) return reply(JSON.stringify({ thought: 'synthetic plan', tools: scenario.plan }));
            if (system.includes('Memory Engine')) return reply('{"summary":"synthetic","keyEntities":[]}');
            return reply('(replaced by each answer variant)');
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

function normalize(fixture) {
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

function withAnswer(fixture, name, variant, answer, expect) {
    const out = structuredClone(fixture);
    out.synthetic = true;
    out.SYNTHETIC = 'Invented telemetry and a hand-written answer for validating evals/check.py. Not real data; never replay or score as a baseline.';
    out.variant = `${name}/${variant}`;
    out.result.report = answer;
    out.result.modelGenerated = true;
    const reportCall = out.calls.find(c => c.kind === 'llm' && !/Planning Engine|Memory Engine/.test(c.request?.messages?.[0]?.content ?? ''));
    if (reportCall?.response?.data?.choices?.[0]?.message) reportCall.response.data.choices[0].message.content = answer;
    out.expect = expect;
    return out;
}

const { captureFixtures } = await import('../src/recording/capture.js');
const { default: db } = await import('../src/config/db.js');
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'synthetic-cases-'));
const quiet = { log: console.log, warn: console.warn, error: console.error };
try {
    fs.mkdirSync(OUT_DIR, { recursive: true });
    for (const old of fs.readdirSync(OUT_DIR).filter(n => n.startsWith('SYNTHETIC-') && n.endsWith('.json'))) fs.rmSync(path.join(OUT_DIR, old));
    let written = 0;
    for (const [name, scenario] of Object.entries(SCENARIOS)) {
        stubHttp(scenario);
        console.log = console.warn = console.error = () => {};
        await captureFixtures({ questions: [scenario.question], outDir: tmp, timeoutMs: 10000, log: () => {} });
        await new Promise(resolve => setTimeout(resolve, 50));
        Object.assign(console, quiet);
        const fixture = normalize(JSON.parse(fs.readFileSync(path.join(tmp, fixtureFileName(scenario.question)), 'utf8')));
        if (fixture.status !== 'completed') throw new Error(`${name}: capture status ${fixture.status}`);
        for (const [variant, { answer, expect }] of Object.entries(ANSWERS[name])) {
            const file = path.join(OUT_DIR, `SYNTHETIC-${name}--${variant}.json`);
            fs.writeFileSync(file, JSON.stringify(withAnswer(fixture, name, variant, answer, expect), null, 2) + '\n');
            written++;
        }
    }
    console.log(`Wrote ${written} SYNTHETIC case(s) to ${OUT_DIR}`);
} finally {
    Object.assign(console, quiet);
    db.close();
    fs.rmSync(tmp, { recursive: true, force: true });
}
