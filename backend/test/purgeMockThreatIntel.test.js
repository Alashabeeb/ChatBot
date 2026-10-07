import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'child_process';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { fileURLToPath } from 'url';
import Database from 'better-sqlite3';

const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'purge-mock-ti-'));
const dbPath = path.join(tmpDir, 'soc_chatbot.db');
const quarantinePath = path.join(tmpDir, 'soc_chatbot.quarantine.db');
const scriptPath = fileURLToPath(new URL('../scripts/purgeMockThreatIntel.js', import.meta.url));

// Must be set before config/db.js loads.
process.env.SOC_DB_PATH = dbPath;
process.env.LLM_API_URL = 'http://llm.test';
process.env.OPENSEARCH_URL = 'http://opensearch.test';
process.env.WAZUH_SERVER_API_URL = 'http://wazuh.test';
process.env.WAZUH_USER = 'test';
process.env.WAZUH_PASSWORD = 'test';

const { default: appDb, initDatabase } = await import('../src/config/db.js');
const { THREAT_INTEL_ABSENT_NOTE } = await import('../src/agent/runtime.js');
const { scan } = await import('../scripts/purgeMockThreatIntel.js');

const USER_ID = 'user_admin_root';
const MOCK_OBJECT = JSON.stringify({ indicator: '41.203.12.56', malicious: false, threatScore: 10, tags: ['scanner'], message: 'Mock threat intelligence response for 41.203.12.56. Real integration pending.' });

const CONTAMINATED = {
    messages: {
        msg_echoed_mock: `**Evidence**: lookupThreatIntel returned ${MOCK_OBJECT}`,
        msg_old_canned: 'I searched the database and intelligence sources, but found zero matching alerts or data for your query.',
        msg_paraphrase: '**Risk Assessment**: Threat intelligence indicates the IP was tagged as a scanner with a threat score of 10.'
    },
    memories: {
        mem_mock: JSON.stringify({ summary: 'Investigated 41.203.12.56; threat intel reports it is not malicious.', keyEntities: ['41.203.12.56', 'scanner'] })
    }
};

const CLEAN = {
    messages: {
        msg_user: 'Check IP 41.203.12.56',
        msg_clean_report: `**Executive Summary**: 3 sshd authentication failures from 41.203.12.56, consistent with a port scan followed by brute force.\n**Confidence Score**: 80%\n\n${THREAT_INTEL_ABSENT_NOTE}`,
        msg_fixed_canned: `I searched the available data sources, but found zero matching alerts or data for your query.\n\n${THREAT_INTEL_ABSENT_NOTE}`
    },
    memories: {
        mem_clean: JSON.stringify({ summary: 'Brute force attempts against web-01 from 41.203.12.56.', keyEntities: ['41.203.12.56', 'web-01'] })
    }
};

function seed() {
    initDatabase();
    const now = new Date().toISOString();
    appDb.prepare('INSERT INTO sessions (id, user_id, title, created_at, updated_at) VALUES (?, ?, ?, ?, ?)').run('sess_1', USER_ID, 'Check IP', now, now);
    const insertMessage = appDb.prepare(`INSERT INTO messages (id, session_id, user_id, role, type, text, summary, raw_logs, total_hits, created_at)
        VALUES (?, 'sess_1', ?, ?, ?, ?, ?, NULL, 0, ?)`);
    const insertMemory = appDb.prepare(`INSERT INTO memories (id, user_id, category, term_type, content, relevance_score, created_at, updated_at)
        VALUES (?, ?, 'investigation', 'long-term', ?, 80, ?, ?)`);

    for (const group of [CONTAMINATED, CLEAN]) {
        for (const [id, body] of Object.entries(group.messages)) {
            const isUser = id === 'msg_user';
            // User messages store body in `text`; agent reports store it in `summary`.
            insertMessage.run(id, USER_ID, isUser ? 'user' : 'assistant', isUser ? 'text' : 'agent_response', isUser ? body : '', isUser ? '' : body, now);
        }
        for (const [id, content] of Object.entries(group.memories)) {
            insertMemory.run(id, USER_ID, content, now, now);
        }
    }
    appDb.close();
}

after(() => fs.rmSync(tmpDir, { recursive: true, force: true }));

seed();

const ids = group => [...Object.keys(group.messages), ...Object.keys(group.memories)].sort();

function runScript(...args) {
    return spawnSync(process.execPath, [scriptPath, '--db', dbPath, '--quarantine', quarantinePath, ...args], { encoding: 'utf8' });
}

function idsIn(file, sql) {
    const db = new Database(file, { readonly: true });
    try {
        return db.prepare(sql).all().map(r => r.id).sort();
    } finally {
        db.close();
    }
}

const mainIds = () => idsIn(dbPath, 'SELECT id FROM messages UNION ALL SELECT id FROM memories');

test('scan flags every contaminated record and no clean one', () => {
    const db = new Database(dbPath, { readonly: true });
    try {
        assert.deepEqual(scan(db).map(h => h.id).sort(), ids(CONTAMINATED));
        // Signature-only mode still catches the verbatim mock and the old canned claim.
        assert.deepEqual(scan(db, { signatureOnly: true }).map(h => h.id).sort(), ['msg_echoed_mock', 'msg_old_canned']);
    } finally {
        db.close();
    }
});

test('CLI: dry run reports, --apply quarantines, --restore puts records back', () => {
    const dryRun = runScript();
    assert.equal(dryRun.status, 2, dryRun.stdout + dryRun.stderr);
    assert.deepEqual(mainIds(), [...ids(CONTAMINATED), ...ids(CLEAN)].sort(), 'dry run must not modify the database');

    const apply = runScript('--apply');
    assert.equal(apply.status, 0, apply.stdout + apply.stderr);
    assert.deepEqual(mainIds(), ids(CLEAN), 'only clean records remain in the main database');
    assert.deepEqual(idsIn(quarantinePath, 'SELECT source_id AS id FROM records'), ids(CONTAMINATED));

    const recheck = runScript();
    assert.equal(recheck.status, 0, recheck.stdout + recheck.stderr);

    const restore = runScript('--restore');
    assert.equal(restore.status, 0, restore.stdout + restore.stderr);
    assert.deepEqual(mainIds(), [...ids(CONTAMINATED), ...ids(CLEAN)].sort());
    assert.deepEqual(idsIn(quarantinePath, 'SELECT source_id AS id FROM records'), []);
});
