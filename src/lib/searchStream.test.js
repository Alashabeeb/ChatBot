import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { applySearchEvent, lastSearchRequestId, startSearchMessage, isFollowUpAnswer } from './searchStream.js';

const run = (events, msg = startSearchMessage('m1', 'show me failed logons today')) => events.reduce(applySearchEvent, msg);

test('a streaming search message shows the live stage, then the verified answer as it grows', () => {
  let msg = startSearchMessage('m1', 'show me failed logons today');
  assert.equal(msg.type, 'agent_response');
  assert.equal(msg.isStreaming, true);
  assert.equal(msg.summary, '');
  msg = applySearchEvent(msg, { event: 'meta', data: { request_id: 'r1' } });
  msg = applySearchEvent(msg, { event: 'stage', data: { stage: 'searching', label: 'Searching Wazuh alerts and firewall events (2 queries)' } });
  assert.equal(msg.request_id, 'r1');
  assert.equal(msg.stageLabel, 'Searching Wazuh alerts and firewall events (2 queries)');
  msg = applySearchEvent(msg, { event: 'report', data: { markdown: '**Searched:** Wazuh alerts (3 matches).' } });
  msg = applySearchEvent(msg, { event: 'report', data: { markdown: '**Searched:** Wazuh alerts (3 matches).\n\nThere were 3 failed logons.' } });
  assert.equal(msg.summary, '**Searched:** Wazuh alerts (3 matches).\n\nThere were 3 failed logons.');
  assert.equal(msg.isStreaming, true);
});

test('done replaces everything with the final response', () => {
  const final = { type: 'agent_response', request_id: 'r1', summary: 'final', raw_logs: { searchSecurityLogs: [{}] }, total_hits: 3, follow_up_of: null, footer: 'f' };
  const msg = run([
    { event: 'meta', data: { request_id: 'r1' } },
    { event: 'report', data: { markdown: 'partial' } },
    { event: 'done', data: { response: final } }
  ]);
  assert.equal(msg.summary, 'final');
  assert.equal(msg.isStreaming, false);
  assert.equal(msg.stageLabel, null);
  assert.deepEqual(msg.raw_logs, final.raw_logs);
  assert.equal(msg.question, 'show me failed logons today', 'kept, for "Search again"');
  assert.equal(msg.id, 'm1');
});

test('a clarifying question or plain text answer becomes a text message', () => {
  const msg = run([{ event: 'done', data: { response: { type: 'text', text: 'Quick question before I search: Which IP address do you mean?', clarification: true, request_id: 'r2' } } }]);
  assert.equal(msg.type, 'text');
  assert.equal(msg.text, 'Quick question before I search: Which IP address do you mean?');
  assert.equal(msg.clarification, true);
  assert.equal(msg.isStreaming, false);
});

test('an error event becomes an error message', () => {
  const msg = run([{ event: 'error', data: { message: 'System error: boom.' } }]);
  assert.equal(msg.type, 'text');
  assert.equal(msg.isError, true);
  assert.equal(msg.text, 'System error: boom.');
});

test('follow-ups point at the latest search answer in the conversation', () => {
  const messages = [
    { role: 'assistant', type: 'agent_response', request_id: 'old' },
    { role: 'user', type: 'text', text: 'hi' },
    { role: 'assistant', type: 'agent_response', request_id: 'latest' },
    { role: 'assistant', type: 'text', text: 'chat answer', request_id: 'chat' },
    { role: 'assistant', type: 'agent_response', isStreaming: true, request_id: 'in-flight' }
  ];
  assert.equal(lastSearchRequestId(messages), 'latest');
  assert.equal(lastSearchRequestId([{ role: 'assistant', type: 'agent_response', isError: true, request_id: 'x' }]), null);
  assert.equal(lastSearchRequestId([]), null);
});

test('the old fixed "Searching…" placeholder is gone: the stage shown is the one actually running', () => {
  const src = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
  const files = ['pages/ChatPage.jsx', 'components/ChatMessage.jsx'].map(f => fs.readFileSync(path.join(src, f), 'utf8'));
  for (const text of files) {
    assert.doesNotMatch(text, /Searching Wazuh and firewall data…/);
    assert.doesNotMatch(text, /PendingSearch/);
  }
  assert.match(files[0], /\/api\/chat\/search\/stream/);
  // A follow-up answer searched nothing, so it must not carry the "Searched Wazuh" badge.
  assert.match(files[0], /isFollowUpAnswer\(m\) \? 'From previous search' : 'Searched Wazuh'/);
});

test('a follow-up answer is recognised live and after reloading from history', () => {
  assert.equal(isFollowUpAnswer({ follow_up_of: 'r1', summary: 'x' }), true);
  assert.equal(isFollowUpAnswer({ summary: '**Answered from the evidence of your previous search** ("q"). Nothing new…' }), true);
  assert.equal(isFollowUpAnswer({ summary: '**Searched:** Wazuh alerts (3 matches).' }), false);
});

test('the live stage is shown inside the assistant message column, not as a loose line in the card', () => {
  const src = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
  const page = fs.readFileSync(path.join(src, 'pages/ChatPage.jsx'), 'utf8');
  const message = fs.readFileSync(path.join(src, 'components/ChatMessage.jsx'), 'utf8');
  assert.doesNotMatch(page, /className="typing-status/, 'ChatPage must not render its own status line');
  assert.match(page, /status=\{m\.isStreaming \? \(m\.stageLabel \|\| 'Sending your question'\) : null\}/);
  assert.match(message, /export default function ChatMessage\(\{ message, badge, onSearchWazuh, status \}\)/);
});
