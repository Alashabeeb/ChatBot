import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { startPendingMessage, applyMessageEvent } from './messageStream.js';

const run = events => events.reduce(applyMessageEvent, startPendingMessage('m1', 'question'));

test('before the assistant has decided, the message shows what it is doing', () => {
  const msg = startPendingMessage('m1', 'the firewall seems slow');
  assert.equal(msg.type, 'pending');
  assert.equal(msg.isStreaming, true);
  const routing = applyMessageEvent(msg, { event: 'stage', data: { stage: 'routing', label: 'Working out whether this needs your Wazuh data' } });
  assert.equal(routing.stageLabel, 'Working out whether this needs your Wazuh data');
});

test('a chat answer streams as text, and keeps the chat flags', () => {
  const msg = run([
    { event: 'meta', data: { request_id: 'r1', mode: 'chat', route: { route: 'chat', by: 'rule' } } },
    { event: 'token', data: { text: 'Hello' } },
    { event: 'token', data: { text: ' there' } },
    { event: 'done', data: { mode: 'chat', model_generated: true, truncated: false, suggest_search: true } }
  ]);
  assert.equal(msg.type, 'text');
  assert.equal(msg.text, 'Hello there');
  assert.equal(msg.request_id, 'r1');
  assert.equal(msg.isStreaming, false);
  assert.equal(msg.suggestSearch, true);
  assert.equal(msg.question, 'question', 'kept, for "Search Wazuh for this"');
});

test('a chat error keeps any partial text and shows the notice; with no text it becomes the message', () => {
  const partial = run([{ event: 'meta', data: { mode: 'chat' } }, { event: 'token', data: { text: 'Part' } }, { event: 'error', data: { message: 'stopped responding' } }, { event: 'done', data: { mode: 'chat' } }]);
  assert.equal(partial.text, 'Part');
  assert.equal(partial.errorNotice, 'stopped responding');
  const none = run([{ event: 'meta', data: { mode: 'chat' } }, { event: 'error', data: { message: 'unavailable' } }, { event: 'done', data: { mode: 'chat' } }]);
  assert.equal(none.text, 'unavailable');
  assert.equal(none.isError, true);
});

test('a search answer becomes an agent response: stages, the growing verified answer, then the final one', () => {
  let msg = run([
    { event: 'meta', data: { request_id: 'r2', mode: 'search' } },
    { event: 'stage', data: { stage: 'searching', label: 'Searching Wazuh alerts and firewall events (2 queries)' } },
    { event: 'report', data: { markdown: '**Searched:** ...' } }
  ]);
  assert.equal(msg.type, 'agent_response');
  assert.equal(msg.stageLabel, 'Searching Wazuh alerts and firewall events (2 queries)');
  assert.equal(msg.summary, '**Searched:** ...');
  msg = applyMessageEvent(msg, { event: 'done', data: { response: { type: 'agent_response', request_id: 'r2', summary: 'final', raw_logs: {} } } });
  assert.equal(msg.summary, 'final');
  assert.equal(msg.isStreaming, false);
});

test('a search that ends in a clarifying question becomes a text message', () => {
  const msg = run([{ event: 'meta', data: { mode: 'search' } }, { event: 'done', data: { response: { type: 'text', text: 'Quick question before I search: Which IP address do you mean?', clarification: true } } }]);
  assert.equal(msg.type, 'text');
  assert.equal(msg.clarification, true);
});

test('the page has no Search Wazuh toggle: every message goes to /api/chat/message, and the assistant decides', () => {
  const src = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
  const page = fs.readFileSync(path.join(src, 'pages/ChatPage.jsx'), 'utf8');
  assert.doesNotMatch(page, /mode-toggle|setSearchWazuh|soc_search_wazuh|aria-pressed=\{searchWazuh\}/);
  assert.match(page, /\/api\/chat\/message/);
  assert.doesNotMatch(page, /\/api\/chat\/stream'|\/api\/chat\/search\/stream/);
  assert.match(page, /force_route: forceSearch \? 'search' : undefined/, '"Search Wazuh for this" still forces a search');
  assert.doesNotMatch(page, /Turn on \*\*Search Wazuh\*\*/i, 'the welcome message does not mention the removed toggle');
});
