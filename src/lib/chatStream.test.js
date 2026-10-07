import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createSseParser, streamChat, buildHistory, ChatHttpError } from './chatStream.js';

const SAMPLE = 'event: meta\ndata: {"request_id":"r1","mode":"chat"}\n\n'
  + 'event: token\ndata: {"text":"Hel"}\n\n'
  + 'event: token\ndata: {"text":"lo"}\n\n'
  + 'event: done\ndata: {"model_generated":true}\n\n';

function collect(chunks) {
  const events = [];
  const parser = createSseParser(e => events.push(e));
  for (const c of chunks) parser.push(c);
  parser.end();
  return events;
}

test('SSE parser: same events however the stream is chunked', () => {
  const whole = collect([SAMPLE]);
  assert.deepEqual(whole.map(e => e.event), ['meta', 'token', 'token', 'done']);
  assert.deepEqual(whole[1].data, { text: 'Hel' });

  // One character at a time: every possible split point, including inside "\n\n" and inside JSON.
  assert.deepEqual(collect([...SAMPLE]), whole);
  // CRLF line endings.
  assert.deepEqual(collect([SAMPLE.replace(/\n/g, '\r\n')]), whole);
});

test('SSE parser: a final event without a trailing blank line is still delivered', () => {
  const events = collect(['event: done\ndata: {"ok":true}']);
  assert.deepEqual(events, [{ event: 'done', data: { ok: true } }]);
});

function fakeFetch(status, bodyChunks, json) {
  return async () => ({
    ok: status >= 200 && status < 300,
    status,
    json: async () => json,
    body: {
      getReader() {
        const encoder = new TextEncoder();
        const queue = bodyChunks.map(c => encoder.encode(c));
        return { read: async () => (queue.length ? { value: queue.shift(), done: false } : { value: undefined, done: true }) };
      }
    }
  });
}

test('streamChat: delivers events in order from a chunked body', async () => {
  const events = [];
  await streamChat({ url: '/x', headers: {}, body: {}, onEvent: e => events.push(e), fetchImpl: fakeFetch(200, [SAMPLE.slice(0, 40), SAMPLE.slice(40)]) });
  assert.equal(events.filter(e => e.event === 'token').map(e => e.data.text).join(''), 'Hello');
  assert.equal(events.at(-1).event, 'done');
});

test('streamChat: non-2xx replies reject with the server message and status', async () => {
  await assert.rejects(
    streamChat({ url: '/x', headers: {}, body: {}, onEvent: () => {}, fetchImpl: fakeFetch(413, [], { error: 'That message is too long.' }) }),
    e => e instanceof ChatHttpError && e.status === 413 && e.message === 'That message is too long.'
  );
});

test('history: only real conversation turns are sent to the model', () => {
  const history = buildHistory([
    { role: 'assistant', type: 'text', text: 'Welcome to SOC ChatBot…', isWelcome: true },
    { role: 'user', type: 'text', text: 'Draft an email' },
    { role: 'assistant', type: 'text', text: 'Here is a draft…' },
    { role: 'user', type: 'text', text: 'show me failed logons' },
    { role: 'assistant', type: 'agent_response', summary: '**Answer**: 12 failed logons…' },
    { role: 'assistant', type: 'text', text: 'The AI model is unavailable right now…', isError: true },
    { role: 'assistant', type: 'text', text: 'half an answ', isStreaming: true },
    { role: 'assistant', type: 'text', text: '   ' },
    { role: 'assistant', type: 'data_card', rows: [] }
  ]);
  assert.deepEqual(history, [
    { role: 'user', content: 'Draft an email' },
    { role: 'assistant', content: 'Here is a draft…' },
    { role: 'user', content: 'show me failed logons' },
    { role: 'assistant', content: '**Answer**: 12 failed logons…' }
  ]);
});
