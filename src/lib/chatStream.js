/**
 * Browser side of POST /api/chat/stream. Plain functions with no React, so they can be unit-tested
 * with node --test (see chatStream.test.js).
 */

/**
 * Incremental parser for server-sent events. Feed it text chunks as they arrive; it calls
 * onEvent({ event, data }) once per complete event, however the chunks happen to be split.
 */
export function createSseParser(onEvent) {
  let buffer = '';
  const dispatch = (block) => {
    let event = 'message';
    const dataLines = [];
    for (const line of block.split(/\r?\n/)) {
      if (line.startsWith('event:')) event = line.slice(6).trim();
      else if (line.startsWith('data:')) dataLines.push(line.slice(5).trimStart());
    }
    if (dataLines.length === 0) return;
    let data = dataLines.join('\n');
    try {
      data = JSON.parse(data);
    } catch {
      // leave non-JSON data as a string
    }
    onEvent({ event, data });
  };
  return {
    push(chunk) {
      buffer += chunk;
      const blocks = buffer.split(/\r?\n\r?\n/);
      buffer = blocks.pop();
      for (const block of blocks) if (block.trim()) dispatch(block);
    },
    end() {
      if (buffer.trim()) dispatch(buffer);
      buffer = '';
    }
  };
}

export class ChatHttpError extends Error {
  constructor(status, message) {
    super(message);
    this.name = 'ChatHttpError';
    this.status = status;
  }
}

/**
 * POSTs a chat message and calls onEvent for each server-sent event (meta, token, error, done).
 * Rejects with ChatHttpError for non-2xx replies (401/403 expired session, 400/413 bad input), and
 * with an AbortError when `signal` is aborted.
 */
export async function streamChat({ url, headers, body, signal, onEvent, fetchImpl = fetch }) {
  const response = await fetchImpl(url, { method: 'POST', headers, body: JSON.stringify(body), signal });
  if (!response.ok) {
    let message = `Request failed with status ${response.status}.`;
    try {
      const json = await response.json();
      if (json?.error) message = json.error;
    } catch {
      // keep the generic message
    }
    throw new ChatHttpError(response.status, message);
  }

  const parser = createSseParser(onEvent);
  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  for (;;) {
    const { value, done } = await reader.read();
    if (done) break;
    parser.push(decoder.decode(value, { stream: true }));
  }
  parser.push(decoder.decode());
  parser.end();
}

/**
 * Conversation history to send with a new message: real user and assistant turns only. The welcome
 * message, error notices, unfinished answers and empty turns are left out, so the model never sees
 * text it did not write as if it had.
 */
export function buildHistory(messages) {
  return messages
    .filter(m => !m.isWelcome && !m.isError && !m.isStreaming)
    .filter(m => m.type === 'text' || m.type === 'agent_response')
    .map(m => ({ role: m.role === 'user' ? 'user' : 'assistant', content: (m.text || m.summary || '').trim() }))
    .filter(m => m.content);
}
