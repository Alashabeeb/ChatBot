import { applySearchEvent } from './searchStream.js';

/**
 * Browser side of POST /api/chat/message. The assistant decides per message whether it needs the
 * organisation's Wazuh data; the reply starts as a pending message, then becomes a chat answer (text,
 * streamed word by word) or a search answer (stages, then the verified answer), as `meta.mode` says.
 * Pure functions, unit-tested with node --test.
 */

export function startPendingMessage(id, question) {
  return { id, role: 'assistant', type: 'pending', isStreaming: true, stageLabel: null, question, timestamp: new Date().toISOString() };
}

export function applyMessageEvent(msg, { event, data }) {
  if (event === 'meta') {
    const base = { id: msg.id, role: 'assistant', isStreaming: true, question: msg.question, timestamp: msg.timestamp, request_id: data.request_id, route: data.route ?? null, mode: data.mode };
    return data.mode === 'search'
      ? { ...base, type: 'agent_response', summary: '', stageLabel: msg.stageLabel }
      : { ...base, type: 'text', text: '' };
  }
  if (msg.mode === 'chat') {
    switch (event) {
      case 'token': return { ...msg, text: msg.text + data.text };
      case 'error': return { ...msg, errorNotice: data.message };
      case 'done': {
        const finished = { ...msg, isStreaming: false, truncated: data.truncated, suggestSearch: data.suggest_search, modelGenerated: data.model_generated };
        // Nothing generated at all: the notice is the message.
        return !finished.text && finished.errorNotice ? { ...finished, text: finished.errorNotice, errorNotice: undefined, isError: true } : finished;
      }
      default: return msg;
    }
  }
  // Search answers, and anything before meta (the routing stage, an early error).
  if (event === 'stage') return { ...msg, stageLabel: data.label };
  return applySearchEvent(msg, { event, data });
}
