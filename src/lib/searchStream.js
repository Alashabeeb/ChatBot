/**
 * Browser side of POST /api/chat/search/stream (Phase 7). Pure functions, unit-tested with node --test.
 *
 * A Search Wazuh answer is shown while it runs: the stage the backend reports as it actually starts it,
 * then the answer as it grows. Everything in `summary` while streaming has already passed the server's
 * verification (the code-written header first, then verified statements); `done` replaces it with the
 * final answer.
 */

export function startSearchMessage(id, question) {
  return { id, role: 'assistant', type: 'agent_response', summary: '', isStreaming: true, stageLabel: null, question, timestamp: new Date().toISOString() };
}

export function applySearchEvent(msg, { event, data }) {
  switch (event) {
    case 'meta':
      return { ...msg, request_id: data.request_id };
    case 'stage':
      return { ...msg, stageLabel: data.label };
    case 'report':
      return { ...msg, summary: data.markdown };
    case 'error':
      return { id: msg.id, role: 'assistant', type: 'text', text: data.message, isError: true, isStreaming: false, timestamp: msg.timestamp };
    case 'done': {
      const response = data.response ?? {};
      if (response.type === 'agent_response') {
        return { ...msg, ...response, id: msg.id, question: msg.question, isStreaming: false, stageLabel: null };
      }
      return {
        id: msg.id, role: 'assistant', type: 'text', text: response.text ?? '', clarification: response.clarification === true,
        isError: response.isError === true, request_id: response.request_id ?? msg.request_id, modelGenerated: response.model_generated,
        isStreaming: false, question: msg.question, timestamp: msg.timestamp
      };
    }
    default:
      return msg;
  }
}

/** request_id of the latest finished Search Wazuh answer, for follow-up questions. */
export function lastSearchRequestId(messages) {
  const last = [...messages].reverse().find(m => m.role === 'assistant' && m.type === 'agent_response' && m.request_id && !m.isStreaming && !m.isError);
  return last?.request_id ?? null;
}

/** True for an answer written from a previous search's evidence (live, or reloaded from history). */
export function isFollowUpAnswer(msg) {
  return Boolean(msg?.follow_up_of) || String(msg?.summary ?? '').startsWith('**Answered from the evidence of your previous search**');
}
