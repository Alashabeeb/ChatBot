import { AsyncLocalStorage } from 'async_hooks';

/**
 * Per-run scope for runAgentWorkflow. Everything the run awaits (planner, tools, model calls,
 * background memory writes) sees the same store, so logs and errors can be attributed to the
 * run without threading the request ID through every function signature.
 */
const storage = new AsyncLocalStorage();

export function withRunScope(requestId, fn, { question = null } = {}) {
    return storage.run({ requestId, question, errors: [] }, fn);
}

export function currentRequestId() {
    return storage.getStore()?.requestId ?? null;
}

/** The user's question for the current run (used to select fixtures in replay mode). */
export function currentRunQuestion() {
    return storage.getStore()?.question ?? null;
}

/** Records an error against the current run. No-op outside a run. */
export function recordRunError(stage, message, detail = {}) {
    const store = storage.getStore();
    if (store) {
        store.errors.push({ stage, message, ...detail, at: new Date().toISOString() });
    }
}

export function currentRunErrors() {
    return [...(storage.getStore()?.errors ?? [])];
}

function tag(args) {
    const requestId = currentRequestId();
    return requestId ? [`[req:${requestId}]`, ...args] : args;
}

/** Console logging tagged with the current request ID, matching runs.request_id. */
export const runLog = {
    info: (...args) => console.log(...tag(args)),
    warn: (...args) => console.warn(...tag(args)),
    error: (...args) => console.error(...tag(args))
};
