const ALLOWED_HISTORY_ROLES = new Set(['user', 'assistant']);

/**
 * Validates client-supplied chat history before it can reach a prompt.
 * Keeps only { role, content } for 'user'/'assistant' turns with string content. Every other
 * role ('system', 'developer', 'tool', differently cased variants, ...) and any malformed
 * entry is dropped, so a client cannot add instructions with elevated authority.
 */
export function sanitizeChatHistory(history) {
    if (!Array.isArray(history)) {
        return { history: [], dropped: history == null ? 0 : 1 };
    }
    const clean = [];
    for (const entry of history) {
        if (entry && ALLOWED_HISTORY_ROLES.has(entry.role) && typeof entry.content === 'string') {
            clean.push({ role: entry.role, content: entry.content });
        }
    }
    return { history: clean, dropped: history.length - clean.length };
}
