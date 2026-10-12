/**
 * Evidence kept briefly so a follow-up question can be answered from the previous search (Phase 7).
 *
 * In memory only, per backend process (one process per database, F-31): nothing more is written to
 * disk, and a restart simply means the next follow-up searches again. Entries belong to the user who
 * ran the search, expire after FOLLOW_UP_TTL_MS (default 2 hours), and at most FOLLOW_UP_MAX_ENTRIES
 * (default 50) are kept, oldest dropped first.
 */
const entries = new Map();

const setting = (name, fallback) => {
    const value = Number(process.env[name]);
    return Number.isFinite(value) && value > 0 ? value : fallback;
};

/** entry: { userId, question, results, plan, searchedAt }. A follow-up stores the same evidence under its own ID. */
export function storeEvidence(requestId, entry) {
    entries.delete(requestId);
    entries.set(requestId, { ...entry, storedAt: Date.now() });
    const max = setting('FOLLOW_UP_MAX_ENTRIES', 50);
    while (entries.size > max) entries.delete(entries.keys().next().value);
}

/** The evidence for requestId, only if it belongs to userId and hasn't expired. */
export function getEvidence(requestId, userId) {
    const entry = entries.get(requestId);
    if (!entry) return null;
    if (Date.now() - entry.storedAt > setting('FOLLOW_UP_TTL_MS', 2 * 60 * 60 * 1000)) {
        entries.delete(requestId);
        return null;
    }
    return entry.userId === userId ? entry : null;
}

export function clearEvidenceCache() {
    entries.clear();
}
