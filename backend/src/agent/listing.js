/**
 * "Show me the 20 most recent logs" (F-68): a request for records, not analysis. The search already
 * returns each source's most recent records, newest first, so the code lists them itself, exact and
 * with nothing for the model to get wrong. No model call.
 */
const NOUNS = 'logs?|events?|alerts?|records?|entries|entry|logons?|logins?|attempts?|failures?';
const LISTING = new RegExp(`\\b(?:(?:top|first)\\s+(\\d{1,3})\\s+)?(?:(\\d{1,3})\\s+)?(?:most\\s+recent|latest|newest|recent|last)\\s+(?:(\\d{1,3})\\s+)?((?:[a-z-]+\\s+){0,2}?)(${NOUNS})\\b`, 'i');
const TIME_UNIT = /\b(?:hours?|hrs?|days?|weeks?|minutes?|mins?|months?|years?)\b/i;
export const MAX_LISTED = 100;

/** { count } when the question asks for the N most recent records, else null. */
export function listingRequest(text) {
    const m = LISTING.exec(String(text ?? ''));
    if (!m || TIME_UNIT.test(m[4] ?? '')) return null;   // "the last 24 hours of alerts" is a window, not a list
    const stated = m[1] ?? m[2] ?? m[3];
    const singular = !/s$/i.test(m[5]) && m[5].toLowerCase() !== 'entries';
    const count = stated ? Number(stated) : singular ? 1 : 20;
    return { count: Math.min(Math.max(count, 1), MAX_LISTED) };
}

const get = (obj, path) => path.reduce((v, k) => (v && typeof v === 'object' ? v[k] : undefined), obj);
const first = (record, paths) => paths.map(p => get(record, p)).find(v => v !== undefined && v !== null && v !== '');
const cell = value => String(value ?? '').replace(/\s+/g, ' ').replace(/\|/g, '\\|').trim().slice(0, 100) || '-';
const time = value => (value ? String(value).replace('T', ' ').replace(/(\.\d+)?(Z|[+-]\d{2}:?\d{2})$/, '') : '-');

/** A Markdown table of records, one row each, values escaped so no log value can break the table. */
export function listingTable(records) {
    const rows = records.map(r => `| ${cell(time(r['@timestamp'] ?? r.vulnerability?.detected_at))} | ${cell(r.rule?.id ?? r.vulnerability?.id)} | ${cell(r.rule?.level ?? r.vulnerability?.severity)} | ${cell(r.rule?.description ?? r.vulnerability?.description)} | ${cell(r.agent?.name ?? r.agent?.id)} | ${cell(first(r, [['data', 'srcip'], ['data', 'src_ip'], ['data', 'win', 'eventdata', 'ipAddress'], ['srcip']]))} | ${cell(first(r, [['data', 'srcuser'], ['data', 'dstuser'], ['data', 'user'], ['data', 'win', 'eventdata', 'targetUserName']]))} |`);
    return ['| Time (UTC) | Rule | Level | Description | Agent | Source IP | User |', '|---|---|---|---|---|---|---|', ...rows].join('\n');
}

/** The N most recent records across every successful search, newest first. */
export function mostRecentRecords(index, count) {
    const records = index.searches.filter(s => !s.failed).flatMap(s => s.records);
    const at = r => Date.parse(r['@timestamp'] ?? r.vulnerability?.detected_at ?? '') || 0;
    return { records: [...records].sort((a, b) => at(b) - at(a)).slice(0, count), retrieved: records.length };
}
