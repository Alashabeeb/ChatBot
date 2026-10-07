/**
 * raw_logs from a Search Wazuh answer is keyed per tool call:
 *   { searchSecurityLogs: [...], 'searchSecurityLogs:firewall': [...], getEndpointStatus: [...],
 *     'searchSecurityLogs#2': [...] }
 * Messages saved before that change hold a plain array. These helpers turn either shape into a flat
 * list of { record, source } so "View Full Details" can say where each record came from (F-33).
 */

const BASE_LABELS = {
  searchSecurityLogs: 'Wazuh alerts',
  'searchSecurityLogs:firewall': 'Firewall (Wazuh)',
  getEndpointStatus: 'Wazuh agents'
};

export function sourceLabel(key) {
  const match = /^([^#:]+)(?:#(\d+))?(:firewall)?$/.exec(key);
  if (!match) return key;
  const [, tool, n, firewall = ''] = match;
  const base = BASE_LABELS[tool + firewall] ?? key;
  return n && base !== key ? `${base} (query ${n})` : base;
}

export function labelRawLogs(rawLogs) {
  if (Array.isArray(rawLogs)) return rawLogs.map(record => ({ record, source: null }));
  if (!rawLogs || typeof rawLogs !== 'object') return [];
  return Object.entries(rawLogs).flatMap(([key, records]) =>
    (Array.isArray(records) ? records : []).map(record => ({ record, source: sourceLabel(key) })));
}
