import { Fragment, useMemo, useState } from 'react';
import { ChevronDown, ChevronRight } from 'lucide-react';
import './LogDetailsModal.css';

// ---------- Wazuh field extraction (defensive — field names vary by rule) ----------
function extractFields(log) {
  const rule = log.rule || {};
  const data = log.data || {};
  const agent = log.agent || {};

  return {
    time: log['@timestamp'] || log.timestamp || null,
    level: typeof rule.level === 'number' ? rule.level : 0,
    description: rule.description || 'Unlabeled event',
    ruleId: rule.id || '—',
    groups: rule.groups || [],
    mitreIds: rule.mitre?.id || [],
    mitreTechniques: rule.mitre?.technique || [],
    host: agent.name || agent.id || log.manager?.name || '—',
    srcip: data.srcip || data.src_ip || log.srcip || '—',
    user: data.srcuser || data.dstuser || data.user || '—',
  };
}

function severityBand(level) {
  if (level >= 12) return { key: 'critical', label: 'Critical' };
  if (level >= 7) return { key: 'high', label: 'High' };
  if (level >= 4) return { key: 'medium', label: 'Medium' };
  return { key: 'low', label: 'Low' };
}

function formatTime(ts) {
  if (!ts) return '—';
  const d = new Date(ts);
  if (Number.isNaN(d.getTime())) return String(ts);
  return d.toLocaleString(undefined, {
    month: 'short', day: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit',
  });
}

function topN(list, n = 3) {
  const counts = new Map();
  for (const v of list) {
    if (!v || v === '—') continue;
    counts.set(v, (counts.get(v) || 0) + 1);
  }
  return [...counts.entries()].sort((a, b) => b[1] - a[1]).slice(0, n);
}

export default function LogDetailsModal({ logs = [], source }) {
  const [expandedRow, setExpandedRow] = useState(null);

  const parsed = useMemo(() => logs.map((log) => ({ raw: log, ...extractFields(log) })), [logs]);

  const severityCounts = useMemo(() => {
    const counts = { critical: 0, high: 0, medium: 0, low: 0 };
    for (const p of parsed) counts[severityBand(p.level).key] += 1;
    return counts;
  }, [parsed]);

  const topIPs = useMemo(() => topN(parsed.map((p) => p.srcip)), [parsed]);
  const topUsers = useMemo(() => topN(parsed.map((p) => p.user)), [parsed]);
  const topHosts = useMemo(() => topN(parsed.map((p) => p.host)), [parsed]);

  if (!logs.length) {
    return (
      <div className="log-details">
        <div className="log-empty">No matching events were returned for this query.</div>
      </div>
    );
  }

  return (
    <div className="log-details">
      {/* Provenance strip */}
      <div className="log-provenance">
        <span>{source || 'wazuh-alerts-*'}</span>
        <span className="dot">·</span>
        <span>{logs.length} events</span>
        <span className="dot">·</span>
        <span>Fetched {formatTime(new Date().toISOString())}</span>
      </div>

      {/* Summary strip */}
      <div className="log-summary-strip">
        <div className="summary-stat">
          <span className="stat-value">{logs.length}</span>
          <span className="stat-label">Total Events</span>
        </div>
        {(['critical', 'high', 'medium', 'low']).map((key) => (
          severityCounts[key] > 0 && (
            <div className="summary-stat" key={key}>
              <span className={`stat-value sev-text-${key}`}>{severityCounts[key]}</span>
              <span className="stat-label">{key[0].toUpperCase() + key.slice(1)}</span>
            </div>
          )
        ))}
      </div>

      {/* Top offenders */}
      <div className="log-offenders">
        <OffenderColumn title="Top Source IPs" items={topIPs} mono />
        <OffenderColumn title="Top Accounts" items={topUsers} mono />
        <OffenderColumn title="Top Hosts" items={topHosts} />
      </div>

      {/* Detail table */}
      <div className="log-table-wrapper">
        <table className="log-table">
          <thead>
            <tr>
              <th className="col-expand" />
              <th>Time</th>
              <th>Severity</th>
              <th>Rule</th>
              <th>Host</th>
              <th>Source IP</th>
              <th>User</th>
            </tr>
          </thead>
          <tbody>
            {parsed.map((p, i) => {
              const sev = severityBand(p.level);
              const isOpen = expandedRow === i;
              return (
                <Fragment key={i}>
                  <tr
                    className="log-row"
                    onClick={() => setExpandedRow(isOpen ? null : i)}
                  >
                    <td className="col-expand">
                      {isOpen ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
                    </td>
                    <td className="mono">{formatTime(p.time)}</td>
                    <td>
                      <span className={`sev-badge sev-${sev.key}`}>{sev.label}</span>
                    </td>
                    <td>
                      <div className="rule-cell">
                        <span>{p.description}</span>
                        {p.mitreTechniques.length > 0 && (
                          <span className="mitre-chip">
                            {p.mitreIds[0]} · {p.mitreTechniques[0]}
                          </span>
                        )}
                      </div>
                    </td>
                    <td>{p.host}</td>
                    <td className="mono">{p.srcip}</td>
                    <td className="mono">{p.user}</td>
                  </tr>
                  {isOpen && (
                    <tr className="raw-row">
                      <td colSpan={7}>
                        <pre>{JSON.stringify(p.raw, null, 2)}</pre>
                      </td>
                    </tr>
                  )}
                </Fragment>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function OffenderColumn({ title, items, mono }) {
  const max = items.length > 0 ? items[0][1] : 1;
  return (
    <div className="offender-col">
      <h4>{title}</h4>
      {items.length === 0 && <div className="offender-empty">—</div>}
      {items.map(([value, count]) => (
        <div className="offender-row" key={value}>
          <span className={`offender-value ${mono ? 'mono' : ''}`}>{value}</span>
          <div className="offender-bar-track">
            <div className="offender-bar-fill" style={{ width: `${(count / max) * 100}%` }} />
          </div>
          <span className="offender-count">{count}</span>
        </div>
      ))}
    </div>
  );
}