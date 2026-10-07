import { Fragment, useMemo, useState } from 'react';
import { ChevronDown, ChevronRight, Search } from 'lucide-react';
import './LogDetailsModal.css';

// ---------- Wazuh field extraction (defensive — field names vary by rule) ----------
function extractFields(log) {
  const rule = log.rule || {};
  const data = log.data || {};
  const agent = log.agent || {};
  const predecoder = log.predecoder || {};
  const decoder = log.decoder || {};

  // Deep user extraction — Wazuh stores users in many different places
  const user = data.srcuser || data.dstuser || data.user || data.win?.eventdata?.targetUserName 
    || data.win?.eventdata?.subjectUserName || data.audit?.auid || data.uid 
    || predecoder.user || log.syscheck?.uname || '—';

  // Deep email extraction — check common mail-related fields
  const email = data.email || data.mail || data.recipient || data.sender 
    || data.win?.eventdata?.targetUserName?.includes?.('@') && data.win.eventdata.targetUserName
    || data.srcuser?.includes?.('@') && data.srcuser
    || data.dstuser?.includes?.('@') && data.dstuser
    || '—';

  return {
    time: log['@timestamp'] || log.timestamp || null,
    level: typeof rule.level === 'number' ? rule.level : 0,
    // Wazuh agent inventory records have no rule; describe them as what they are.
    description: rule.description || (log.status && log.name ? `Wazuh agent: ${log.status}` : 'Unlabeled event'),
    ruleId: rule.id || '—',
    groups: rule.groups || [],
    mitreIds: rule.mitre?.id || [],
    mitreTechniques: rule.mitre?.technique || [],
    host: agent.name || agent.id || log.manager?.name || '—',
    srcip: data.srcip || data.src_ip || log.srcip || data.win?.eventdata?.ipAddress || '—',
    user,
    email,
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

/** entries: [{ record, source }] from labelRawLogs(); source names the tool each record came from (F-33). */
export default function LogDetailsModal({ entries = [], source, totalHits, isLoading }) {
  const logs = entries;
  const [expandedRow, setExpandedRow] = useState(null);
  const [visibleCount, setVisibleCount] = useState(100);
  const [searchQuery, setSearchQuery] = useState('');

  const parsed = useMemo(() => entries.map(({ record, source: from }) => ({ raw: record, from: from || '—', ...extractFields(record) })), [entries]);
  
  const filteredParsed = useMemo(() => {
    if (!searchQuery.trim()) return parsed;
    const lower = searchQuery.toLowerCase();
    return parsed.filter(p => 
      p.srcip.toLowerCase().includes(lower) ||
      p.user.toLowerCase().includes(lower) ||
      p.host.toLowerCase().includes(lower) ||
      p.description.toLowerCase().includes(lower) ||
      p.from.toLowerCase().includes(lower) ||
      p.email.toLowerCase().includes(lower) ||
      (p.mitreIds && p.mitreIds.some(m => String(m).toLowerCase().includes(lower))) ||
      (p.mitreTechniques && p.mitreTechniques.some(m => String(m).toLowerCase().includes(lower)))
    );
  }, [parsed, searchQuery]);

  const severityCounts = useMemo(() => {
    const counts = { critical: 0, high: 0, medium: 0, low: 0 };
    for (const p of parsed) counts[severityBand(p.level).key] += 1;
    return counts;
  }, [parsed]);

  const topIPs = useMemo(() => topN(parsed.map((p) => p.srcip)), [parsed]);
  const topUsers = useMemo(() => topN(parsed.map((p) => p.user)), [parsed]);
  const topHosts = useMemo(() => topN(parsed.map((p) => p.host)), [parsed]);

  if (isLoading) {
    return (
      <div className="log-details" style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', minHeight: '300px' }}>
        <div className="typing-indicator" style={{ display: 'flex', gap: '5px', marginBottom: '15px' }}>
          <span style={{ width: '8px', height: '8px', background: 'var(--accent, #00ff88)', borderRadius: '50%', animation: 'typing 1.4s infinite ease-in-out both' }}></span>
          <span style={{ width: '8px', height: '8px', background: 'var(--accent, #00ff88)', borderRadius: '50%', animation: 'typing 1.4s infinite ease-in-out both', animationDelay: '0.2s' }}></span>
          <span style={{ width: '8px', height: '8px', background: 'var(--accent, #00ff88)', borderRadius: '50%', animation: 'typing 1.4s infinite ease-in-out both', animationDelay: '0.4s' }}></span>
        </div>
        <div style={{ color: 'var(--text-secondary, #aaa)', fontSize: '14px' }}>Loading massive payload from database...</div>
      </div>
    );
  }

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
        <span>{totalHits || logs.length} events</span>
        <span className="dot">·</span>
        <span>Fetched {formatTime(new Date().toISOString())}</span>
      </div>

      {/* Summary strip */}
      <div className="log-summary-strip">
        <div className="summary-stat">
          <span className="stat-value">{totalHits || logs.length}</span>
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

      {/* Filter / Search Input */}
      <div style={{ padding: '0 20px', marginBottom: '15px' }}>
        <div style={{ display: 'flex', alignItems: 'center', background: 'var(--bg-tertiary, #2d2d2d)', padding: '8px 12px', borderRadius: '6px', border: '1px solid var(--border, #444)' }}>
          <Search size={16} color="var(--text-secondary, #aaa)" style={{ marginRight: '10px' }} />
          <input 
            type="text" 
            placeholder="Filter these events..." 
            value={searchQuery}
            onChange={(e) => { setSearchQuery(e.target.value); setVisibleCount(100); setExpandedRow(null); }}
            style={{ background: 'transparent', border: 'none', color: 'var(--text-primary, #fff)', width: '100%', outline: 'none', fontSize: '14px' }}
          />
        </div>
      </div>

      {/* Detail table */}
      <div className="log-table-wrapper">
        <table className="log-table">
          <thead>
            <tr>
              <th className="col-expand" />
              <th>Source</th>
              <th>Time</th>
              <th>Severity</th>
              <th>Rule</th>
              <th>Host</th>
              <th>Source IP</th>
              <th>User</th>
              <th>Email</th>
            </tr>
          </thead>
          <tbody>
            {filteredParsed.length === 0 ? (
              <tr>
                <td colSpan={9} style={{ textAlign: 'center', padding: '30px', color: 'var(--text-secondary, #aaa)' }}>
                  No events match your filter.
                </td>
              </tr>
            ) : filteredParsed.slice(0, visibleCount).map((p, i) => {
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
                    <td><span className="source-chip">{p.from}</span></td>
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
                    <td className="mono">{p.email}</td>
                  </tr>
                  {isOpen && (
                    <tr className="raw-row">
                      <td colSpan={9} style={{ padding: 0 }}>
                        <HumanReadableLog log={p.raw} />
                      </td>
                    </tr>
                  )}
                </Fragment>
              );
            })}
          </tbody>
        </table>
      </div>

      {/* Load More Controls */}
      {filteredParsed.length > visibleCount && (
        <div className="pagination-controls" style={{ display: 'flex', justifyContent: 'center', marginTop: '15px', paddingBottom: '15px' }}>
          <button 
            onClick={() => setVisibleCount(c => c + 50)}
            style={{ padding: '8px 24px', background: 'var(--bg-tertiary, #2d2d2d)', border: '1px solid var(--border, #444)', color: 'var(--text-primary, #fff)', borderRadius: '4px', cursor: 'pointer' }}
          >
            Load Next 50 Events
          </button>
        </div>
      )}
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

function HumanReadableLog({ log }) {
  const sections = [];
  const rootPrimitives = {};

  if (!log || typeof log !== 'object') {
    return <div className="human-readable-log"><pre>{String(log)}</pre></div>;
  }

  Object.entries(log).forEach(([key, value]) => {
    if (typeof value === 'object' && value !== null && !Array.isArray(value)) {
      sections.push({ name: key, data: value });
    } else {
      rootPrimitives[key] = value;
    }
  });

  if (Object.keys(rootPrimitives).length > 0) {
    sections.unshift({ name: 'General', data: rootPrimitives });
  }

  return (
    <div className="human-readable-log">
      {sections.map((section, idx) => (
        <div className="hr-section" key={idx}>
          <div className="hr-section-title">{section.name.replace(/_/g, ' ')}</div>
          <div className="hr-grid">
            {Object.entries(section.data).map(([k, v]) => (
              <div className="hr-item" key={k}>
                <span className="hr-key">{k.replace(/_/g, ' ')}</span>
                <span className="hr-value">
                  {typeof v === 'object' ? JSON.stringify(v) : String(v)}
                </span>
              </div>
            ))}
          </div>
        </div>
      ))}
    </div>
  );
}