import { useEffect, useRef, useState } from 'react';
import './TerminalFeed.css';

// Scripted lines simulating a live SOC / Wazuh session.
// Each line: the text to type, and a tag that controls its color once complete.
const SCRIPT = [
  { text: '$ wazuh-agent --status --all', tag: 'cmd' },
  { text: '12 agents reporting · 11 active · 1 disconnected', tag: 'info' },
  { text: '$ query siem --rule.group authentication_failures --last 24h', tag: 'cmd' },
  { text: 'scanning wazuh-alerts-* on manager v4.9.0 ...', tag: 'muted' },
  { text: '[OK] 47 events matched · top source 41.203.x.x', tag: 'ok' },
  { text: '$ query siem --rule.group vulnerability-detector', tag: 'cmd' },
  { text: '[WARN] 3 hosts flagged for unpatched CVEs', tag: 'warn' },
  { text: '$ resolve ip 190.03.12.56 --context', tag: 'cmd' },
  { text: 'geo: unknown · reputation: 2 prior brute-force hits', tag: 'muted' },
  { text: '[OK] summary handed to foundation-sec-8b-instruct', tag: 'ok' },
  { text: '$ standing by for the next question_', tag: 'cmd' },
];

const TYPE_MS = 22;
const LINE_PAUSE_MS = 550;
const RESTART_PAUSE_MS = 1800;
const MAX_VISIBLE_LINES = 7;

export default function TerminalFeed() {
  const [lines, setLines] = useState([]);
  const [current, setCurrent] = useState('');
  const indexRef = useRef(0);
  const charRef = useRef(0);

  useEffect(() => {
    let timeout;

    const typeStep = () => {
      const entry = SCRIPT[indexRef.current];
      charRef.current += 1;
      setCurrent(entry.text.slice(0, charRef.current));

      if (charRef.current < entry.text.length) {
        timeout = setTimeout(typeStep, TYPE_MS);
      } else {
        timeout = setTimeout(advanceLine, LINE_PAUSE_MS);
      }
    };

    const advanceLine = () => {
      const entry = SCRIPT[indexRef.current];
      setLines((prev) => [...prev.slice(-(MAX_VISIBLE_LINES - 1)), entry]);
      setCurrent('');
      charRef.current = 0;

      const isLast = indexRef.current === SCRIPT.length - 1;
      if (isLast) {
        timeout = setTimeout(() => {
          setLines([]);
          indexRef.current = 0;
          timeout = setTimeout(typeStep, TYPE_MS);
        }, RESTART_PAUSE_MS);
      } else {
        indexRef.current += 1;
        timeout = setTimeout(typeStep, TYPE_MS);
      }
    };

    timeout = setTimeout(typeStep, TYPE_MS);
    return () => clearTimeout(timeout);
  }, []);

  return (
    <div className="terminal-panel">
      <div className="terminal-titlebar">
        <span className="terminal-dot dot-red" />
        <span className="terminal-dot dot-yellow" />
        <span className="terminal-dot dot-green" />
        <span className="terminal-title">wazuh-agent — live feed</span>
      </div>
      <div className="terminal-body">
        {lines.map((line, i) => (
          <div key={i} className={`terminal-line tag-${line.tag}`}>{line.text}</div>
        ))}
        <div className={`terminal-line tag-${SCRIPT[indexRef.current].tag}`}>
          {current}
          <span className="terminal-cursor" />
        </div>
      </div>
    </div>
  );
}