import { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import './ChatMessage.css';

// Custom Markdown Tokenizer
function parseToTokens(text) {
  const tokens = [];
  const regex = /(\*\*.*?\*\*|\*.*?\*|\n)/g;
  let lastIndex = 0;
  let match;
  while ((match = regex.exec(text)) !== null) {
    if (match.index > lastIndex) {
      tokens.push({ type: 'text', value: text.slice(lastIndex, match.index) });
    }
    const m = match[0];
    if (m === '\n') {
      tokens.push({ type: 'newline', value: '\n' });
    } else if (m.startsWith('**')) {
      tokens.push({ type: 'bold', value: m.slice(2, -2) });
    } else if (m.startsWith('*')) {
      tokens.push({ type: 'italic', value: m.slice(1, -1) });
    }
    lastIndex = regex.lastIndex;
  }
  if (lastIndex < text.length) {
    tokens.push({ type: 'text', value: text.slice(lastIndex) });
  }
  return tokens;
}

function MarkdownRenderer({ tokens }) {
  return (
    <>
      {tokens.map((t, i) => {
        if (t.type === 'newline') return <br key={i} />;
        if (t.type === 'bold') return <strong key={i}>{t.value}</strong>;
        if (t.type === 'italic') return <em key={i}>{t.value}</em>;
        return <span key={i}>{t.value}</span>;
      })}
    </>
  );
}

function Typewriter({ text, speed = 8 }) {
  const [revealed, setRevealed] = useState(0);
  const tokens = parseToTokens(text);
  const totalLength = tokens.reduce((acc, t) => acc + t.value.length, 0);

  useEffect(() => {
    if (revealed < totalLength) {
      const timer = setTimeout(() => {
        setRevealed(r => r + 2);
      }, speed);
      return () => clearTimeout(timer);
    }
  }, [revealed, totalLength, speed]);

  if (revealed >= totalLength) {
    return <MarkdownRenderer tokens={tokens} />;
  }

  let charsLeft = revealed;
  const slicedTokens = [];
  for (const token of tokens) {
    if (charsLeft <= 0) break;
    if (charsLeft >= token.value.length) {
      slicedTokens.push(token);
      charsLeft -= token.value.length;
    } else {
      slicedTokens.push({ ...token, value: token.value.slice(0, charsLeft) });
      charsLeft = 0;
    }
  }

  return (
    <>
      <MarkdownRenderer tokens={slicedTokens} />
      <span className="typewriter-cursor">▋</span>
    </>
  );
}

export default function ChatMessage({ message }) {
  const isUser = message.role === 'user';

  return (
    <motion.div
      className={`chat-message-row ${isUser ? 'row-user' : 'row-bot'}`}
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.25, ease: [0.16, 1, 0.3, 1] }}
    >
      <div className="chat-message-container">
        <div className={`chat-content ${isUser ? 'content-user' : 'content-bot'}`}>
          {!isUser && <span className="assistant-label">SOC Assistant</span>}
          <div className={isUser ? 'message-bubble' : 'message-text'}>
            {isUser ? (
              message.text
            ) : message.isNew ? (
              <Typewriter text={message.text || ''} />
            ) : (
              <MarkdownRenderer tokens={parseToTokens(message.text || '')} />
            )}
          </div>
        </div>
      </div>
    </motion.div>
  );
}

export function TypingDots() {
  const phases = [
    '🔍 Querying SIEM database…',
    '🧠 Analyzing threat patterns…',
    '🛡️ Correlating security events…',
    '📊 Generating threat report…',
  ];

  const [phaseIndex, setPhaseIndex] = useState(0);

  useEffect(() => {
    const interval = setInterval(() => {
      setPhaseIndex((prev) => (prev + 1) % phases.length);
    }, 2500);
    return () => clearInterval(interval);
  }, []);

  return (
    <motion.div
      className="chat-message-row row-bot"
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      exit={{ opacity: 0 }}
    >
      <div className="chat-message-container">
        <div className="chat-content content-bot">
          <span className="assistant-label">SOC Assistant</span>
          <div className="typing-status">
            <motion.span
              key={phaseIndex}
              className="typing-status-text"
              initial={{ opacity: 0, y: 6 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -6 }}
              transition={{ duration: 0.3 }}
            >
              {phases[phaseIndex]}
            </motion.span>
            <span className="typing-spinner" />
          </div>
        </div>
      </div>
    </motion.div>
  );
}