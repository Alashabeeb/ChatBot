import { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import './ChatMessage.css';

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
          <div className={isUser ? 'message-bubble' : 'message-text'}>{message.text}</div>
        </div>
      </div>
    </motion.div>
  );
}

export function TypingDots() {
  const phases = [
    '🔍 Querying SIEM database…',
    '📡 Fetching threat intelligence…',
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