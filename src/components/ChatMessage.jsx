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
          {!isUser && <span className="assistant-label">GBB Assistant</span>}
          <div className={isUser ? 'message-bubble' : 'message-text'}>{message.text}</div>
        </div>
      </div>
    </motion.div>
  );
}

export function TypingDots() {
  return (
    <motion.div
      className="chat-message-row row-bot"
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      exit={{ opacity: 0 }}
    >
      <div className="chat-message-container">
        <div className="chat-content content-bot typing-container">
          {[0, 1, 2].map((i) => (
            <motion.span
              key={i}
              className="typing-dot"
              animate={{ y: [0, -3, 0], opacity: [0.3, 1, 0.3] }}
              transition={{ duration: 0.8, repeat: Infinity, delay: i * 0.15 }}
            />
          ))}
        </div>
      </div>
    </motion.div>
  );
}