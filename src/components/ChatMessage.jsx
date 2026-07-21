import { motion } from 'framer-motion';
import { useTheme } from '../context/ThemeContext';
import './ChatMessage.css';

export default function ChatMessage({ message, isLast }) {
  const isUser = message.role === 'user';
  
  return (
    <motion.div
      className={`chat-message-wrapper ${isUser ? 'is-user' : 'is-bot'}`}
      initial={{ opacity: 0, y: 15, scale: 0.95 }}
      animate={{ opacity: 1, y: 0, scale: 1 }}
      transition={{ duration: 0.4, type: 'spring', bounce: 0.3 }}
    >
      <div className={`chat-bubble ${isUser ? 'bubble-user' : 'bubble-bot'}`}>
        {message.text}
      </div>
    </motion.div>
  );
}

export function TypingDots() {
  return (
    <motion.div
      className="chat-message-wrapper is-bot"
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      exit={{ opacity: 0, y: -10 }}
    >
      <div className="chat-bubble bubble-bot typing-bubble">
        {[0, 1, 2].map((i) => (
          <motion.span
            key={i}
            className="typing-dot"
            animate={{
              y: [0, -4, 0],
              opacity: [0.4, 1, 0.4]
            }}
            transition={{
              duration: 1,
              repeat: Infinity,
              delay: i * 0.2,
              ease: "easeInOut"
            }}
          />
        ))}
      </div>
    </motion.div>
  );
}
