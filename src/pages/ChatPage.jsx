import { useState, useRef, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Send, Menu, Shield, LogOut } from 'lucide-react';
import { useTheme } from '../context/ThemeContext';
import ChatMessage, { TypingDots } from '../components/ChatMessage';
import DataCard from '../components/DataCard';
import ChartCard from '../components/ChartCard';
import Sidebar from '../components/Sidebar';
import './ChatPage.css';

// Synthetic Chart Data
const mockChartData = [
  { time: '10:00', alerts: 4 },
  { time: '11:00', alerts: 7 },
  { time: '12:00', alerts: 2 },
  { time: '13:00', alerts: 12 },
  { time: '14:00', alerts: 5 },
  { time: '15:00', alerts: 8 },
];

export default function ChatPage({ onLogout }) {
  const { theme, toggleTheme } = useTheme();
  const [messages, setMessages] = useState([
    {
      role: 'assistant',
      type: 'text',
      text: 'Welcome to GBB ChatBot. I am connected to the manager. Ask me about agent status, recent alerts, or run /stats for trends.',
      timestamp: new Date().toISOString()
    },
  ]);
  const [input, setInput] = useState('');
  const [isTyping, setIsTyping] = useState(false);
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const scrollRef = useRef(null);
  const textareaRef = useRef(null);

  // Auto-scroll
  useEffect(() => {
    if (scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [messages, isTyping]);

  // Auto-resize textarea
  useEffect(() => {
    if (textareaRef.current) {
      textareaRef.current.style.height = 'auto';
      textareaRef.current.style.height = Math.min(textareaRef.current.scrollHeight, 140) + 'px';
    }
  }, [input]);

  // Simulate Live Mode pushing random alerts
  useEffect(() => {
    const interval = setInterval(() => {
      if (Math.random() > 0.85) {
        setMessages((prev) => [
          ...prev,
          {
            role: 'assistant',
            type: 'data_card',
            source: 'wazuh-live-feed',
            rows: [
              { severity: 'low', label: 'Successful SSH login', meta: 'db-srv-01 · Just now' }
            ],
            footer: 'Live event triggered'
          }
        ]);
      }
    }, 15000);
    return () => clearInterval(interval);
  }, []);

  async function getBackendReply(text) {
    try {
      // Point to our new Node.js Proxy Server
      const API_URL = window.location.hostname === 'localhost' 
        ? 'http://localhost:3001/api/chat' 
        : `http://${window.location.hostname}:3001/api/chat`;

      const response = await fetch(API_URL, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ text })
      });
      
      if (!response.ok) {
        throw new Error('Network error or server is down');
      }
      
      return await response.json();
    } catch (error) {
      console.error("Backend Error:", error);
      return {
        type: 'text',
        text: '⚠️ Cannot connect to the Wazuh Proxy Backend. Make sure the Node.js server is running on port 3001.'
      };
    }
  }

  async function handleSend(overrideText) {
    const text = (overrideText ?? input).trim();
    if (!text) return;

    setMessages((prev) => [...prev, { role: 'user', type: 'text', text }]);
    setInput('');
    setIsTyping(true);

    const reply = await getBackendReply(text);

    setIsTyping(false);
    setMessages((prev) => [...prev, { role: 'assistant', ...reply }]);
  }

  function handleKeyDown(e) {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      handleSend();
    }
  }

  return (
    <div className="chat-layout">
      {/* Header */}
      <header className="chat-header glass">
        <div className="header-left">
          <button 
            className="menu-btn"
            onClick={() => setSidebarOpen(o => !o)}
            aria-label="Toggle sidebar"
          >
            <Menu size={20} />
          </button>
          <div className="header-brand">
            <div className="header-logo"><Shield size={16} /></div>
            <div className="header-titles">
              <h1>GBB ChatBot</h1>
              <span>Security Assistant</span>
            </div>
          </div>
        </div>

        <div className="header-center">
          <div className="status-indicator">
            <span className="status-dot pulsing" />
            Live Monitoring Active
          </div>
        </div>
        
        <div className="header-right">
          <button className="icon-btn" onClick={toggleTheme} aria-label="Toggle theme">
            {theme === 'dark' ? '☀️' : '🌙'}
          </button>
          <button className="icon-btn logout-btn" onClick={onLogout} aria-label="Logout">
            <LogOut size={18} />
          </button>
        </div>
      </header>

      <div className="chat-body">
        <Sidebar 
          isOpen={sidebarOpen} 
          onClose={() => setSidebarOpen(false)} 
          onPromptClick={handleSend}
        />

        {/* Mobile sidebar overlay */}
        <AnimatePresence>
          {sidebarOpen && (
            <motion.div 
              className="sidebar-overlay"
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              onClick={() => setSidebarOpen(false)}
            />
          )}
        </AnimatePresence>

        <main className="chat-main">
          {/* Message List */}
          <div className="chat-messages" ref={scrollRef}>
            {messages.map((m, i) => (
              <div key={i}>
                {m.type === 'text' && (
                  <ChatMessage message={m} isLast={i === messages.length - 1} />
                )}
                {m.type === 'data_card' && (
                  <DataCard source={m.source} rows={m.rows} footer={m.footer} />
                )}
                {m.type === 'chart' && (
                  <ChartCard data={m.data} title="Alert Volume Trends" />
                )}
              </div>
            ))}
            
            <AnimatePresence>
              {isTyping && <TypingDots />}
            </AnimatePresence>
          </div>

          {/* Composer */}
          <div className="chat-composer-container">
            <div className="composer-inner">
              <textarea
                ref={textareaRef}
                rows={1}
                value={input}
                onChange={(e) => setInput(e.target.value)}
                onKeyDown={handleKeyDown}
                placeholder="Ask about agents, alerts, or vulnerabilities…"
                className="composer-textarea"
              />
              <button
                onClick={() => handleSend()}
                className="send-btn"
                disabled={!input.trim() || isTyping}
                aria-label="Send message"
              >
                <Send size={16} />
              </button>
            </div>
            <div className="composer-footer">
              Wazuh Integration · AI responses can make mistakes · Verify critical alerts
            </div>
          </div>
        </main>
      </div>
    </div>
  );
}
