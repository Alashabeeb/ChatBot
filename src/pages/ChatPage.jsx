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
    await new Promise((res) => setTimeout(res, 800));

    if (/stats/i.test(text) || /chart/i.test(text) || /trend/i.test(text)) {
      return { type: 'chart', data: mockChartData };
    }
    if (/alert/i.test(text)) {
      return {
        type: 'data_card',
        source: 'wazuh-alerts-index',
        rows: [
          { severity: 'high', label: 'Multiple authentication failures', meta: 'web-srv-02 · 2m ago', action: 'Block IP' },
          { severity: 'mid', label: 'File integrity change detected', meta: 'db-srv-01 · 14m ago', action: 'Diff' },
          { severity: 'low', label: 'New agent connected', meta: 'app-srv-04 · 41m ago' },
        ],
        footer: '3 of 128 alerts shown · last 24h',
      };
    }
    if (/agent/i.test(text)) {
      return {
        type: 'data_card',
        source: 'wazuh-manager /agents',
        rows: [
          { severity: 'high', label: 'app-srv-04 disconnected', meta: 'last seen 3h ago', action: 'Restart' },
          { severity: 'ok', label: '11 agents active', meta: 'healthy' },
        ],
        footer: 'agent status snapshot',
      };
    }
    if (/vulnerab/i.test(text)) {
      return {
        type: 'data_card',
        source: 'wazuh-manager /vulnerability',
        rows: [
          { severity: 'high', label: 'CVE-2024-3094 — xz-utils', meta: 'db-srv-01', action: 'Patch' },
          { severity: 'mid', label: 'CVE-2023-4911 — glibc', meta: 'web-srv-02', action: 'Patch' },
        ],
        footer: '2 critical/high findings',
      };
    }
    return {
      type: 'text',
      text: "I can pull data from Wazuh. Try asking about alerts, agents, vulnerabilities, or type '/stats' for charts.",
    };
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
