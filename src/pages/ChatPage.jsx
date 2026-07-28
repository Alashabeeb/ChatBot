import { useState, useRef, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Send, Menu, Shield, LogOut, X, FileText, ChevronDown, Square } from 'lucide-react';
import { useTheme } from '../context/ThemeContext';
import ChatMessage, { TypingDots } from '../components/ChatMessage';
import DataCard from '../components/DataCard';
import ChartCard from '../components/ChartCard';
import Sidebar from '../components/Sidebar';
import LogDetailsModal from '../components/LogDetailsModal';
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

// Truncated summary with "more" / "less" toggle
function TruncatedSummary({ text, wordLimit = 20 }) {
  const [expanded, setExpanded] = useState(false);
  if (!text) return null;
  const words = text.split(/\s+/);
  const isTruncated = words.length > wordLimit;
  const displayText = !expanded && isTruncated ? words.slice(0, wordLimit).join(' ') + '…' : text;
  return (
    <p className="log-modal-subtitle">
      {displayText}
      {isTruncated && (
        <button className="summary-toggle-btn" onClick={() => setExpanded(!expanded)}>
          {expanded ? 'show less' : 'more'}
        </button>
      )}
    </p>
  );
}

export default function ChatPage({ onLogout }) {
  const { theme, toggleTheme } = useTheme();
  const [messages, setMessages] = useState([
    {
      role: 'assistant',
      type: 'text',
      text: 'Welcome to SOC ChatBot. I am connected to the manager. Ask me about agent status, recent alerts, or run /stats for trends.',
      timestamp: new Date().toISOString()
    },
  ]);
  const [input, setInput] = useState('');
  const [isTyping, setIsTyping] = useState(false);
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [selectedSources, setSelectedSources] = useState(['wazuh']);
  const [modalData, setModalData] = useState(null);
  const [isAgentDropdownOpen, setIsAgentDropdownOpen] = useState(false);
  const [lastUserPrompt, setLastUserPrompt] = useState('');
  const scrollRef = useRef(null);
  const textareaRef = useRef(null);
  const abortControllerRef = useRef(null);

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

  async function getBackendReply(text, signal) {
    try {
      // Point to our new Node.js Proxy Server (Port changed to 3002 to avoid conflicts)
      const API_URL = window.location.hostname === 'localhost' 
        ? 'http://localhost:3002/api/chat' 
        : `http://${window.location.hostname}:3002/api/chat`;

      // Build conversation history for context (last 10 messages)
      const history = messages
        .filter(m => m.type === 'text' || m.type === 'agent_response')
        .slice(-10)
        .map(m => ({
          role: m.role || 'assistant',
          content: m.text || m.summary || ''
        }))
        .filter(m => m.content);

      const response = await fetch(API_URL, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ text, sources: selectedSources, history }),
        signal
      });
      
      const data = await response.json();
      
      if (!response.ok) {
        // If the backend sent a graceful 500 error, return it so the chat UI shows it
        if (data.type === 'text') return data;
        throw new Error('Network error or server is down');
      }
      
      return data;
    } catch (error) {
      if (error.name === 'AbortError') {
        return {
          type: 'text',
          text: '⏹️ Prompt response generation was cancelled.'
        };
      }
      console.error("Backend Error:", error);
      return {
        type: 'text',
        text: `⚠️ Connection Error: ${error.message}`
      };
    }
  }

  async function handleSend(overrideText) {
    const text = (overrideText ?? input).trim();
    if (!text || isTyping) return;

    const controller = new AbortController();
    abortControllerRef.current = controller;

    setMessages((prev) => [...prev, { role: 'user', type: 'text', text }]);
    setInput('');
    setIsTyping(true);
    setLastUserPrompt(text);

    const reply = await getBackendReply(text, controller.signal);

    setIsTyping(false);
    abortControllerRef.current = null;
    setMessages((prev) => [...prev, { role: 'assistant', ...reply }]);
  }

  function handleCancel() {
    if (abortControllerRef.current) {
      abortControllerRef.current.abort();
      abortControllerRef.current = null;
    }
    setIsTyping(false);
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
              <h1>SOC ChatBot</h1>
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
          lastUserPrompt={lastUserPrompt}
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
                {m.type === 'agent_response' && (
                  <div className="agent-response-card">
                    <ChatMessage message={{ role: 'assistant', text: m.summary }} />
                    <div className="agent-response-actions">
                      <button 
                        className="view-logs-btn"
                        onClick={() => setModalData({ logs: m.raw_logs, source: m.source, summary: m.summary })}
                      >
                        <FileText size={14} />
                        View Full Details
                      </button>
                    </div>
                  </div>
                )}
              </div>
            ))}
            
            <AnimatePresence>
              {isTyping && <TypingDots />}
            </AnimatePresence>
          </div>

          {/* Composer */}
          <div className="chat-composer-container">
            <div className="composer-wrapper">
              
              {/* Claude-style internal agent dropdown */}
              <div className="composer-toolbar">
                <div className="agent-dropdown-container">
                  <button 
                    className="agent-dropdown-btn"
                    onClick={() => setIsAgentDropdownOpen(!isAgentDropdownOpen)}
                  >
                    <span>{selectedSources.length > 0 ? selectedSources.map(s => s.charAt(0).toUpperCase() + s.slice(1)).join(', ') : 'Select Source'}</span>
                    <ChevronDown size={14} />
                  </button>

                  <AnimatePresence>
                    {isAgentDropdownOpen && (
                      <motion.div 
                        className="agent-dropdown-menu"
                        initial={{ opacity: 0, y: 5 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: 5 }}
                      >
                         <label className="dropdown-item">
                           <input type="checkbox" checked={selectedSources.includes('wazuh')} onChange={() => setSelectedSources(p => p.includes('wazuh') ? p.filter(s => s !== 'wazuh') : [...p, 'wazuh'])} />
                           Wazuh (SIEM)
                         </label>
                         <label className="dropdown-item">
                           <input type="checkbox" checked={selectedSources.includes('hisec')} onChange={() => setSelectedSources(p => p.includes('hisec') ? p.filter(s => s !== 'hisec') : [...p, 'hisec'])} />
                           HiSec (Threat)
                         </label>
                         <label className="dropdown-item">
                           <input type="checkbox" checked={selectedSources.includes('honeypot')} onChange={() => setSelectedSources(p => p.includes('honeypot') ? p.filter(s => s !== 'honeypot') : [...p, 'honeypot'])} />
                           Honeypot
                         </label>
                      </motion.div>
                    )}
                  </AnimatePresence>
                </div>
              </div>

              <div className="composer-inner">
                <textarea
                  ref={textareaRef}
                  rows={1}
                  value={input}
                  onChange={(e) => setInput(e.target.value)}
                  onKeyDown={handleKeyDown}
                  placeholder="Ask SOC Security Assistant..."
                  className="composer-textarea"
                />
                {isTyping ? (
                  <button
                    onClick={handleCancel}
                    className="send-btn cancel-btn"
                    aria-label="Cancel prompt generation"
                    title="Cancel generation"
                  >
                    <Square size={14} fill="currentColor" />
                  </button>
                ) : (
                  <button
                    onClick={() => handleSend()}
                    className="send-btn"
                    disabled={!input.trim()}
                    aria-label="Send message"
                  >
                    <Send size={16} />
                  </button>
                )}
              </div>
            </div>
            <div className="composer-footer">
              SOC AI can make mistakes. Please verify critical security alerts.
            </div>
          </div>
        </main>
      </div>

      {/* Full-Screen Logs Modal */}
      <AnimatePresence>
        {modalData && (
          <motion.div 
            className="log-modal-overlay"
            initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
          >
            <div className="log-modal-content">
              <div className="log-modal-header">
                <div>
                  <h2>Event Details</h2>
                  <TruncatedSummary text={modalData.summary} wordLimit={20} />
                </div>
                <button className="icon-btn" onClick={() => setModalData(null)}>
                  <X size={20} />
                </button>
              </div>
              <div className="log-modal-body">
                <LogDetailsModal logs={modalData.logs} source={modalData.source} />
              </div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}