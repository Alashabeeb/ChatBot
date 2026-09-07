import { useState, useRef, useEffect, useCallback } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Send, Menu, Shield, LogOut, X, FileText, ChevronDown, Square, Users, User, Settings } from 'lucide-react';
import { useTheme } from '../context/ThemeContext';
import ChatMessage, { TypingDots } from '../components/ChatMessage';
import DataCard from '../components/DataCard';
import ChartCard from '../components/ChartCard';
import Sidebar from '../components/Sidebar';
import LogDetailsModal from '../components/LogDetailsModal';
import AdminUsersModal from '../components/AdminUsersModal';
import ManageQueriesModal from '../components/ManageQueriesModal';
import './ChatPage.css';

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

const INITIAL_MESSAGES = [
  {
    role: 'assistant',
    type: 'text',
    text: 'Welcome to SOC ChatBot. I am connected to the Wazuh SIEM manager. Ask me about agent status, recent alerts, authentication failures, or CVE vulnerabilities.',
    timestamp: new Date().toISOString()
  }
];

export default function ChatPage({ currentUser, onLogout }) {
  const { theme, toggleTheme } = useTheme();
  const [sessions, setSessions] = useState([]);
  const [activeSessionId, setActiveSessionId] = useState(null);
  const [messages, setMessages] = useState(INITIAL_MESSAGES);
  const [input, setInput] = useState('');
  const [isTyping, setIsTyping] = useState(false);
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [selectedSources, setSelectedSources] = useState(['wazuh']);
  const [modalData, setModalData] = useState(null);
  const [isAgentDropdownOpen, setIsAgentDropdownOpen] = useState(false);
  const [isAdminModalOpen, setIsAdminModalOpen] = useState(false);
  const [isSettingsOpen, setIsSettingsOpen] = useState(false);
  
  // Custom Quick Queries
  const [quickQueries, setQuickQueries] = useState([]);
  const [isQueriesModalOpen, setIsQueriesModalOpen] = useState(false);
  
  const scrollRef = useRef(null);
  const textareaRef = useRef(null);
  const abortControllerRef = useRef(null);

  const getAuthHeaders = () => {
    const token = localStorage.getItem('soc_auth_token');
    return {
      'Content-Type': 'application/json',
      ...(token ? { 'Authorization': `Bearer ${token}` } : {})
    };
  };

  // Fetch user sessions from SQLite Database on mount
  const loadSessionsFromDB = useCallback(async () => {
    try {
      const API_URL = window.location.hostname === 'localhost'
        ? 'http://localhost:3002/api/sessions'
        : `http://${window.location.hostname}:3002/api/sessions`;

      const res = await fetch(API_URL, { headers: getAuthHeaders() });
      if (res.status === 401 || res.status === 403) {
        onLogout();
        return;
      }
      const data = await res.json();
      if (data.success && Array.isArray(data.sessions)) {
        setSessions(data.sessions);
      }
    } catch (error) {
      console.error('Failed to load sessions:', error);
    }
  }, [onLogout]);

  // Fetch user-specific quick queries
  const fetchQueries = useCallback(async () => {
    try {
      const API_URL = window.location.hostname === 'localhost'
        ? 'http://localhost:3002/api/queries'
        : `http://${window.location.hostname}:3002/api/queries`;
      const res = await fetch(API_URL, { headers: getAuthHeaders() });
      const data = await res.json();
      if (data.success) {
        setQuickQueries(data.queries);
      }
    } catch (err) {
      console.error('Failed to fetch quick queries:', err);
    }
  }, []);

  useEffect(() => {
    loadSessionsFromDB();
    fetchQueries();
  }, [loadSessionsFromDB, fetchQueries]);

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
      const API_URL = window.location.hostname === 'localhost' 
        ? 'http://localhost:3002/api/chat' 
        : `http://${window.location.hostname}:3002/api/chat`;

      const history = messages
        .filter(m => m.type === 'text' || m.type === 'agent_response')
        .map(m => ({
          role: m.role || 'assistant',
          content: m.text || m.summary || ''
        }))
        .filter(m => m.content);

      const response = await fetch(API_URL, {
        method: 'POST',
        headers: getAuthHeaders(),
        body: JSON.stringify({ text, sources: selectedSources, history }),
        signal
      });
      
      if (response.status === 401 || response.status === 403) {
        onLogout();
        return { type: 'text', text: '⚠️ Session expired. Please log in again.' };
      }

      const data = await response.json();
      
      if (!response.ok) {
        if (data.type === 'text') return data;
        throw new Error(data.error || 'Network error or server is down');
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

  async function saveMessageToDB(sessionId, msg) {
    try {
      const API_URL = window.location.hostname === 'localhost'
        ? `http://localhost:3002/api/sessions/${sessionId}/messages`
        : `http://${window.location.hostname}:3002/api/sessions/${sessionId}/messages`;

      await fetch(API_URL, {
        method: 'POST',
        headers: getAuthHeaders(),
        body: JSON.stringify({
          id: msg.id,
          role: msg.role,
          type: msg.type || 'text',
          text: msg.text || '',
          summary: msg.summary || '',
          rawLogs: msg.raw_logs || null,
          totalHits: msg.total_hits || 0,
          isNew: msg.isNew ? 1 : 0
        })
      });
    } catch (e) {
      console.warn('Failed to persist message to DB:', e);
    }
  }

  async function handleSend(overrideText) {
    const text = (overrideText ?? input).trim();
    if (!text || isTyping) return;

    const controller = new AbortController();
    abortControllerRef.current = controller;

    const userMsg = {
      id: 'msg_u_' + Date.now(),
      role: 'user',
      type: 'text',
      text,
      timestamp: new Date().toISOString()
    };
    const newMessages = [...messages, userMsg];
    setMessages(newMessages);
    setInput('');
    setIsTyping(true);

    // Handle Session Creation / Update
    let currentSessionId = activeSessionId;

    if (!currentSessionId) {
      currentSessionId = 'sess_' + Date.now();
      let title = text;
      title = title.charAt(0).toUpperCase() + title.slice(1);
      if (title.length > 40) title = title.slice(0, 37) + '...';

      setActiveSessionId(currentSessionId);
      
      // Save session in DB
      try {
        const API_URL = window.location.hostname === 'localhost'
          ? 'http://localhost:3002/api/sessions'
          : `http://${window.location.hostname}:3002/api/sessions`;

        const res = await fetch(API_URL, {
          method: 'POST',
          headers: getAuthHeaders(),
          body: JSON.stringify({ id: currentSessionId, title })
        });
        const d = await res.json();
        if (d.success && d.session) {
          setSessions(prev => [d.session, ...prev.filter(s => s.id !== currentSessionId)]);
        }
      } catch (e) {
        console.warn('Session create failed:', e);
      }
    }

    // Persist user message to DB
    saveMessageToDB(currentSessionId, userMsg);

    const reply = await getBackendReply(text, controller.signal);

    setIsTyping(false);
    abortControllerRef.current = null;
    
    // Add isNew flag for typewriter animation
    const assistantMsg = {
      id: 'msg_a_' + Date.now(),
      role: 'assistant',
      isNew: true,
      ...reply,
      timestamp: new Date().toISOString()
    };
    
    const finalMessages = [...newMessages, assistantMsg];
    setMessages(finalMessages);

    // Persist bot response to DB
    saveMessageToDB(currentSessionId, assistantMsg);
    loadSessionsFromDB();
  }

  function handleNewChat() {
    if (isTyping) handleCancel();
    setActiveSessionId(null);
    setMessages(INITIAL_MESSAGES);
    setInput('');
  }

  async function handleSelectSession(sessionId) {
    if (isTyping) handleCancel();
    setActiveSessionId(sessionId);

    try {
      const API_URL = window.location.hostname === 'localhost'
        ? `http://localhost:3002/api/sessions/${sessionId}/messages`
        : `http://${window.location.hostname}:3002/api/sessions/${sessionId}/messages`;

      const res = await fetch(API_URL, { headers: getAuthHeaders() });
      const data = await res.json();
      if (data.success && Array.isArray(data.messages) && data.messages.length > 0) {
        setMessages(data.messages.map(m => ({ ...m, isNew: false })));
      } else {
        setMessages(INITIAL_MESSAGES);
      }
    } catch (e) {
      console.warn('Error loading session messages:', e);
    }
  }

  async function handleClearSessions() {
    if (isTyping) handleCancel();
    try {
      const API_URL = window.location.hostname === 'localhost'
        ? 'http://localhost:3002/api/sessions'
        : `http://${window.location.hostname}:3002/api/sessions`;

      await fetch(API_URL, {
        method: 'DELETE',
        headers: getAuthHeaders()
      });
    } catch (e) {
      console.warn('Error clearing sessions:', e);
    }
    setSessions([]);
    setActiveSessionId(null);
    setMessages(INITIAL_MESSAGES);
  }

  async function handleDeleteSession(sessionId) {
    if (isTyping && sessionId === activeSessionId) handleCancel();
    
    try {
      const API_URL = window.location.hostname === 'localhost'
        ? `http://localhost:3002/api/sessions/${sessionId}`
        : `http://${window.location.hostname}:3002/api/sessions/${sessionId}`;

      await fetch(API_URL, {
        method: 'DELETE',
        headers: getAuthHeaders()
      });
    } catch (e) {
      console.warn('Error deleting session:', e);
    }

    setSessions(prev => prev.filter(s => s.id !== sessionId));

    if (activeSessionId === sessionId) {
      setActiveSessionId(null);
      setMessages(INITIAL_MESSAGES);
      setInput('');
    }
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
          {/* User Profile Chip */}
          <div className="user-profile-badge">
            <div className="user-avatar-tiny">
              {currentUser?.role === 'admin' ? <Shield size={13} /> : <User size={13} />}
            </div>
            <span className="user-name-label">{currentUser?.username || 'User'}</span>
          </div>

          {/* Settings Dropdown */}
          <div className="settings-dropdown-wrapper">
            <button
              className="icon-btn settings-trigger-btn"
              onClick={() => setIsSettingsOpen(!isSettingsOpen)}
              aria-label="Settings"
              title="Settings"
            >
              <Settings size={18} className={isSettingsOpen ? 'spin-gear' : ''} />
            </button>

            <AnimatePresence>
              {isSettingsOpen && (
                <>
                  <div className="settings-backdrop" onClick={() => setIsSettingsOpen(false)} />
                  <motion.div
                    className="settings-dropdown-menu"
                    initial={{ opacity: 0, y: -8, scale: 0.95 }}
                    animate={{ opacity: 1, y: 0, scale: 1 }}
                    exit={{ opacity: 0, y: -8, scale: 0.95 }}
                    transition={{ duration: 0.15 }}
                  >
                    {currentUser?.role === 'admin' && (
                      <button
                        className="settings-menu-item"
                        onClick={() => { setIsAdminModalOpen(true); setIsSettingsOpen(false); }}
                      >
                        <Users size={15} />
                        <span>User Management</span>
                      </button>
                    )}
                    <button
                      className="settings-menu-item"
                      onClick={() => { toggleTheme(); setIsSettingsOpen(false); }}
                    >
                      <span style={{ fontSize: '15px' }}>{theme === 'dark' ? '☀️' : '🌙'}</span>
                      <span>{theme === 'dark' ? 'Light Mode' : 'Dark Mode'}</span>
                    </button>
                    <div className="settings-menu-divider" />
                    <button
                      className="settings-menu-item settings-menu-danger"
                      onClick={() => { setIsSettingsOpen(false); onLogout(); }}
                    >
                      <LogOut size={15} />
                      <span>Sign Out</span>
                    </button>
                  </motion.div>
                </>
              )}
            </AnimatePresence>
          </div>
        </div>
      </header>

      <div className="chat-body">
        <Sidebar 
          isOpen={sidebarOpen} 
          onClose={() => setSidebarOpen(false)} 
          onPromptClick={handleSend}
          sessions={sessions}
          activeSessionId={activeSessionId}
          onSelectSession={handleSelectSession}
          onNewChat={handleNewChat}
          onClearSessions={handleClearSessions}
          onDeleteSession={handleDeleteSession}
          currentUser={currentUser}
          onOpenAdminModal={() => setIsAdminModalOpen(true)}
          quickQueries={quickQueries}
          onManageQueries={() => setIsQueriesModalOpen(true)}
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
              <div key={m.id || i}>
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
                    <ChatMessage message={{ role: 'assistant', text: m.summary, isNew: m.isNew }} />
                    <div className="agent-response-actions">
                      <button 
                        className="view-logs-btn"
                        onClick={async () => {
                          let finalLogs = m.raw_logs;
                          if (!finalLogs || finalLogs.length === 0) {
                            try {
                              const API_URL = window.location.hostname === 'localhost'
                                ? `http://localhost:3002/api/sessions/messages/${m.id}/logs`
                                : `http://${window.location.hostname}:3002/api/sessions/messages/${m.id}/logs`;
                              const res = await fetch(API_URL, { headers: getAuthHeaders() });
                              const data = await res.json();
                              if (data.success) {
                                finalLogs = data.logs;
                                // Cache it locally
                                m.raw_logs = finalLogs;
                              }
                            } catch(e) {
                              console.error('Failed to fetch raw logs', e);
                            }
                          }
                          setModalData({ logs: finalLogs || [], source: m.source, summary: m.summary, totalHits: m.total_hits });
                        }}
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
              
              {/* Internal agent dropdown */}
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
                <LogDetailsModal logs={modalData.logs} source={modalData.source} totalHits={modalData.totalHits} />
              </div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>

      {/* Admin User Management Modal (Only openable by Admin) */}
      <AnimatePresence>
        {isAdminModalOpen && (
          <AdminUsersModal
            isOpen={isAdminModalOpen}
            onClose={() => setIsAdminModalOpen(false)}
            currentUser={currentUser}
          />
        )}
      </AnimatePresence>

      {/* Manage Custom Quick Queries Modal */}
      <AnimatePresence>
        {isQueriesModalOpen && (
          <ManageQueriesModal
            isOpen={isQueriesModalOpen}
            onClose={() => setIsQueriesModalOpen(false)}
            queries={quickQueries}
            fetchQueries={fetchQueries}
          />
        )}
      </AnimatePresence>
    </div>
  );
}