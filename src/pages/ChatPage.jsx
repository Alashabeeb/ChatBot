import { useState, useRef, useEffect, useCallback } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Send, Menu, Shield, LogOut, X, FileText, Square, Users, User, Settings, Database, RefreshCw } from 'lucide-react';
import { useTheme } from '../context/ThemeContext';
import ChatMessage, { Markdown } from '../components/ChatMessage';
import { labelRawLogs } from '../lib/rawLogs';
import { streamChat, buildHistory, ChatHttpError } from '../lib/chatStream';
import { applySearchEvent, lastSearchRequestId, startSearchMessage, isFollowUpAnswer } from '../lib/searchStream';
import DataCard from '../components/DataCard';
import ChartCard from '../components/ChartCard';
import Sidebar from '../components/Sidebar';
import LogDetailsModal from '../components/LogDetailsModal';
import AdminUsersModal from '../components/AdminUsersModal';
import ManageQueriesModal from '../components/ManageQueriesModal';
import './ChatPage.css';

// The answer's summary in the details modal: rendered as Markdown (F-40), collapsed to a few lines
// until expanded. Collapsing by height, not by cutting words, keeps the Markdown intact.
function CollapsibleSummary({ text }) {
  const [expanded, setExpanded] = useState(false);
  if (!text) return null;
  return (
    <div className="log-modal-subtitle">
      <div className={`summary-md ${expanded ? 'is-expanded' : ''}`}>
        <Markdown text={text} />
      </div>
      <button className="summary-toggle-btn" onClick={() => setExpanded(!expanded)}>
        {expanded ? 'show less' : 'more'}
      </button>
    </div>
  );
}

const INITIAL_MESSAGES = [
  {
    role: 'assistant',
    type: 'text',
    isWelcome: true,
    text: 'Welcome to SOC ChatBot. Ask me anything, from drafting an email to explaining a log line or writing a script.\n\nTurn on **Search Wazuh** to query your live Wazuh and firewall telemetry: agent status, recent alerts, authentication failures, firewall activity or CVE vulnerabilities.',
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
  // 'chat' streams from the model; 'siem' runs the Search Wazuh pipeline. Remembered per browser.
  const [searchWazuh, setSearchWazuh] = useState(() => {
    try { return localStorage.getItem('soc_search_wazuh') === '1'; } catch { return false; }
  });
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [modalData, setModalData] = useState(null);
  const [isAdminModalOpen, setIsAdminModalOpen] = useState(false);
  const [isSettingsOpen, setIsSettingsOpen] = useState(false);
  
  // Custom Quick Queries
  const [quickQueries, setQuickQueries] = useState([]);
  const [isQueriesModalOpen, setIsQueriesModalOpen] = useState(false);
  
  const scrollRef = useRef(null);
  // Follow new output only while the user is at the bottom; scrolling up to read stops following.
  const stickToBottomRef = useRef(true);
  const textareaRef = useRef(null);
  const abortControllerRef = useRef(null);

  const apiUrl = (path) => (window.location.hostname === 'localhost'
    ? `http://localhost:3002${path}`
    : `http://${window.location.hostname}:3002${path}`);

  useEffect(() => {
    try { localStorage.setItem('soc_search_wazuh', searchWazuh ? '1' : '0'); } catch { /* storage unavailable */ }
  }, [searchWazuh]);

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

  // Auto-scroll, only while following the bottom of the conversation
  useEffect(() => {
    if (!scrollRef.current || !stickToBottomRef.current) return;
    // Wait one frame so newly added content has its final height.
    const frame = requestAnimationFrame(() => {
      if (scrollRef.current) scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    });
    return () => cancelAnimationFrame(frame);
  }, [messages, isTyping]);

  function handleMessagesScroll() {
    const el = scrollRef.current;
    if (el) stickToBottomRef.current = el.scrollHeight - el.scrollTop - el.clientHeight < 80;
  }

  // Auto-resize textarea
  useEffect(() => {
    if (textareaRef.current) {
      textareaRef.current.style.height = 'auto';
      textareaRef.current.style.height = Math.min(textareaRef.current.scrollHeight, 200) + 'px';
    }
  }, [input]);

  /**
   * Search Wazuh, streamed (Phase 7): the stage the backend is actually in, then the answer as it grows.
   * Only verified text arrives. followUpOf lets a follow-up question reuse the previous search's evidence.
   */
  async function streamSearchReply(id, text, history, signal, followUpOf) {
    let msg = startSearchMessage(id, text);
    const update = (next) => {
      msg = next;
      setMessages(prev => prev.map(m => (m.id === id ? msg : m)));
    };
    try {
      await streamChat({
        url: apiUrl('/api/chat/search/stream'),
        headers: getAuthHeaders(),
        body: { text, history, follow_up_of: followUpOf },
        signal,
        onEvent: (event) => update(applySearchEvent(msg, event))
      });
      if (msg.isStreaming) update({ ...msg, isStreaming: false, stageLabel: null, errorNotice: 'The search ended without an answer.' });
    } catch (error) {
      if (error.name === 'AbortError') {
        update({ id, role: 'assistant', type: 'text', text: 'Search stopped.', isError: true, isStreaming: false });
      } else if (error instanceof ChatHttpError && (error.status === 401 || error.status === 403)) {
        update({ id, role: 'assistant', type: 'text', text: 'Your session expired. Please log in again.', isError: true, isStreaming: false });
        onLogout();
      } else {
        const message = error instanceof ChatHttpError ? error.message : `Connection error: ${error.message}`;
        update({ id, role: 'assistant', type: 'text', text: message, isError: true, isStreaming: false });
      }
    }
    return msg;
  }

  /**
   * General chat: streams the model's answer into the assistant message `id` as it is generated.
   * Returns the finished message.
   */
  async function streamAssistantReply(id, text, history, signal) {
    let msg = { id, role: 'assistant', type: 'text', text: '', isStreaming: true, question: text, timestamp: new Date().toISOString() };
    const update = (patch) => {
      msg = { ...msg, ...patch };
      setMessages(prev => prev.map(m => (m.id === id ? msg : m)));
    };
    try {
      await streamChat({
        url: apiUrl('/api/chat/stream'),
        headers: getAuthHeaders(),
        body: { text, history },
        signal,
        onEvent: ({ event, data }) => {
          if (event === 'meta') update({ request_id: data.request_id });
          else if (event === 'token') update({ text: msg.text + data.text });
          else if (event === 'error') update({ errorNotice: data.message });
          else if (event === 'done') update({ truncated: data.truncated, suggestSearch: data.suggest_search, modelGenerated: data.model_generated });
        }
      });
      // Nothing generated at all: show the notice as the message itself.
      if (!msg.text && msg.errorNotice) update({ text: msg.errorNotice, errorNotice: undefined, isError: true });
    } catch (error) {
      if (error.name === 'AbortError') {
        update(msg.text ? { stopped: true } : { text: 'Stopped before the model answered.', isError: true });
      } else if (error instanceof ChatHttpError && (error.status === 401 || error.status === 403)) {
        update({ text: 'Your session expired. Please log in again.', isError: true });
        onLogout();
      } else {
        const message = error instanceof ChatHttpError ? error.message : `Connection error: ${error.message}`;
        update(msg.text ? { errorNotice: message } : { text: message, isError: true });
      }
    }
    update({ isStreaming: false });
    return msg;
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
          isNew: msg.isNew ? 1 : 0,
          // Links the saved report to its server-side run record.
          requestId: msg.request_id || null
        })
      });
    } catch (e) {
      console.warn('Failed to persist message to DB:', e);
    }
  }

  async function handleSend(overrideText, { forceSearch = false, fresh = false } = {}) {
    const text = (overrideText ?? input).trim();
    if (!text || isTyping) return;
    const mode = forceSearch || searchWazuh ? 'siem' : 'chat';
    const history = buildHistory(messages);
    // A follow-up can reuse the previous search's evidence; "Search again" (fresh) always searches.
    const followUpOf = mode === 'siem' && !fresh ? lastSearchRequestId(messages) : null;

    const controller = new AbortController();
    abortControllerRef.current = controller;
    stickToBottomRef.current = true;

    const userMsg = {
      id: 'msg_u_' + Date.now(),
      role: 'user',
      type: 'text',
      text,
      timestamp: new Date().toISOString()
    };
    setMessages(prev => [...prev, userMsg]);
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

    let assistantMsg;
    if (mode === 'chat') {
      const id = 'msg_a_' + Date.now();
      setMessages(prev => [...prev, { id, role: 'assistant', type: 'text', text: '', isStreaming: true, question: text }]);
      assistantMsg = await streamAssistantReply(id, text, history, controller.signal);
    } else {
      const id = 'msg_a_' + Date.now();
      setMessages(prev => [...prev, startSearchMessage(id, text)]);
      assistantMsg = await streamSearchReply(id, text, history, controller.signal, followUpOf);
    }

    setIsTyping(false);
    abortControllerRef.current = null;

    // Persist the answer. Error notices are not saved: they would come back as conversation
    // history the model never wrote.
    if (!assistantMsg.isError && (assistantMsg.text || assistantMsg.summary)) {
      saveMessageToDB(currentSessionId, assistantMsg);
    }
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
    // Enter sends, Shift+Enter adds a new line. Ignore Enter while an input method is composing.
    if (e.key === 'Enter' && !e.shiftKey && !e.nativeEvent.isComposing) {
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

        <div className="header-center" />
        
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
          <div className="chat-messages" ref={scrollRef} onScroll={handleMessagesScroll}>
            {messages.map((m, i) => (
              <div key={m.id || i}>
                {m.type === 'text' && (
                  <ChatMessage message={m} onSearchWazuh={(question) => handleSend(question, { forceSearch: true })} />
                )}
                {m.type === 'data_card' && (
                  <DataCard source={m.source} rows={m.rows} footer={m.footer} />
                )}
                {m.type === 'chart' && (
                  <ChartCard data={m.data} title="Alert Volume Trends" />
                )}
                {m.type === 'agent_response' && (
                  <div className="agent-response-card">
                    <ChatMessage
                      message={{ role: 'assistant', text: m.summary, isStreaming: m.isStreaming }}
                      badge={isFollowUpAnswer(m) ? 'From previous search' : 'Searched Wazuh'}
                      status={m.isStreaming ? (m.stageLabel || 'Sending your question') : null}
                    />
                    {!m.isStreaming && (
                    <div className="agent-response-actions">
                      <button 
                        className="view-logs-btn"
                        onClick={async () => {
                          let finalEntries = labelRawLogs(m.raw_logs);
                          if (finalEntries.length === 0) {
                            // OPEN MODAL WITH LOADING STATE
                            setModalData({ isLoading: true, source: m.source, summary: m.summary, totalHits: m.total_hits });
                            
                            try {
                              const API_URL = window.location.hostname === 'localhost'
                                ? `http://localhost:3002/api/sessions/messages/${m.id}/logs`
                                : `http://${window.location.hostname}:3002/api/sessions/messages/${m.id}/logs`;
                              const res = await fetch(API_URL, { headers: getAuthHeaders() });
                              const data = await res.json();
                              if (data.success) {
                                finalEntries = labelRawLogs(data.logs);
                                // Cache it locally
                                m.raw_logs = data.logs;
                              }
                            } catch(e) {
                              console.error('Failed to fetch raw logs', e);
                            }
                          }
                          // UPDATE MODAL WITH ACTUAL LOGS
                          setModalData({ entries: finalEntries, source: m.source, summary: m.summary, totalHits: m.total_hits });
                        }}
                      >
                        <FileText size={14} />
                        View Full Details
                      </button>
                      {m.follow_up_of && m.question && (
                        <button
                          className="view-logs-btn"
                          disabled={isTyping}
                          title="This answer reused the previous search. Run a fresh search for the same question."
                          onClick={() => handleSend(m.question, { forceSearch: true, fresh: true })}
                        >
                          <RefreshCw size={14} />
                          Search again
                        </button>
                      )}
                    </div>
                    )}
                  </div>
                )}
              </div>
            ))}
            
          </div>

          {/* Composer */}
          <div className="chat-composer-container">
            <div className="composer-wrapper">
              <div className="composer-inner">
                <textarea
                  ref={textareaRef}
                  rows={1}
                  value={input}
                  onChange={(e) => setInput(e.target.value)}
                  onKeyDown={handleKeyDown}
                  placeholder={searchWazuh ? 'Ask about your Wazuh and firewall data…' : 'Message SOC Assistant…'}
                  className="composer-textarea"
                  aria-label="Message"
                />
                {isTyping ? (
                  <button
                    onClick={handleCancel}
                    className="send-btn cancel-btn"
                    aria-label="Stop generating"
                    title="Stop generating"
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
              <div className="composer-tools">
                <button
                  type="button"
                  className={`mode-toggle ${searchWazuh ? 'is-on' : ''}`}
                  onClick={() => setSearchWazuh(v => !v)}
                  aria-pressed={searchWazuh}
                  title={searchWazuh ? 'Answers come from your Wazuh and firewall data. Click to switch to general chat.' : 'Search your live Wazuh and firewall data instead of general chat.'}
                >
                  <Database size={14} />
                  Search Wazuh
                </button>
                <span className="composer-hint">Enter to send · Shift+Enter for a new line</span>
              </div>
            </div>
            <div className="composer-footer">
              {searchWazuh
                ? 'Answers are based on your Wazuh and firewall data. Verify critical alerts before acting.'
                : 'SOC Assistant can make mistakes, and it cannot see your security data unless Search Wazuh is on.'}
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
                  <CollapsibleSummary text={modalData.summary} />
                </div>
                <button className="icon-btn" onClick={() => setModalData(null)}>
                  <X size={20} />
                </button>
              </div>
              <div className="log-modal-body">
                <LogDetailsModal entries={modalData.entries} source={modalData.source} totalHits={modalData.totalHits} isLoading={modalData.isLoading} />
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
