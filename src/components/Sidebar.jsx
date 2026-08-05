import { useState, useRef, useEffect } from 'react';
import { motion } from 'framer-motion';
import { Terminal, ShieldAlert, Users, Server, Activity, Clock, Plus, Settings, Search, Bug, Globe, Key, Trash2, MessageSquare } from 'lucide-react';
import './Sidebar.css';

const QUICK_PROMPTS = [
  { label: 'Authentication failures (24h)', prompt: 'Show me all authentication failures in the last 24 hours', icon: <Key size={14} className="text-danger" /> },
  { label: 'Brute force attacks', prompt: 'Find all brute force login attempts on the network', icon: <ShieldAlert size={14} className="text-danger" /> },
  { label: 'Top attacking IPs', prompt: 'What are the top source IPs generating alerts today?', icon: <Globe size={14} className="text-warning" /> },
  { label: 'Critical CVE vulnerabilities', prompt: 'List all hosts with unpatched critical CVE vulnerabilities', icon: <Bug size={14} className="text-danger" /> },
  { label: 'Suspicious SSH activity', prompt: 'Show me all SSH login failures and suspicious SSH activity', icon: <Terminal size={14} className="text-warning" /> },
];

export default function Sidebar({ isOpen, onClose, onPromptClick, sessions = [], activeSessionId, onSelectSession, onNewChat, onClearSessions }) {
  const [width, setWidth] = useState(280);
  const isResizing = useRef(false);

  useEffect(() => {
    const handleMouseMove = (e) => {
      if (!isResizing.current) return;
      let newWidth = e.clientX;
      if (newWidth < 220) newWidth = 220;
      if (newWidth > 600) newWidth = 600;
      setWidth(newWidth);
    };

    const handleMouseUp = () => {
      isResizing.current = false;
      document.body.style.cursor = 'default';
      document.body.classList.remove('is-resizing');
    };

    document.addEventListener('mousemove', handleMouseMove);
    document.addEventListener('mouseup', handleMouseUp);

    return () => {
      document.removeEventListener('mousemove', handleMouseMove);
      document.removeEventListener('mouseup', handleMouseUp);
    };
  }, []);

  const handleMouseDown = (e) => {
    e.preventDefault();
    isResizing.current = true;
    document.body.style.cursor = 'col-resize';
    document.body.classList.add('is-resizing');
  };

  return (
    <motion.aside
      className={`sidebar ${isOpen ? 'open' : ''}`}
      initial={false}
      animate={{ x: isOpen ? 0 : '0%' }} 
      style={{ width: window.innerWidth < 768 ? '280px' : `${width}px` }}
    >
      <div className="sidebar-content">
        <div className="sidebar-section sidebar-top-actions">
           <motion.button 
             className="new-chat-btn"
             whileHover={{ scale: 1.02 }}
             whileTap={{ scale: 0.98 }}
             onClick={() => {
                onNewChat();
                if (window.innerWidth < 768) onClose();
             }}
           >
             <Plus size={18} />
             <span>New Chat</span>
           </motion.button>
        </div>

        <div className="sidebar-section">
          <h3 className="sidebar-heading">Quick Queries</h3>
          <div className="quick-prompts">
            {QUICK_PROMPTS.map((q) => (
              <motion.button
                key={q.label}
                className="quick-prompt-btn"
                onClick={() => {
                  onPromptClick(q.prompt);
                  if (window.innerWidth < 768) onClose();
                }}
                whileHover={{ scale: 1.02, x: 2 }}
                whileTap={{ scale: 0.98 }}
              >
                {q.icon}
                <span>{q.label}</span>
              </motion.button>
            ))}
          </div>
        </div>

        <div className="sidebar-divider" />

        <div className="sidebar-section">
          <div className="sidebar-heading-row">
            <h3 className="sidebar-heading">Recent Chats</h3>
            {sessions.length > 0 && (
              <button className="clear-recent-btn" onClick={onClearSessions} title="Clear all chat sessions">
                <Trash2 size={13} />
              </button>
            )}
          </div>
          <div className="recent-list">
            {sessions.length === 0 && (
              <div className="recent-empty">No recent chats yet</div>
            )}
            {sessions.map((session) => (
              <motion.div
                key={session.id}
                className={`recent-item-wrapper ${session.id === activeSessionId ? 'active-session' : ''}`}
                style={{ position: 'relative', display: 'flex', alignItems: 'center' }}
                whileHover="hover"
                initial="initial"
              >
                <motion.button
                  className={`recent-item-btn ${session.id === activeSessionId ? 'active-session' : ''}`}
                  onClick={() => {
                    onSelectSession(session.id);
                    if (window.innerWidth < 768) onClose();
                  }}
                  style={{ flex: 1, paddingRight: '28px' }}
                >
                  <MessageSquare size={14} className={session.id === activeSessionId ? 'text-accent' : 'text-muted'} />
                  <span className="truncate">{session.title}</span>
                </motion.button>
                
                <motion.button
                  className="delete-session-btn"
                  onClick={(e) => {
                    e.stopPropagation();
                    onDeleteSession(session.id);
                  }}
                  title="Delete chat"
                  variants={{
                    initial: { opacity: 0 },
                    hover: { opacity: 1 }
                  }}
                  style={{
                    position: 'absolute',
                    right: '6px',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    width: '22px',
                    height: '22px',
                    background: 'transparent',
                    border: 'none',
                    color: 'var(--text-muted)',
                    cursor: 'pointer',
                    borderRadius: '4px'
                  }}
                  whileHover={{ backgroundColor: 'var(--bg-hover)', color: 'var(--danger)' }}
                >
                  <Trash2 size={13} />
                </motion.button>
              </motion.div>
            ))}
          </div>
        </div>
        
        <div className="sidebar-footer">
          <motion.button 
             className="settings-btn"
             whileHover={{ scale: 1.02 }}
             whileTap={{ scale: 0.98 }}
          >
            <Settings size={16} />
            <span>Settings</span>
          </motion.button>
        </div>
      </div>
      
      {/* Drag Handle */}
      <div 
        className="sidebar-resizer" 
        onMouseDown={handleMouseDown}
      />
    </motion.aside>
  );
}
