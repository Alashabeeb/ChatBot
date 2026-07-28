import { useState, useRef, useEffect } from 'react';
import { motion } from 'framer-motion';
import { Terminal, ShieldAlert, Users, Server, Activity, Clock, Plus, Settings, Search, Bug, Globe, Key, Trash2 } from 'lucide-react';
import './Sidebar.css';

const QUICK_PROMPTS = [
  { label: 'Authentication failures (24h)', prompt: 'Show me all authentication failures in the last 24 hours', icon: <Key size={14} className="text-danger" /> },
  { label: 'Brute force attacks', prompt: 'Find all brute force login attempts on the network', icon: <ShieldAlert size={14} className="text-danger" /> },
  { label: 'Top attacking IPs', prompt: 'What are the top source IPs generating alerts today?', icon: <Globe size={14} className="text-warning" /> },
  { label: 'Critical CVE vulnerabilities', prompt: 'List all hosts with unpatched critical CVE vulnerabilities', icon: <Bug size={14} className="text-danger" /> },
  { label: 'Suspicious SSH activity', prompt: 'Show me all SSH login failures and suspicious SSH activity', icon: <Terminal size={14} className="text-warning" /> },
];

const RECENT_KEY = 'gbb_recent_chats';
const MAX_RECENT = 5;

function getRecent() {
  try {
    return JSON.parse(localStorage.getItem(RECENT_KEY)) || [];
  } catch { return []; }
}

function saveRecent(list) {
  localStorage.setItem(RECENT_KEY, JSON.stringify(list));
}

export default function Sidebar({ isOpen, onClose, onPromptClick, lastUserPrompt }) {
  const [width, setWidth] = useState(280);
  const [recentChats, setRecentChats] = useState(getRecent);
  const isResizing = useRef(false);

  // When a new user prompt comes in, add it to recent (FIFO: 6th replaces 1st)
  useEffect(() => {
    if (!lastUserPrompt || !lastUserPrompt.trim()) return;
    setRecentChats(prev => {
      const trimmed = lastUserPrompt.trim();
      // Don't add duplicates
      const filtered = prev.filter(p => p !== trimmed);
      const updated = [...filtered, trimmed].slice(-MAX_RECENT);
      saveRecent(updated);
      return updated;
    });
  }, [lastUserPrompt]);

  function clearRecent() {
    setRecentChats([]);
    localStorage.removeItem(RECENT_KEY);
  }

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
                window.location.reload();
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
            {recentChats.length > 0 && (
              <button className="clear-recent-btn" onClick={clearRecent} title="Clear recent chats">
                <Trash2 size={13} />
              </button>
            )}
          </div>
          <div className="recent-list">
            {recentChats.length === 0 && (
              <div className="recent-empty">No recent chats yet</div>
            )}
            {[...recentChats].reverse().map((item, idx) => (
              <motion.button
                key={idx}
                className="recent-item-btn"
                onClick={() => {
                  onPromptClick(item);
                  if (window.innerWidth < 768) onClose();
                }}
                whileHover={{ x: 2 }}
              >
                <Clock size={14} className="text-muted" />
                <span className="truncate">{item}</span>
              </motion.button>
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
