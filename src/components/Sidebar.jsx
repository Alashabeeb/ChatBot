import { useState, useRef, useEffect } from 'react';
import { motion } from 'framer-motion';
import { Terminal, ShieldAlert, Users, Server, Activity, Clock, Plus, Settings } from 'lucide-react';
import './Sidebar.css';

const QUICK_PROMPTS = [
  { label: 'Recent high-severity alerts', prompt: 'Show me the most recent high-severity alerts.', icon: <ShieldAlert size={14} className="text-danger" /> },
  { label: 'Alert Trends (Chart)', prompt: '/stats alerts', icon: <Activity size={14} className="text-warning" /> },
  { label: 'Disconnected agents', prompt: 'Which agents are currently disconnected?', icon: <Users size={14} className="text-info" /> },
  { label: 'Critical vulnerabilities', prompt: 'List any hosts with unpatched critical vulnerabilities.', icon: <Terminal size={14} className="text-danger" /> },
  { label: 'Manager health', prompt: 'What is the current status of the Wazuh manager?', icon: <Server size={14} className="text-success" /> },
];

export default function Sidebar({ isOpen, onClose, onPromptClick }) {
  const [width, setWidth] = useState(280);
  const isResizing = useRef(false);

  useEffect(() => {
    const handleMouseMove = (e) => {
      if (!isResizing.current) return;
      let newWidth = e.clientX;
      if (newWidth < 220) newWidth = 220; // Min width
      if (newWidth > 600) newWidth = 600; // Max width
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
    document.body.classList.add('is-resizing'); // Prevent text selection while dragging
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
                // Reset chat logic placeholder
             }}
           >
             <Plus size={18} />
             <span>New Chat</span>
           </motion.button>
        </div>

        <div className="sidebar-section">
          <h3 className="sidebar-heading">Quick queries</h3>
          <div className="quick-prompts">
            {QUICK_PROMPTS.map((q, i) => (
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
          <h3 className="sidebar-heading">Environment</h3>
          <div className="env-stats">
            <div className="env-stat-row">
              <span className="env-label">Agents:</span>
              <span className="env-value">12</span>
            </div>
            <div className="env-stat-row">
              <span className="env-label">Active:</span>
              <span className="env-value">11</span>
            </div>
            <div className="env-stat-row">
              <span className="env-label">Disconnected:</span>
              <span className="env-value text-danger">1</span>
            </div>
            <div className="env-stat-row">
              <span className="env-label">Manager:</span>
              <span className="env-value text-success">v4.9.0</span>
            </div>
          </div>
        </div>

        <div className="sidebar-divider" />

        <div className="sidebar-section">
          <h3 className="sidebar-heading">Recent</h3>
          <div className="recent-list">
            {[
              'SSH brute force attempts',
              'Outdated glibc packages',
              'Status of db-srv-01'
            ].map((item, idx) => (
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
