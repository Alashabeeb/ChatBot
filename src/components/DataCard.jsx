import { motion } from 'framer-motion';
import { Database, AlertTriangle, Info, CheckCircle2 } from 'lucide-react';
import './DataCard.css';

function SeverityIcon({ severity }) {
  switch (severity) {
    case 'high':
      return <AlertTriangle size={14} className="text-danger" />;
    case 'mid':
      return <AlertTriangle size={14} className="text-warning" />;
    case 'low':
      return <Info size={14} className="text-info" />;
    case 'ok':
      return <CheckCircle2 size={14} className="text-success" />;
    default:
      return <div className={`severity-dot ${severity}`} />;
  }
}

export default function DataCard({ source, rows, footer }) {
  return (
    <motion.div
      className="data-card-wrapper"
      initial={{ opacity: 0, y: 15 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.5, type: 'spring' }}
    >
      <div className="data-card glass">
        <div className="data-card-header">
          <span className="header-label">
            <Database size={12} />
            wazuh query
          </span>
          <span className="header-source">{source}</span>
        </div>
        
        <div className="data-card-rows">
          {rows.map((row, i) => (
            <motion.div 
              key={i} 
              className="data-row"
              initial={{ opacity: 0, x: -10 }}
              animate={{ opacity: 1, x: 0 }}
              transition={{ delay: 0.1 + (i * 0.05) }}
            >
              <div className="row-icon">
                <SeverityIcon severity={row.severity} />
              </div>
              <div className="row-content">
                <span className="row-label">{row.label}</span>
                <span className="row-meta">{row.meta}</span>
              </div>
              {row.action && (
                <button className="row-action-btn">{row.action}</button>
              )}
            </motion.div>
          ))}
        </div>
        
        {footer && (
          <div className="data-card-footer">
            {footer}
          </div>
        )}
      </div>
    </motion.div>
  );
}
