import { motion } from 'framer-motion';
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';
import { Activity } from 'lucide-react';
import { useTheme } from '../context/ThemeContext';

export default function ChartCard({ data, title }) {
  const { theme } = useTheme();
  const strokeColor = theme === 'dark' ? '#10b981' : '#059669'; // Green 500 / 600
  const gridColor = theme === 'dark' ? '#1f1f1f' : '#e5e7eb';
  const textColor = theme === 'dark' ? '#9ca3af' : '#6b7280';
  
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
            <Activity size={12} />
            {title || 'Alert Trends'}
          </span>
          <span className="header-source">wazuh-analytics</span>
        </div>
        
        <div style={{ height: 240, padding: '20px 20px 0 0' }}>
          <ResponsiveContainer width="100%" height="100%">
            <LineChart data={data} margin={{ top: 5, right: 5, left: -20, bottom: 5 }}>
              <CartesianGrid strokeDasharray="3 3" stroke={gridColor} vertical={false} />
              <XAxis 
                dataKey="time" 
                stroke={textColor} 
                fontSize={15} 
                tickLine={false} 
                axisLine={false}
              />
              <YAxis 
                stroke={textColor} 
                fontSize={15} 
                tickLine={false} 
                axisLine={false} 
              />
              <Tooltip 
                contentStyle={{ 
                  backgroundColor: theme === 'dark' ? '#141414' : '#ffffff',
                  border: `1px solid ${theme === 'dark' ? '#2a2a2a' : '#e5e7eb'}`,
                  borderRadius: '8px',
                  fontFamily: 'var(--font-mono)',
                  fontSize: '16px',
                  color: theme === 'dark' ? '#f3f4f6' : '#111827'
                }}
              />
              <Line 
                type="monotone" 
                dataKey="alerts" 
                stroke={strokeColor} 
                strokeWidth={2} 
                dot={{ r: 4, fill: strokeColor, strokeWidth: 0 }} 
                activeDot={{ r: 6, strokeWidth: 0 }} 
              />
            </LineChart>
          </ResponsiveContainer>
        </div>
        
        <div className="data-card-footer">
          Showing alert frequency over the last 6 hours
        </div>
      </div>
    </motion.div>
  );
}
