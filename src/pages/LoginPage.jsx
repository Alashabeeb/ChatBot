import { useState } from 'react';
import { Shield, Eye, EyeOff, ShieldCheck, Activity, Zap } from 'lucide-react';
import { useTheme } from '../context/ThemeContext';
import './LoginPage.css';

export default function LoginPage({ onLogin }) {
  const { theme, toggleTheme } = useTheme();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  
  const handleLogin = async (e) => {
    e.preventDefault();
    setIsLoading(true);
    await new Promise((r) => setTimeout(r, 1200));
    setIsLoading(false);
    onLogin();
  };

  return (
    <div className="gb-login-page">
      <header className="gb-header">
        <div className="gb-logo-container">
           <Shield size={36} className="gb-logo-icon" />
           <span className="gb-logo-text">GBB ChatBot</span>
        </div>
        <button className="theme-toggle-btn gb-theme-btn" onClick={toggleTheme} aria-label="Toggle theme">
          {theme === 'dark' ? '☀️' : '🌙'}
        </button>
      </header>

      <main className="gb-main">
        {/* Abstract Background Graphic */}
        <div className="gb-graphic-container">
           <div className="network-orb">
              <div className="orb-outer-ring"></div>
              <div className="orb-inner-ring"></div>
              <div className="orb-core"></div>
           </div>
           
           {/* Floating Glass Nodes */}
           <div className="floating-node node-1">
             Real-time Monitoring
           </div>
           
           <div className="floating-node node-2">
             Threat Analytics
           </div>
           
           <div className="floating-node node-3">
             Wazuh
           </div>
           
           <div className="floating-node node-4">
             Agent Insights
           </div>
           
           <div className="floating-node node-5">
             AI-Powered Triage
           </div>
           
           <div className="floating-node node-6">
             Security
           </div>
        </div>
        
        {/* Login Box */}
        <div className="gb-login-box-container">
           <div className="gb-login-box">
             <div className="gb-box-header">
               <Shield className="box-header-icon" size={28} />
               <h2><b>GBB ChatBot</b> Advanced Threat Analytics System</h2>
             </div>
             
             <form className="gb-form" onSubmit={handleLogin}>
                <button type="submit" className="gb-login-btn" disabled={isLoading}>
                   {isLoading ? 'Connecting...' : 'Open ChatBit'}
                </button>
             </form>
           </div>
        </div>
      </main>

      <footer className="gb-footer">
        <p>Chrome 85, Firefox 80, Firefox ESR 78 and above browsers are supported. It is recommended to update the version in time. The recommended resolution is 1920 x 1080, and the minimum supported resolution is 1366 x 768.</p>
        <p>Copyright© GBB ChatBot 2016-2026. All rights reserved. <a href="#">Privacy Statement</a></p>
      </footer>
    </div>
  );
}
