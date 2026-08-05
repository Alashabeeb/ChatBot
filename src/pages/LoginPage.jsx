import { useState } from 'react';
import { Shield, ShieldCheck, Activity, Brain, Lock, ArrowRight } from 'lucide-react';
import { useTheme } from '../context/ThemeContext';
import TerminalFeed from '../components/TerminalFeed';
import './LoginPage.css';

export default function LoginPage({ onLogin }) {
  const { theme, toggleTheme } = useTheme();
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
      {/* Floating particles */}
      <div className="gb-particles">
        {Array.from({ length: 20 }).map((_, i) => (
          <div key={i} className="gb-particle" style={{
            left: `${Math.random() * 100}%`,
            top: `${Math.random() * 100}%`,
            animationDelay: `${Math.random() * 8}s`,
            animationDuration: `${6 + Math.random() * 8}s`,
          }} />
        ))}
      </div>

      {/* Header */}
      <header className="gb-header">
        <div className="gb-logo-container">
           <Shield size={36} className="gb-logo-icon" />
           <span className="gb-logo-text">SOC ChatBot</span>
        </div>
        <button className="theme-toggle-btn gb-theme-btn" onClick={toggleTheme} aria-label="Toggle theme">
          {theme === 'dark' ? '☀️' : '🌙'}
        </button>
      </header>

      {/* Full-screen main area with orbit as background */}
      <main className="gb-main">

        {/* Orbit background — positioned absolutely to fill the entire main area */}
        <div className="gb-orb-bg">
          <div className="gb-orb-stage">
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
        </div>

        {/* Naked terminal feed — bottom left, floating raw text */}
        <div className="gb-terminal-float">
          <TerminalFeed naked />
        </div>

        {/* Glassmorphism login card — center right */}
        <div className="gb-card-container">
          <div className="gb-glass-card">
            {/* Shield icon */}
            <div className="gb-card-icon">
              <div className="gb-icon-ring" />
              <Shield size={40} />
            </div>

            {/* Title */}
            <h1 className="gb-card-title">SOC ChatBot</h1>
            <p className="gb-card-subtitle">Advanced Threat Analytics System</p>

            {/* Divider */}
            <div className="gb-card-divider" />

            {/* Feature badges */}
            <div className="gb-badge-row">
              <div className="gb-badge">
                <Brain size={14} />
                <span>AI-Powered</span>
              </div>
              <div className="gb-badge">
                <Activity size={14} />
                <span>Real-time</span>
              </div>
              <div className="gb-badge">
                <ShieldCheck size={14} />
                <span>24/7 SOC</span>
              </div>
            </div>

            {/* Stat cards */}
            <div className="gb-stats-row">
              <div className="gb-stat-card">
                <span className="gb-stat-value">99.9%</span>
                <span className="gb-stat-label">Uptime</span>
              </div>
              <div className="gb-stat-card">
                <span className="gb-stat-value">24/7</span>
                <span className="gb-stat-label">Active</span>
              </div>
              <div className="gb-stat-card">
                <span className="gb-stat-value">500+</span>
                <span className="gb-stat-label">Rules</span>
              </div>
            </div>

            {/* Open button */}
            <form onSubmit={handleLogin}>
              <button type="submit" className="gb-open-btn" disabled={isLoading}>
                <span>{isLoading ? 'Connecting...' : 'Open ChatBot'}</span>
                {!isLoading && <ArrowRight size={18} />}
                <div className="gb-btn-shimmer" />
              </button>
            </form>

            {/* Footer text */}
            <p className="gb-card-footer">
              <Lock size={12} />
              Enterprise-grade security • Connected to Wazuh SIEM
            </p>
          </div>
        </div>
      </main>

      <footer className="gb-footer">
        <p>Copyright© SOC ChatBot 2016-2026. All rights reserved. <a href="#">Privacy Statement</a></p>
      </footer>
    </div>
  );
}