import { useState } from 'react';
import { Shield, ShieldCheck, Activity, Brain, Lock, User, ArrowRight, AlertCircle, Eye, EyeOff } from 'lucide-react';
import { useTheme } from '../context/ThemeContext';
import TerminalFeed from '../components/TerminalFeed';
import './LoginPage.css';

export default function LoginPage({ onLogin }) {
  const { theme, toggleTheme } = useTheme();
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState(null);

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!username.trim() || !password) {
      setError('Please enter both username and password.');
      return;
    }

    setIsLoading(true);
    setError(null);

    try {
      const API_URL = window.location.hostname === 'localhost'
        ? 'http://localhost:3002/api/auth/login'
        : `http://${window.location.hostname}:3002/api/auth/login`;

      const res = await fetch(API_URL, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: username.trim(), password })
      });

      const data = await res.json();

      if (!res.ok || !data.success) {
        throw new Error(data.error || 'Authentication failed. Please check your credentials.');
      }

      // Save token and user details to localStorage
      localStorage.setItem('soc_auth_token', data.token);
      localStorage.setItem('soc_auth_user', JSON.stringify(data.user));

      onLogin(data.user);
    } catch (err) {
      console.error('Login Error:', err);
      setError(err.message || 'Unable to reach backend server. Please verify backend is running on port 3002.');
    } finally {
      setIsLoading(false);
    }
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

        {/* Orbit background */}
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
              <Shield size={38} />
            </div>

            {/* Title */}
            <h1 className="gb-card-title">SOC ChatBot</h1>
            <p className="gb-card-subtitle">Enterprise Security Operations Portal</p>

            {/* Divider */}
            <div className="gb-card-divider" />

            {/* Error Message Box */}
            {error && (
              <div className="gb-error-banner">
                <AlertCircle size={16} />
                <span>{error}</span>
              </div>
            )}

            {/* Sign-In Form */}
            <form onSubmit={handleSubmit} className="gb-login-form">
              <div className="gb-input-group">
                <label className="gb-input-label">Username</label>
                <div className="gb-input-wrapper">
                  <User size={18} className="gb-input-icon" />
                  <input
                    type="text"
                    placeholder="Enter username (e.g. admin)"
                    value={username}
                    onChange={(e) => setUsername(e.target.value)}
                    required
                    autoFocus
                    className="gb-text-input"
                    disabled={isLoading}
                  />
                </div>
              </div>

              <div className="gb-input-group">
                <label className="gb-input-label">Password</label>
                <div className="gb-input-wrapper">
                  <Lock size={18} className="gb-input-icon" />
                  <input
                    type={showPassword ? 'text' : 'password'}
                    placeholder="Enter password"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    required
                    className="gb-text-input"
                    disabled={isLoading}
                  />
                  <button
                    type="button"
                    className="gb-password-toggle"
                    onClick={() => setShowPassword(!showPassword)}
                    tabIndex={-1}
                    aria-label={showPassword ? "Hide password" : "Show password"}
                  >
                    {showPassword ? <EyeOff size={16} /> : <Eye size={16} />}
                  </button>
                </div>
              </div>

              {/* Submit button */}
              <button type="submit" className="gb-open-btn" disabled={isLoading}>
                <span>{isLoading ? 'Authenticating...' : 'Sign In'}</span>
                {!isLoading && <ArrowRight size={18} />}
                <div className="gb-btn-shimmer" />
              </button>
            </form>

            {/* Feature badges */}
            <div className="gb-badge-row">
              <div className="gb-badge">
                <Brain size={13} />
                <span>AI-Powered</span>
              </div>
              <div className="gb-badge">
                <Activity size={13} />
                <span>Real-time</span>
              </div>
              <div className="gb-badge">
                <ShieldCheck size={13} />
                <span>RBAC Secured</span>
              </div>
            </div>

            {/* Footer text */}
            <p className="gb-card-footer">
              <Lock size={12} />
              Enterprise-grade security • Role-Based Access Control
            </p>
          </div>
        </div>
      </main>

      <footer className="gb-footer">
        <p>Copyright© SOC ChatBot 2016-2026. All rights reserved.</p>
      </footer>
    </div>
  );
}