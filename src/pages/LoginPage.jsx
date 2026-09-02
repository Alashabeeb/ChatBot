import { useState, useRef, useCallback, useEffect } from 'react';
import { Shield, Lock, User, ArrowRight, AlertCircle, Eye, EyeOff } from 'lucide-react';
import './LoginPage.css';

/* ─── Floating 3D Wireframe Cube ─── */
function WireframeCube({ size = 120, speed = 20, className = '' }) {
  return (
    <div className={`wf-cube-scene ${className}`}>
      <div className="wf-cube" style={{
        width: size, height: size,
        animationDuration: `${speed}s`
      }}>
        {['front','back','right','left','top','bottom'].map(face => (
          <div key={face} className={`wf-face wf-${face}`} style={{ width: size, height: size }} />
        ))}
      </div>
    </div>
  );
}

/* ─── Orbiting Ring ─── */
function OrbitRing({ radius = 200, duration = 12, dotCount = 8, reverse = false }) {
  return (
    <div className="orbit-ring" style={{
      width: radius * 2, height: radius * 2,
      animationDuration: `${duration}s`,
      animationDirection: reverse ? 'reverse' : 'normal'
    }}>
      {Array.from({ length: dotCount }).map((_, i) => {
        const angle = (360 / dotCount) * i;
        return (
          <div key={i} className="orbit-dot" style={{
            transform: `rotate(${angle}deg) translateX(${radius}px)`
          }} />
        );
      })}
    </div>
  );
}

/* ─── Hexagonal Grid Background ─── */
function HexGrid() {
  return (
    <svg className="hex-grid" viewBox="0 0 800 600" preserveAspectRatio="xMidYMid slice">
      <defs>
        <pattern id="hexPattern" width="60" height="52" patternUnits="userSpaceOnUse" patternTransform="scale(1.5)">
          <path d="M30 0 L60 15 L60 37 L30 52 L0 37 L0 15 Z" fill="none" stroke="rgba(16,185,129,0.06)" strokeWidth="0.5" />
        </pattern>
      </defs>
      <rect width="100%" height="100%" fill="url(#hexPattern)" />
    </svg>
  );
}

/* ─── Scan Line Effect ─── */
function ScanLine() {
  return <div className="scan-line" />;
}

/* ─── Main Login Page ─── */
export default function LoginPage({ onLogin }) {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState(null);
  const [focusedField, setFocusedField] = useState(null);
  const cardRef = useRef(null);

  // 3D Card Tilt Effect
  const handleMouseMove = useCallback((e) => {
    if (!cardRef.current) return;
    const rect = cardRef.current.getBoundingClientRect();
    const x = e.clientX - rect.left;
    const y = e.clientY - rect.top;
    const centerX = rect.width / 2;
    const centerY = rect.height / 2;
    const rotateX = ((y - centerY) / centerY) * -6;
    const rotateY = ((x - centerX) / centerX) * 6;
    cardRef.current.style.transform = `perspective(1000px) rotateX(${rotateX}deg) rotateY(${rotateY}deg) translateZ(10px)`;
  }, []);

  const handleMouseLeave = useCallback(() => {
    if (!cardRef.current) return;
    cardRef.current.style.transform = 'perspective(1000px) rotateX(0deg) rotateY(0deg) translateZ(0px)';
  }, []);

  // Typing title animation
  const [titleText, setTitleText] = useState('');
  const fullTitle = 'SOC ChatBot';
  useEffect(() => {
    let i = 0;
    const interval = setInterval(() => {
      setTitleText(fullTitle.slice(0, i + 1));
      i++;
      if (i >= fullTitle.length) clearInterval(interval);
    }, 90);
    return () => clearInterval(interval);
  }, []);

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

      localStorage.setItem('soc_auth_token', data.token);
      localStorage.setItem('soc_auth_user', JSON.stringify(data.user));
      onLogin(data.user);
    } catch (err) {
      console.error('Login Error:', err);
      setError(err.message || 'Unable to reach backend server.');
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="lp-universe">
      {/* Background Layers */}
      <div className="lp-deep-bg" />
      <HexGrid />
      <ScanLine />

      {/* Floating Particles */}
      <div className="lp-particles">
        {Array.from({ length: 40 }).map((_, i) => (
          <div key={i} className="lp-particle" style={{
            left: `${Math.random() * 100}%`,
            top: `${Math.random() * 100}%`,
            width: `${2 + Math.random() * 3}px`,
            height: `${2 + Math.random() * 3}px`,
            animationDelay: `${Math.random() * 8}s`,
            animationDuration: `${6 + Math.random() * 10}s`,
            opacity: 0.15 + Math.random() * 0.4
          }} />
        ))}
      </div>

      {/* 3D Wireframe Cubes */}
      <WireframeCube size={100} speed={25} className="cube-pos-1" />
      <WireframeCube size={60} speed={18} className="cube-pos-2" />
      <WireframeCube size={40} speed={30} className="cube-pos-3" />

      {/* Orbiting Rings */}
      <div className="orbit-container">
        <OrbitRing radius={180} duration={15} dotCount={10} />
        <OrbitRing radius={240} duration={22} dotCount={14} reverse />
        <OrbitRing radius={300} duration={30} dotCount={6} />
      </div>

      {/* Central Glowing Core */}
      <div className="lp-core-glow" />

      {/* Login Card */}
      <div className="lp-card-container">
        <div
          ref={cardRef}
          className="lp-card"
          onMouseMove={handleMouseMove}
          onMouseLeave={handleMouseLeave}
        >
          {/* Card Glow Border */}
          <div className="lp-card-glow" />

          {/* Header */}
          <div className="lp-card-header">
            <div className="lp-logo-ring">
              <div className="lp-logo-ring-inner">
                <Shield size={28} />
              </div>
              <svg className="lp-logo-ring-svg" viewBox="0 0 100 100">
                <circle cx="50" cy="50" r="46" fill="none" stroke="rgba(16,185,129,0.2)" strokeWidth="1" />
                <circle cx="50" cy="50" r="46" fill="none" stroke="url(#logoGrad)" strokeWidth="2"
                  strokeDasharray="50 240" strokeLinecap="round" className="lp-ring-spin" />
                <defs>
                  <linearGradient id="logoGrad" x1="0%" y1="0%" x2="100%" y2="100%">
                    <stop offset="0%" stopColor="#10b981" />
                    <stop offset="100%" stopColor="#06d6a0" />
                  </linearGradient>
                </defs>
              </svg>
            </div>

            <h1 className="lp-title">
              {titleText}
              <span className="lp-cursor">|</span>
            </h1>
            <p className="lp-subtitle">Advanced Threat Analytics System</p>
            <div className="lp-secure-badge">
              <Lock size={11} />
              <span>ENCRYPTED SESSION</span>
            </div>
          </div>

          {/* Form */}
          <form className="lp-form" onSubmit={handleSubmit}>
            {error && (
              <div className="lp-error">
                <AlertCircle size={15} />
                <span>{error}</span>
              </div>
            )}

            <div className={`lp-input-group ${focusedField === 'user' ? 'focused' : ''} ${username ? 'has-value' : ''}`}>
              <div className="lp-input-icon">
                <User size={16} />
              </div>
              <input
                type="text"
                className="lp-input"
                placeholder="Username"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                onFocus={() => setFocusedField('user')}
                onBlur={() => setFocusedField(null)}
                autoComplete="username"
                disabled={isLoading}
              />
              <div className="lp-input-line" />
            </div>

            <div className={`lp-input-group ${focusedField === 'pass' ? 'focused' : ''} ${password ? 'has-value' : ''}`}>
              <div className="lp-input-icon">
                <Lock size={16} />
              </div>
              <input
                type={showPassword ? 'text' : 'password'}
                className="lp-input"
                placeholder="Password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                onFocus={() => setFocusedField('pass')}
                onBlur={() => setFocusedField(null)}
                autoComplete="current-password"
                disabled={isLoading}
              />
              <button
                type="button"
                className="lp-eye-btn"
                onClick={() => setShowPassword(!showPassword)}
                tabIndex={-1}
              >
                {showPassword ? <EyeOff size={16} /> : <Eye size={16} />}
              </button>
              <div className="lp-input-line" />
            </div>

            <button type="submit" className="lp-submit-btn" disabled={isLoading}>
              <div className="lp-btn-content">
                {isLoading ? (
                  <>
                    <div className="lp-spinner" />
                    <span>Authenticating...</span>
                  </>
                ) : (
                  <>
                    <span>Sign In</span>
                    <ArrowRight size={18} />
                  </>
                )}
              </div>
              <div className="lp-btn-glow" />
            </button>
          </form>

          {/* Footer */}
          <div className="lp-card-footer">
            <span>Enterprise-grade security</span>
            <span className="lp-dot">•</span>
            <span>Connected to Wazuh SIEM</span>
          </div>
        </div>
      </div>

      {/* Bottom Status Bar */}
      <div className="lp-status-bar">
        <div className="lp-status-item">
          <span className="lp-status-dot lp-pulse" />
          <span>SYSTEM ONLINE</span>
        </div>
        <div className="lp-status-item">
          <span>TLS 1.3 ENCRYPTED</span>
        </div>
        <div className="lp-status-item">
          <span>v2.0.0</span>
        </div>
      </div>
    </div>
  );
}