import { useState } from 'react';
import { Shield, Lock, AlertCircle, ArrowRight, LogOut } from 'lucide-react';
import './LoginPage.css';

const MIN_LENGTH = 12;

/**
 * Shown after login while the account must change its password (F-08b), for example the default
 * admin on first login. The backend refuses every other request until this succeeds.
 */
export default function ChangePasswordPage({ currentUser, onChanged, onLogout }) {
  const [currentPassword, setCurrentPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [confirm, setConfirm] = useState('');
  const [error, setError] = useState(null);
  const [isSaving, setIsSaving] = useState(false);

  const apiUrl = (path) => (window.location.hostname === 'localhost'
    ? `http://localhost:3002${path}`
    : `http://${window.location.hostname}:3002${path}`);

  async function handleSubmit(e) {
    e.preventDefault();
    setError(null);
    if (newPassword.length < MIN_LENGTH) return setError(`The new password must be at least ${MIN_LENGTH} characters long.`);
    if (newPassword !== confirm) return setError('The new passwords do not match.');

    setIsSaving(true);
    try {
      const token = localStorage.getItem('soc_auth_token');
      const res = await fetch(apiUrl('/api/auth/change-password'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', ...(token ? { Authorization: `Bearer ${token}` } : {}) },
        body: JSON.stringify({ currentPassword, newPassword })
      });
      const data = await res.json().catch(() => ({}));
      if (res.status === 401) return onLogout();
      if (!res.ok || !data.success) throw new Error(data.error || `Request failed with status ${res.status}.`);
      localStorage.setItem('soc_auth_user', JSON.stringify(data.user));
      onChanged(data.user);
    } catch (err) {
      setError(err.message || 'Unable to reach the server.');
    } finally {
      setIsSaving(false);
    }
  }

  const field = (label, value, setter, autoComplete) => (
    <div className={`lp-input-group ${value ? 'has-value' : ''}`}>
      <div className="lp-input-icon"><Lock size={16} /></div>
      <input
        type="password"
        className="lp-input"
        placeholder={label}
        aria-label={label}
        value={value}
        onChange={(e) => setter(e.target.value)}
        autoComplete={autoComplete}
        disabled={isSaving}
      />
      <div className="lp-input-line" />
    </div>
  );

  return (
    <div className="lp-universe">
      <div className="lp-deep-bg" />
      <div className="lp-card-container">
        <div className="lp-card">
          <div className="lp-card-header">
            <div className="lp-logo-ring"><div className="lp-logo-ring-inner"><Shield size={28} /></div></div>
            <h1 className="lp-title">Set a new password</h1>
            <p className="lp-subtitle">
              {currentUser?.username ? `Signed in as ${currentUser.username}. ` : ''}
              This account must choose its own password before continuing.
            </p>
          </div>

          <form className="lp-form" onSubmit={handleSubmit}>
            {error && (
              <div className="lp-error" role="alert">
                <AlertCircle size={15} />
                <span>{error}</span>
              </div>
            )}
            {field('Current password', currentPassword, setCurrentPassword, 'current-password')}
            {field(`New password (${MIN_LENGTH}+ characters)`, newPassword, setNewPassword, 'new-password')}
            {field('Confirm new password', confirm, setConfirm, 'new-password')}

            <button type="submit" className="lp-submit-btn" disabled={isSaving || !currentPassword || !newPassword || !confirm}>
              <div className="lp-btn-content">
                {isSaving ? (<><div className="lp-spinner" /><span>Saving…</span></>) : (<><span>Save and continue</span><ArrowRight size={18} /></>)}
              </div>
            </button>
          </form>

          <div className="lp-card-footer">
            <button type="button" className="lp-eye-btn" style={{ position: 'static', display: 'inline-flex', gap: 6, alignItems: 'center', whiteSpace: 'nowrap', width: 'auto', padding: '4px 8px' }} onClick={onLogout}>
              <LogOut size={14} /> Sign out
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
