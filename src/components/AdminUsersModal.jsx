import { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { X, UserPlus, Users, Trash2, Shield, User, Key, CheckCircle, AlertCircle, RefreshCw } from 'lucide-react';
import './AdminUsersModal.css';

export default function AdminUsersModal({ isOpen, onClose, currentUser }) {
  const [activeTab, setActiveTab] = useState('list'); // 'list' | 'create'
  const [users, setUsers] = useState([]);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState(null);
  const [successMsg, setSuccessMsg] = useState(null);

  // New User Form State
  const [newUsername, setNewUsername] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [newRole, setNewRole] = useState('user');
  const [isSubmitting, setIsSubmitting] = useState(false);

  // Delete Confirmation State
  const [deletingUser, setDeletingUser] = useState(null);

  const getAuthHeaders = () => {
    const token = localStorage.getItem('soc_auth_token');
    return {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${token}`
    };
  };

  const fetchUsers = async () => {
    setIsLoading(true);
    setError(null);
    try {
      const API_URL = window.location.hostname === 'localhost'
        ? 'http://localhost:3002/api/auth/users'
        : `http://${window.location.hostname}:3002/api/auth/users`;

      const res = await fetch(API_URL, {
        headers: getAuthHeaders()
      });
      const data = await res.json();
      if (!res.ok || !data.success) {
        throw new Error(data.error || 'Failed to fetch user list');
      }
      setUsers(data.users || []);
    } catch (err) {
      setError(err.message);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    if (isOpen) {
      fetchUsers();
      setError(null);
      setSuccessMsg(null);
    }
  }, [isOpen]);

  const handleCreateUser = async (e) => {
    e.preventDefault();
    if (!newUsername.trim() || !newPassword) {
      setError('Please provide username and password.');
      return;
    }

    setIsSubmitting(true);
    setError(null);
    setSuccessMsg(null);

    try {
      const API_URL = window.location.hostname === 'localhost'
        ? 'http://localhost:3002/api/auth/users'
        : `http://${window.location.hostname}:3002/api/auth/users`;

      const res = await fetch(API_URL, {
        method: 'POST',
        headers: getAuthHeaders(),
        body: JSON.stringify({
          username: newUsername.trim(),
          password: newPassword,
          role: newRole
        })
      });

      const data = await res.json();
      if (!res.ok || !data.success) {
        throw new Error(data.error || 'Failed to create user');
      }

      setSuccessMsg(`User '${data.user.username}' created successfully with role '${data.user.role}'!`);
      setNewUsername('');
      setNewPassword('');
      setNewRole('user');
      fetchUsers();
      setTimeout(() => setActiveTab('list'), 1500);
    } catch (err) {
      setError(err.message);
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleDeleteUser = async (user) => {
    if (user.id === currentUser?.id || user.username === currentUser?.username) {
      setError('You cannot delete your own active administrator account.');
      return;
    }

    setIsLoading(true);
    setError(null);
    setSuccessMsg(null);

    try {
      const API_URL = window.location.hostname === 'localhost'
        ? `http://localhost:3002/api/auth/users/${user.id}`
        : `http://${window.location.hostname}:3002/api/auth/users/${user.id}`;

      const res = await fetch(API_URL, {
        method: 'DELETE',
        headers: getAuthHeaders()
      });

      const data = await res.json();
      if (!res.ok || !data.success) {
        throw new Error(data.error || 'Failed to delete user');
      }

      setSuccessMsg(data.message || `User '${user.username}' deleted.`);
      setDeletingUser(null);
      fetchUsers();
    } catch (err) {
      setError(err.message);
    } finally {
      setIsLoading(false);
    }
  };

  if (!isOpen) return null;

  return (
    <div className="admin-modal-overlay">
      <motion.div
        className="admin-modal-container glass"
        initial={{ opacity: 0, scale: 0.95, y: 10 }}
        animate={{ opacity: 1, scale: 1, y: 0 }}
        exit={{ opacity: 0, scale: 0.95, y: 10 }}
        transition={{ duration: 0.2 }}
      >
        {/* Header */}
        <div className="admin-modal-header">
          <div className="admin-header-title">
            <div className="admin-icon-box">
              <Users size={20} />
            </div>
            <div>
              <h2>User Management</h2>
              <span className="admin-header-sub">Role-Based Access Control</span>
            </div>
          </div>
          <button className="admin-close-btn" onClick={onClose} aria-label="Close modal">
            <X size={20} />
          </button>
        </div>

        {/* Navigation Tabs */}
        <div className="admin-nav-tabs">
          <button
            className={`admin-tab-btn ${activeTab === 'list' ? 'active' : ''}`}
            onClick={() => { setActiveTab('list'); setError(null); setSuccessMsg(null); }}
          >
            <Users size={16} />
            <span>All Users ({users.length})</span>
          </button>
          <button
            className={`admin-tab-btn ${activeTab === 'create' ? 'active' : ''}`}
            onClick={() => { setActiveTab('create'); setError(null); setSuccessMsg(null); }}
          >
            <UserPlus size={16} />
            <span>Create New User</span>
          </button>
        </div>

        {/* Notification Banners */}
        {error && (
          <div className="admin-alert admin-alert-danger">
            <AlertCircle size={16} />
            <span>{error}</span>
          </div>
        )}

        {successMsg && (
          <div className="admin-alert admin-alert-success">
            <CheckCircle size={16} />
            <span>{successMsg}</span>
          </div>
        )}

        {/* Tab 1: User List */}
        {activeTab === 'list' && (
          <div className="admin-tab-content">
            <div className="admin-list-actions">
              <span className="admin-list-summary">
                Showing {users.length} registered {users.length === 1 ? 'account' : 'accounts'}
              </span>
              <button className="admin-refresh-btn" onClick={fetchUsers} disabled={isLoading} title="Refresh list">
                <RefreshCw size={14} className={isLoading ? 'spinning' : ''} />
                <span>Refresh</span>
              </button>
            </div>

            <div className="admin-table-wrapper">
              <table className="admin-users-table">
                <thead>
                  <tr>
                    <th>User</th>
                    <th>Role</th>
                    <th>Created Date</th>
                    <th>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {users.length === 0 ? (
                    <tr>
                      <td colSpan={4} className="admin-table-empty">
                        {isLoading ? 'Loading users...' : 'No users found.'}
                      </td>
                    </tr>
                  ) : (
                    users.map((u) => {
                      const isSelf = u.id === currentUser?.id || u.username === currentUser?.username;
                      return (
                        <tr key={u.id} className="admin-user-row">
                          <td>
                            <div className="admin-user-cell">
                              <div className="admin-avatar">
                                {u.role === 'admin' ? <Shield size={14} /> : <User size={14} />}
                              </div>
                              <div className="admin-user-info">
                                <span className="admin-username">{u.username}</span>
                                {isSelf && <span className="admin-self-badge">(You)</span>}
                              </div>
                            </div>
                          </td>
                          <td>
                            <span className={`admin-role-badge role-${u.role}`}>
                              {u.role.toUpperCase()}
                            </span>
                          </td>
                          <td className="admin-date-cell">
                            {new Date(u.created_at).toLocaleDateString(undefined, {
                              year: 'numeric',
                              month: 'short',
                              day: '2-digit',
                              hour: '2-digit',
                              minute: '2-digit'
                            })}
                          </td>
                          <td>
                            <button
                              className="admin-delete-btn"
                              disabled={isSelf || isLoading}
                              title={isSelf ? "You cannot delete your own account" : `Delete ${u.username}`}
                              onClick={() => setDeletingUser(u)}
                            >
                              <Trash2 size={15} />
                              <span>Delete</span>
                            </button>
                          </td>
                        </tr>
                      );
                    })
                  )}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* Tab 2: Create User Form */}
        {activeTab === 'create' && (
          <div className="admin-tab-content">
            <form onSubmit={handleCreateUser} className="admin-create-form">
              <div className="admin-form-group">
                <label>Username</label>
                <div className="admin-input-box">
                  <User size={16} className="admin-box-icon" />
                  <input
                    type="text"
                    placeholder="e.g. analyst_john"
                    value={newUsername}
                    onChange={(e) => setNewUsername(e.target.value)}
                    required
                    minLength={3}
                  />
                </div>
                <span className="admin-help-text">Minimum 3 characters, letters and numbers.</span>
              </div>

              <div className="admin-form-group">
                <label>Password</label>
                <div className="admin-input-box">
                  <Key size={16} className="admin-box-icon" />
                  <input
                    type="password"
                    placeholder="Enter secure password"
                    value={newPassword}
                    onChange={(e) => setNewPassword(e.target.value)}
                    required
                    minLength={6}
                  />
                </div>
                <span className="admin-help-text">Minimum 6 characters.</span>
              </div>

              <div className="admin-form-group">
                <label>Role Assignment</label>
                <div className="admin-role-options">
                  <label className={`admin-role-card ${newRole === 'user' ? 'selected' : ''}`}>
                    <input
                      type="radio"
                      name="role"
                      value="user"
                      checked={newRole === 'user'}
                      onChange={() => setNewRole('user')}
                    />
                    <div className="role-card-inner">
                      <div className="role-card-header">
                        <User size={16} />
                        <strong>User (Analyst)</strong>
                      </div>
                      <p>Can query Wazuh SIEM, inspect security logs, and use the AI ChatBot. Cannot manage users.</p>
                    </div>
                  </label>

                  <label className={`admin-role-card ${newRole === 'admin' ? 'selected' : ''}`}>
                    <input
                      type="radio"
                      name="role"
                      value="admin"
                      checked={newRole === 'admin'}
                      onChange={() => setNewRole('admin')}
                    />
                    <div className="role-card-inner">
                      <div className="role-card-header">
                        <Shield size={16} />
                        <strong>Administrator</strong>
                      </div>
                      <p>Full system access + User Management (create and delete user and admin accounts).</p>
                    </div>
                  </label>
                </div>
              </div>

              <div className="admin-form-actions">
                <button
                  type="button"
                  className="admin-cancel-btn"
                  onClick={() => setActiveTab('list')}
                  disabled={isSubmitting}
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="admin-submit-btn"
                  disabled={isSubmitting || !newUsername.trim() || !newPassword}
                >
                  <UserPlus size={16} />
                  <span>{isSubmitting ? 'Creating Account...' : 'Create Account'}</span>
                </button>
              </div>
            </form>
          </div>
        )}

        {/* Delete Confirmation Modal */}
        <AnimatePresence>
          {deletingUser && (
            <motion.div
              className="admin-confirm-overlay"
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
            >
              <div className="admin-confirm-box glass">
                <div className="admin-confirm-icon">
                  <Trash2 size={24} />
                </div>
                <h3>Delete User Account?</h3>
                <p>
                  Are you sure you want to permanently delete user <strong>{deletingUser.username}</strong> ({deletingUser.role})?
                  This action will also remove all associated chat sessions and cannot be undone.
                </p>
                <div className="admin-confirm-actions">
                  <button
                    className="admin-confirm-cancel"
                    onClick={() => setDeletingUser(null)}
                    disabled={isLoading}
                  >
                    Cancel
                  </button>
                  <button
                    className="admin-confirm-delete"
                    onClick={() => handleDeleteUser(deletingUser)}
                    disabled={isLoading}
                  >
                    {isLoading ? 'Deleting...' : 'Yes, Delete User'}
                  </button>
                </div>
              </div>
            </motion.div>
          )}
        </AnimatePresence>
      </motion.div>
    </div>
  );
}
