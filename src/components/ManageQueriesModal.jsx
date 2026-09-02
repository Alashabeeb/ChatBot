import { useState, useEffect } from 'react';
import { X, Plus, Edit2, Trash2, Check, AlertCircle } from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';
import './ManageQueriesModal.css';

export default function ManageQueriesModal({ isOpen, onClose, queries, fetchQueries }) {
  const [editingId, setEditingId] = useState(null);
  const [editLabel, setEditLabel] = useState('');
  const [editPrompt, setEditPrompt] = useState('');
  
  const [isAdding, setIsAdding] = useState(false);
  const [newLabel, setNewLabel] = useState('');
  const [newPrompt, setNewPrompt] = useState('');
  
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState('');

  // Reset state when modal opens/closes
  useEffect(() => {
    if (isOpen) {
      setEditingId(null);
      setIsAdding(false);
      setError('');
    }
  }, [isOpen]);

  const getAuthHeaders = () => {
    const token = localStorage.getItem('soc_auth_token');
    return {
      'Content-Type': 'application/json',
      ...(token ? { 'Authorization': `Bearer ${token}` } : {})
    };
  };

  const handleAdd = async (e) => {
    e.preventDefault();
    if (!newLabel.trim() || !newPrompt.trim()) return;
    
    setIsLoading(true);
    setError('');

    try {
      const API_URL = window.location.hostname === 'localhost' 
        ? 'http://localhost:3002/api/queries' 
        : `http://${window.location.hostname}:3002/api/queries`;
        
      const res = await fetch(API_URL, {
        method: 'POST',
        headers: getAuthHeaders(),
        body: JSON.stringify({ label: newLabel, prompt: newPrompt })
      });
      
      const data = await res.json();
      if (!data.success) throw new Error(data.error);
      
      await fetchQueries();
      setIsAdding(false);
      setNewLabel('');
      setNewPrompt('');
    } catch (err) {
      setError(err.message || 'Failed to add query');
    } finally {
      setIsLoading(false);
    }
  };

  const handleSaveEdit = async (e, id) => {
    e.preventDefault();
    if (!editLabel.trim() || !editPrompt.trim()) return;
    
    setIsLoading(true);
    setError('');

    try {
      const API_URL = window.location.hostname === 'localhost' 
        ? `http://localhost:3002/api/queries/${id}` 
        : `http://${window.location.hostname}:3002/api/queries/${id}`;
        
      const res = await fetch(API_URL, {
        method: 'PUT',
        headers: getAuthHeaders(),
        body: JSON.stringify({ label: editLabel, prompt: editPrompt })
      });
      
      const data = await res.json();
      if (!data.success) throw new Error(data.error);
      
      await fetchQueries();
      setEditingId(null);
    } catch (err) {
      setError(err.message || 'Failed to update query');
    } finally {
      setIsLoading(false);
    }
  };

  const handleDelete = async (id) => {
    if (!confirm('Are you sure you want to delete this query?')) return;
    
    setIsLoading(true);
    setError('');

    try {
      const API_URL = window.location.hostname === 'localhost' 
        ? `http://localhost:3002/api/queries/${id}` 
        : `http://${window.location.hostname}:3002/api/queries/${id}`;
        
      const res = await fetch(API_URL, {
        method: 'DELETE',
        headers: getAuthHeaders()
      });
      
      const data = await res.json();
      if (!data.success) throw new Error(data.error);
      
      await fetchQueries();
    } catch (err) {
      setError(err.message || 'Failed to delete query');
    } finally {
      setIsLoading(false);
    }
  };

  const startEditing = (q) => {
    setEditingId(q.id);
    setEditLabel(q.label);
    setEditPrompt(q.prompt);
    setIsAdding(false);
  };

  if (!isOpen) return null;

  return (
    <div className="queries-modal-overlay" onClick={onClose}>
      <motion.div 
        className="queries-modal-content"
        onClick={(e) => e.stopPropagation()}
        initial={{ opacity: 0, scale: 0.95, y: 10 }}
        animate={{ opacity: 1, scale: 1, y: 0 }}
        exit={{ opacity: 0, scale: 0.95, y: 10 }}
        transition={{ duration: 0.2 }}
      >
        <div className="queries-modal-header">
          <h2>Manage Quick Queries</h2>
          <button className="icon-btn close-btn" onClick={onClose}>
            <X size={18} />
          </button>
        </div>

        <div className="queries-modal-body">
          {error && (
            <div className="queries-error">
              <AlertCircle size={14} />
              <span>{error}</span>
            </div>
          )}

          {!isAdding && (
            <button className="add-query-btn" onClick={() => setIsAdding(true)}>
              <Plus size={16} />
              <span>Add New Query</span>
            </button>
          )}

          {isAdding && (
            <form className="query-edit-form new-query-form" onSubmit={handleAdd}>
              <div className="input-group">
                <label>Label</label>
                <input 
                  type="text" 
                  value={newLabel} 
                  onChange={(e) => setNewLabel(e.target.value)} 
                  placeholder="e.g. Find failed logins" 
                  maxLength={50}
                  autoFocus
                  required 
                />
              </div>
              <div className="input-group">
                <label>Prompt</label>
                <textarea 
                  value={newPrompt} 
                  onChange={(e) => setNewPrompt(e.target.value)} 
                  placeholder="The actual prompt text sent to the LLM..."
                  rows={3}
                  required 
                />
              </div>
              <div className="form-actions">
                <button type="button" className="btn-cancel" onClick={() => setIsAdding(false)}>Cancel</button>
                <button type="submit" className="btn-save" disabled={isLoading}>
                  {isLoading ? 'Saving...' : 'Add Query'}
                </button>
              </div>
            </form>
          )}

          <div className="queries-list">
            {queries.map((q) => (
              <div key={q.id} className="query-item-container">
                {editingId === q.id ? (
                  <form className="query-edit-form" onSubmit={(e) => handleSaveEdit(e, q.id)}>
                    <div className="input-group">
                      <label>Label</label>
                      <input 
                        type="text" 
                        value={editLabel} 
                        onChange={(e) => setEditLabel(e.target.value)} 
                        required 
                      />
                    </div>
                    <div className="input-group">
                      <label>Prompt</label>
                      <textarea 
                        value={editPrompt} 
                        onChange={(e) => setEditPrompt(e.target.value)} 
                        rows={2}
                        required 
                      />
                    </div>
                    <div className="form-actions">
                      <button type="button" className="btn-cancel" onClick={() => setEditingId(null)}>Cancel</button>
                      <button type="submit" className="btn-save" disabled={isLoading}>Save</button>
                    </div>
                  </form>
                ) : (
                  <div className="query-item">
                    <div className="query-item-info">
                      <span className="query-label">{q.label}</span>
                      <span className="query-prompt">{q.prompt}</span>
                    </div>
                    <div className="query-item-actions">
                      <button 
                        className="icon-btn edit-btn" 
                        onClick={() => startEditing(q)}
                        title="Edit Query"
                      >
                        <Edit2 size={14} />
                      </button>
                      <button 
                        className="icon-btn delete-btn" 
                        onClick={() => handleDelete(q.id)}
                        title="Delete Query"
                      >
                        <Trash2 size={14} />
                      </button>
                    </div>
                  </div>
                )}
              </div>
            ))}
            
            {queries.length === 0 && !isAdding && (
              <div className="no-queries">
                <p>You haven't created any custom quick queries yet.</p>
              </div>
            )}
          </div>
        </div>
      </motion.div>
    </div>
  );
}
