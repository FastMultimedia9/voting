// src/components/AdminPanel/AddUserModal.jsx
import React, { useState } from 'react';
import { FaUserPlus, FaTimes, FaUser, FaEnvelope, FaKey, FaUserTag } from 'react-icons/fa';

const AddUserModal = ({ isOpen, onClose, onUserAdded }) => {
  const [formData, setFormData] = useState({
    username: '',
    email: '',
    password: '',
    fullName: '',
    role: 'voter',
    status: 'active',
    isVerified: true
  });
  
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    setSuccess('');
    setLoading(true);

    try {
      const token = localStorage.getItem('adminToken') || localStorage.getItem('token');
      
      // Try the new admin endpoint first, fall back to auth register
      let endpoint = 'http://localhost:5000/api/admin/users';
      
      const response = await fetch(endpoint, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify({
          username: formData.username,
          email: formData.email,
          password: formData.password || 'TempPassword123',
          fullName: formData.fullName,
          role: formData.role,
          status: formData.status,
          isVerified: formData.isVerified
        })
      });

      const result = await response.json();

      if (result.success) {
        setSuccess(`User "${formData.fullName}" added successfully!`);
        setFormData({
          username: '',
          email: '',
          password: '',
          fullName: '',
          role: 'voter',
          status: 'active',
          isVerified: true
        });
        
        if (onUserAdded) {
          onUserAdded(result.user);
        }
        
        // Auto-close after 2 seconds
        setTimeout(() => {
          onClose();
        }, 2000);
      } else {
        setError(result.error || 'Failed to add user');
      }
    } catch (err) {
      setError('Error connecting to server. Please check if the admin endpoint exists.');
      console.error('Add user error:', err);
    } finally {
      setLoading(false);
    }
  };

  if (!isOpen) return null;

  return (
    <div className="modal-overlay">
      <div className="modal">
        <div className="modal-header">
          <h3><FaUserPlus /> Add New User</h3>
          <button className="icon-button" onClick={onClose}>
            <FaTimes />
          </button>
        </div>

        <form onSubmit={handleSubmit}>
          <div className="modal-content">
            {error && <div className="error-message">{error}</div>}
            {success && <div className="success-message">{success}</div>}

            <div className="form-group">
              <label><FaUser /> Username *</label>
              <input
                type="text"
                value={formData.username}
                onChange={(e) => setFormData({...formData, username: e.target.value})}
                required
                placeholder="johndoe"
                disabled={loading}
              />
            </div>

            <div className="form-group">
              <label><FaEnvelope /> Email *</label>
              <input
                type="email"
                value={formData.email}
                onChange={(e) => setFormData({...formData, email: e.target.value})}
                required
                placeholder="john@example.com"
                disabled={loading}
              />
            </div>

            <div className="form-group">
              <label>Full Name *</label>
              <input
                type="text"
                value={formData.fullName}
                onChange={(e) => setFormData({...formData, fullName: e.target.value})}
                required
                placeholder="John Doe"
                disabled={loading}
              />
            </div>

            <div className="form-group">
              <label><FaKey /> Password</label>
              <input
                type="password"
                value={formData.password}
                onChange={(e) => setFormData({...formData, password: e.target.value})}
                placeholder="Leave blank for auto-generate"
                disabled={loading}
              />
              <small>If blank, system will generate temporary password: TempPassword123</small>
            </div>

            <div className="form-row">
              <div className="form-group">
                <label><FaUserTag /> Role *</label>
                <select
                  value={formData.role}
                  onChange={(e) => setFormData({...formData, role: e.target.value})}
                  disabled={loading}
                >
                  <option value="voter">Voter</option>
                  <option value="candidate">Candidate</option>
                  <option value="admin">Administrator</option>
                  <option value="auditor">Auditor</option>
                </select>
              </div>
              <div className="form-group">
                <label>Status *</label>
                <select
                  value={formData.status}
                  onChange={(e) => setFormData({...formData, status: e.target.value})}
                  disabled={loading}
                >
                  <option value="active">Active</option>
                  <option value="pending">Pending</option>
                  <option value="suspended">Suspended</option>
                  <option value="inactive">Inactive</option>
                </select>
              </div>
            </div>

            <div className="form-group">
              <label className="checkbox-label">
                <input
                  type="checkbox"
                  checked={formData.isVerified}
                  onChange={(e) => setFormData({...formData, isVerified: e.target.checked})}
                  disabled={loading}
                />
                <span>Email Verified</span>
              </label>
            </div>
          </div>

          <div className="modal-footer">
            <button type="button" className="secondary-button" onClick={onClose} disabled={loading}>
              Cancel
            </button>
            <button type="submit" className="primary-button" disabled={loading}>
              {loading ? (
                <>
                  <span className="spinner"></span> Adding...
                </>
              ) : (
                'Add User'
              )}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};

export default AddUserModal;