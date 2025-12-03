import React, { useState } from 'react';
import './AdminPage.css';

const AdminPage = () => {
  const [activeTab, setActiveTab] = useState('dashboard');
  
  const tabs = [
    { id: 'dashboard', label: 'Dashboard', icon: '📊' },
    { id: 'candidates', label: 'Candidates', icon: '👥' },
    { id: 'voters', label: 'Voters', icon: '👤' },
    { id: 'settings', label: 'Settings', icon: '⚙️' },
  ];

  return (
    <div className="admin-page">
      <div className="admin-header">
        <h1>Admin Dashboard</h1>
        <p className="admin-subtitle">Manage your voting system</p>
      </div>

      <div className="admin-layout">
        <div className="admin-sidebar">
          <div className="admin-profile">
            <div className="profile-avatar">A</div>
            <div className="profile-info">
              <h4>Admin User</h4>
              <span className="profile-role">Administrator</span>
            </div>
          </div>
          
          <nav className="admin-nav">
            {tabs.map(tab => (
              <button
                key={tab.id}
                className={`nav-item ${activeTab === tab.id ? 'active' : ''}`}
                onClick={() => setActiveTab(tab.id)}
              >
                <span className="nav-icon">{tab.icon}</span>
                <span className="nav-label">{tab.label}</span>
              </button>
            ))}
          </nav>
        </div>

        <div className="admin-content">
          {activeTab === 'dashboard' && (
            <div className="tab-content">
              <h2>Dashboard Overview</h2>
              <div className="stats-grid">
                <div className="stat-card">
                  <div className="stat-icon">👥</div>
                  <div className="stat-details">
                    <h3>4</h3>
                    <p>Total Candidates</p>
                  </div>
                </div>
                <div className="stat-card">
                  <div className="stat-icon">🗳️</div>
                  <div className="stat-details">
                    <h3>254</h3>
                    <p>Total Votes</p>
                  </div>
                </div>
                <div className="stat-card">
                  <div className="stat-icon">📈</div>
                  <div className="stat-details">
                    <h3>78%</h3>
                    <p>Voter Turnout</p>
                  </div>
                </div>
                <div className="stat-card">
                  <div className="stat-icon">⏰</div>
                  <div className="stat-details">
                    <h3>24h</h3>
                    <p>Voting Active</p>
                  </div>
                </div>
              </div>
            </div>
          )}

          {activeTab === 'candidates' && (
            <div className="tab-content">
              <h2>Manage Candidates</h2>
              <div className="candidate-management">
                <div className="add-candidate-form">
                  <h3>Add New Candidate</h3>
                  <form>
                    <div className="form-row">
                      <div className="form-group">
                        <label>Full Name</label>
                        <input type="text" placeholder="Enter candidate name" />
                      </div>
                      <div className="form-group">
                        <label>Position</label>
                        <select>
                          <option value="President">President</option>
                          <option value="Vice President">Vice President</option>
                          <option value="Secretary">Secretary</option>
                        </select>
                      </div>
                    </div>
                    <div className="form-row">
                      <div className="form-group">
                        <label>Party</label>
                        <input type="text" placeholder="Enter party name" />
                      </div>
                      <div className="form-group">
                        <label>Email</label>
                        <input type="email" placeholder="Enter email address" />
                      </div>
                    </div>
                    <button type="submit" className="btn btn-primary">Add Candidate</button>
                  </form>
                </div>
              </div>
            </div>
          )}

          {activeTab === 'settings' && (
            <div className="tab-content">
              <h2>System Settings</h2>
              <div className="settings-grid">
                <div className="setting-card">
                  <h3>Voting Controls</h3>
                  <div className="setting-item">
                    <span>Start Voting</span>
                    <button className="btn btn-success">Start</button>
                  </div>
                  <div className="setting-item">
                    <span>Stop Voting</span>
                    <button className="btn btn-danger">Stop</button>
                  </div>
                  <div className="setting-item">
                    <span>Reset All Votes</span>
                    <button className="btn btn-warning">Reset</button>
                  </div>
                </div>
                <div className="setting-card">
                  <h3>System Status</h3>
                  <div className="status-item">
                    <span>Voting Status</span>
                    <span className="status-badge active">Active</span>
                  </div>
                  <div className="status-item">
                    <span>Database</span>
                    <span className="status-badge online">Online</span>
                  </div>
                  <div className="status-item">
                    <span>Security</span>
                    <span className="status-badge secure">Secure</span>
                  </div>
                </div>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default AdminPage;