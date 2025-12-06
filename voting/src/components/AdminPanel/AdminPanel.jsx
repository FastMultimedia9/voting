// AdminPanel.jsx - FULL FIXED CODE
import React, { useState, useEffect } from 'react';
import './AdminPanel.css';
import AddUserModal from './AddUserModal';

// Import icons
import {
  FaTachometerAlt,
  FaUsers,
  FaVoteYea,
  FaChartBar,
  FaCog,
  FaSignOutAlt,
  FaBell,
  FaUserCircle,
  FaSearch,
  FaFilter,
  FaEdit,
  FaTrash,
  FaEye,
  FaDownload,
  FaUserTie,
  FaUserPlus,
  FaPlus,
  FaTimes,
  FaCheck,
  FaUpload,
  FaSpinner,
  FaExclamationTriangle,
  FaCheckCircle,
  FaTimesCircle,
  FaUserCheck,
  FaUserTimes,
  FaUserSlash,
  FaCalendarAlt,
  FaChartLine,
  FaFileExport,
  FaCrown,
  FaPoll,
  FaIdCard,
  FaDatabase,
  FaShieldAlt,
  FaHistory
} from 'react-icons/fa';

// API service functions
const API_BASE_URL = 'http://localhost:5000/api';

const apiService = {
  // Authentication
  logout: async (token) => {
    const response = await fetch(`${API_BASE_URL}/auth/logout`, {
      method: 'POST',
      headers: { 
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${token}`
      }
    });
    return response.json();
  },

  // Dashboard
  getDashboardStats: async (token) => {
    const response = await fetch(`${API_BASE_URL}/admin/dashboard/stats`, {
      headers: { 'Authorization': `Bearer ${token}` }
    });
    return response.json();
  },

  getRecentActivity: async (token) => {
    const response = await fetch(`${API_BASE_URL}/admin/recent-activity`, {
      headers: { 'Authorization': `Bearer ${token}` }
    });
    return response.json();
  },

  getActiveElections: async (token) => {
    const response = await fetch(`${API_BASE_URL}/admin/active-elections`, {
      headers: { 'Authorization': `Bearer ${token}` }
    });
    return response.json();
  },

  // Elections
  getAllElections: async (token, params = {}) => {
    const queryString = new URLSearchParams(params).toString();
    const response = await fetch(`${API_BASE_URL}/admin/elections?${queryString}`, {
      headers: { 'Authorization': `Bearer ${token}` }
    });
    return response.json();
  },

  getElectionDetails: async (token, electionId) => {
    const response = await fetch(`${API_BASE_URL}/admin/elections/${electionId}/details`, {
      headers: { 'Authorization': `Bearer ${token}` }
    });
    return response.json();
  },

  createElection: async (token, electionData) => {
    const response = await fetch(`${API_BASE_URL}/admin/elections`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${token}`
      },
      body: JSON.stringify(electionData)
    });
    return response.json();
  },

  updateElection: async (token, electionId, updateData) => {
    const response = await fetch(`${API_BASE_URL}/admin/elections/${electionId}`, {
      method: 'PUT',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${token}`
      },
      body: JSON.stringify(updateData)
    });
    return response.json();
  },

  deleteElection: async (token, electionId) => {
    const response = await fetch(`${API_BASE_URL}/admin/elections/${electionId}`, {
      method: 'DELETE',
      headers: { 'Authorization': `Bearer ${token}` }
    });
    return response.json();
  },

  // Candidates
  getAllCandidates: async (token, params = {}) => {
    const queryString = new URLSearchParams(params).toString();
    const response = await fetch(`${API_BASE_URL}/admin/candidates?${queryString}`, {
      headers: { 'Authorization': `Bearer ${token}` }
    });
    return response.json();
  },

  createCandidate: async (token, candidateData) => {
    const response = await fetch(`${API_BASE_URL}/admin/candidates`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${token}`
      },
      body: JSON.stringify(candidateData)
    });
    return response.json();
  },

  updateCandidate: async (token, candidateId, updateData) => {
    const response = await fetch(`${API_BASE_URL}/admin/candidates/${candidateId}`, {
      method: 'PUT',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${token}`
      },
      body: JSON.stringify(updateData)
    });
    return response.json();
  },

  deleteCandidate: async (token, candidateId) => {
    const response = await fetch(`${API_BASE_URL}/admin/candidates/${candidateId}`, {
      method: 'DELETE',
      headers: { 'Authorization': `Bearer ${token}` }
    });
    return response.json();
  },

  // Voters
  getAllVoters: async (token, params = {}) => {
    const queryString = new URLSearchParams(params).toString();
    const response = await fetch(`${API_BASE_URL}/admin/voters?${queryString}`, {
      headers: { 'Authorization': `Bearer ${token}` }
    });
    return response.json();
  },

  updateVoterStatus: async (token, voterId, statusData) => {
    const response = await fetch(`${API_BASE_URL}/admin/voters/${voterId}/status`, {
      method: 'PUT',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${token}`
      },
      body: JSON.stringify(statusData)
    });
    return response.json();
  },

  updateVoterRegistration: async (token, registrationId, statusData) => {
    const response = await fetch(`${API_BASE_URL}/admin/voter-registrations/${registrationId}`, {
      method: 'PUT',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${token}`
      },
      body: JSON.stringify(statusData)
    });
    return response.json();
  },

  // Reports
  getElectionResultsReport: async (token, electionId) => {
    const response = await fetch(`${API_BASE_URL}/admin/reports/election-results/${electionId}`, {
      headers: { 'Authorization': `Bearer ${token}` }
    });
    return response.json();
  },

  getAllReports: async (token) => {
    const response = await fetch(`${API_BASE_URL}/admin/reports`, {
      headers: { 'Authorization': `Bearer ${token}` }
    });
    return response.json();
  },

  // Settings
  getSystemSettings: async (token) => {
    const response = await fetch(`${API_BASE_URL}/admin/settings`, {
      headers: { 'Authorization': `Bearer ${token}` }
    });
    return response.json();
  },

  updateSystemSetting: async (token, settingKey, settingValue) => {
    const response = await fetch(`${API_BASE_URL}/admin/settings/${settingKey}`, {
      method: 'PUT',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${token}`
      },
      body: JSON.stringify({ settingValue })
    });
    return response.json();
  },

  // Notifications
  getNotifications: async (token, unreadOnly = false) => {
    const response = await fetch(`${API_BASE_URL}/admin/notifications?unreadOnly=${unreadOnly}`, {
      headers: { 'Authorization': `Bearer ${token}` }
    });
    return response.json();
  },

  markNotificationAsRead: async (token, notificationId) => {
    const response = await fetch(`${API_BASE_URL}/admin/notifications/${notificationId}/read`, {
      method: 'PUT',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${token}`
      }
    });
    return response.json();
  },

  markAllNotificationsAsRead: async (token) => {
    const response = await fetch(`${API_BASE_URL}/admin/notifications/mark-all-read`, {
      method: 'PUT',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${token}`
      }
    });
    return response.json();
  },

  // Audit Logs
  getAuditLogs: async (token, params = {}) => {
    const queryString = new URLSearchParams(params).toString();
    const response = await fetch(`${API_BASE_URL}/admin/audit-logs?${queryString}`, {
      headers: { 'Authorization': `Bearer ${token}` }
    });
    return response.json();
  },

  getSecurityLogs: async (token, params = {}) => {
    const queryString = new URLSearchParams(params).toString();
    const response = await fetch(`${API_BASE_URL}/admin/security-logs?${queryString}`, {
      headers: { 'Authorization': `Bearer ${token}` }
    });
    return response.json();
  },

  // Utility
  getElectionPositions: async (token, electionId) => {
    const response = await fetch(`${API_BASE_URL}/admin/elections/${electionId}/positions`, {
      headers: { 'Authorization': `Bearer ${token}` }
    });
    return response.json();
  },

  getAdminProfile: async (token) => {
    const response = await fetch(`${API_BASE_URL}/admin/profile`, {
      headers: { 'Authorization': `Bearer ${token}` }
    });
    return response.json();
  },

  updateAdminProfile: async (token, profileData) => {
    const response = await fetch(`${API_BASE_URL}/admin/profile`, {
      method: 'PUT',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${token}`
      },
      body: JSON.stringify(profileData)
    });
    return response.json();
  },

  // Health
  getSystemHealth: async (token) => {
    const response = await fetch(`${API_BASE_URL}/admin/health`, {
      headers: { 'Authorization': `Bearer ${token}` }
    });
    return response.json();
  }
};

const AdminPanel = () => {
  // State for authentication
  const [authToken, setAuthToken] = useState('');
  const [adminInfo, setAdminInfo] = useState(null);

  // State for the active tab
  const [activeTab, setActiveTab] = useState('dashboard');
  
  // State for loading
  const [loading, setLoading] = useState({
    dashboard: false,
    elections: false,
    voters: false,
    candidates: false,
    results: false,
    settings: false
  });

  // State for data
  const [dashboardStats, setDashboardStats] = useState(null);
  const [recentActivity, setRecentActivity] = useState([]);
  const [elections, setElections] = useState([]);
  const [voters, setVoters] = useState([]);
  const [candidates, setCandidates] = useState([]);
  const [reports, setReports] = useState([]);
  const [notifications, setNotifications] = useState([]);
  const [systemSettings, setSystemSettings] = useState({});
  const [auditLogs, setAuditLogs] = useState([]);
  const [securityLogs, setSecurityLogs] = useState([]);

  // State for filters and search
  const [electionFilter, setElectionFilter] = useState('all');
  const [candidateFilter, setCandidateFilter] = useState('all');
  const [voterFilter, setVoterFilter] = useState('all');
  const [searchTerm, setSearchTerm] = useState('');

  // State for modals - ADD THE MISSING STATE HERE
  const [showAddElectionModal, setShowAddElectionModal] = useState(false);
  const [showAddCandidateModal, setShowAddCandidateModal] = useState(false);
  const [showEditElectionModal, setShowEditElectionModal] = useState(false);
  const [showEditCandidateModal, setShowEditCandidateModal] = useState(false);
  const [showViewReportModal, setShowViewReportModal] = useState(false);
  const [showConfirmModal, setShowConfirmModal] = useState(false);
  const [showAddUserModal, setShowAddUserModal] = useState(false); // ADD THIS LINE

  // State for forms
  const [newElection, setNewElection] = useState({
    electionName: '',
    description: '',
    startDate: '',
    endDate: '',
    isSecretBallot: true,
    resultsVisible: 'after_election',
    allowWriteIns: false,
    minVotesPerVoter: 1,
    maxVotesPerVoter: 1
  });

  const [newCandidate, setNewCandidate] = useState({
    positionId: '',
    candidateName: '',
    candidateParty: '',
    biography: '',
    manifesto: '',
    contactEmail: '',
    contactPhone: '',
    websiteUrl: '',
    socialMedia: {}
  });

  const [selectedElection, setSelectedElection] = useState(null);
  const [selectedCandidate, setSelectedCandidate] = useState(null);
  const [selectedReport, setSelectedReport] = useState(null);
  const [confirmAction, setConfirmAction] = useState({ type: '', data: null });

  // Load initial data on component mount
  useEffect(() => {
    const token = localStorage.getItem('adminToken') || localStorage.getItem('token');
    const savedAdminInfo = localStorage.getItem('adminInfo') || localStorage.getItem('user');
    
    if (token && savedAdminInfo) {
      try {
        const adminInfo = JSON.parse(savedAdminInfo);
        // Check if user is actually an admin
        if (adminInfo.role !== 'admin') {
          // Not an admin, redirect to login
          window.location.href = '/login';
          return;
        }
        
        setAuthToken(token);
        setAdminInfo(adminInfo);
        loadInitialData(token);
      } catch (error) {
        console.error('Error parsing admin info:', error);
        window.location.href = '/login';
      }
    } else {
      // Redirect to login if no token found
      window.location.href = '/login';
    }
  }, []);

  // Load data based on active tab
  useEffect(() => {
    if (authToken) {
      loadTabData(activeTab);
    }
  }, [activeTab, authToken]);

  // Load initial data
  const loadInitialData = async (token) => {
    try {
      // Load dashboard stats
      const statsResult = await apiService.getDashboardStats(token);
      if (statsResult.success) {
        setDashboardStats(statsResult.stats);
      }

      // Load recent activity
      const activityResult = await apiService.getRecentActivity(token);
      if (activityResult.success) {
        setRecentActivity(activityResult.activities);
      }

      // Load notifications
      const notificationsResult = await apiService.getNotifications(token);
      if (notificationsResult.success) {
        setNotifications(notificationsResult.notifications);
      }

      // Load admin profile
      const profileResult = await apiService.getAdminProfile(token);
      if (profileResult.success) {
        setAdminInfo(profileResult.admin);
      }
    } catch (error) {
      console.error('Error loading initial data:', error);
      // If token is invalid, redirect to login
      if (error.message.includes('401') || error.message.includes('403')) {
        handleLogout();
      }
    }
  };

  const loadTabData = async (tab) => {
    if (!authToken) return;

    setLoading(prev => ({ ...prev, [tab]: true }));

    try {
      switch (tab) {
        case 'dashboard':
          await loadDashboardData();
          break;
        case 'elections':
          await loadElectionsData();
          break;
        case 'candidates':
          await loadCandidatesData();
          break;
        case 'voters':
          await loadVotersData();
          break;
        case 'results':
          await loadReportsData();
          break;
        case 'settings':
          await loadSettingsData();
          break;
        case 'audit':
          await loadAuditLogs();
          break;
        case 'security':
          await loadSecurityLogs();
          break;
      }
    } catch (error) {
      console.error(`Error loading ${tab} data:`, error);
    } finally {
      setLoading(prev => ({ ...prev, [tab]: false }));
    }
  };

  const loadDashboardData = async () => {
    const [statsResult, activityResult, electionsResult] = await Promise.all([
      apiService.getDashboardStats(authToken),
      apiService.getRecentActivity(authToken),
      apiService.getAllElections(authToken, { status: 'active' })
    ]);

    if (statsResult.success) setDashboardStats(statsResult.stats);
    if (activityResult.success) setRecentActivity(activityResult.activities);
    if (electionsResult.success) setElections(electionsResult.elections);
  };

  const loadElectionsData = async () => {
    const result = await apiService.getAllElections(authToken, { 
      status: electionFilter !== 'all' ? electionFilter : undefined,
      search: searchTerm || undefined
    });
    if (result.success) setElections(result.elections);
  };

  const loadCandidatesData = async () => {
    const result = await apiService.getAllCandidates(authToken, { 
      status: candidateFilter !== 'all' ? candidateFilter : undefined,
      electionId: 'all',
      search: searchTerm || undefined
    });
    if (result.success) setCandidates(result.candidates);
  };

  const loadVotersData = async () => {
    const result = await apiService.getAllVoters(authToken, { 
      status: voterFilter !== 'all' ? voterFilter : undefined,
      search: searchTerm || undefined
    });
    if (result.success) setVoters(result.voters);
  };

  const loadReportsData = async () => {
    const result = await apiService.getAllReports(authToken);
    if (result.success) setReports(result.reports);
  };

  const loadSettingsData = async () => {
    const result = await apiService.getSystemSettings(authToken);
    if (result.success) setSystemSettings(result.settings);
  };

  const loadAuditLogs = async () => {
    const result = await apiService.getAuditLogs(authToken);
    if (result.success) setAuditLogs(result.logs);
  };

  const loadSecurityLogs = async () => {
    const result = await apiService.getSecurityLogs(authToken);
    if (result.success) setSecurityLogs(result.logs);
  };

  // Handle tab change
  const handleTabChange = (tab) => {
    setActiveTab(tab);
    setSearchTerm('');
  };

  // Handle logout
  const handleLogout = async () => {
    try {
      if (authToken) {
        await apiService.logout(authToken);
      }
    } catch (error) {
      console.error('Logout error:', error);
    } finally {
      localStorage.removeItem('adminToken');
      localStorage.removeItem('adminInfo');
      setAuthToken('');
      setAdminInfo(null);
      window.location.href = '/admin/login';
    }
  };

  // Handle search
  const handleSearch = (e) => {
    setSearchTerm(e.target.value);
    // Debounce search
    setTimeout(() => {
      loadTabData(activeTab);
    }, 300);
  };

  // Handle election actions
  const handleCreateElection = async () => {
    try {
      const result = await apiService.createElection(authToken, newElection);
      if (result.success) {
        alert('Election created successfully!');
        setShowAddElectionModal(false);
        setNewElection({
          electionName: '',
          description: '',
          startDate: '',
          endDate: '',
          isSecretBallot: true,
          resultsVisible: 'after_election',
          allowWriteIns: false,
          minVotesPerVoter: 1,
          maxVotesPerVoter: 1
        });
        loadElectionsData();
      } else {
        alert(`Error: ${result.error}`);
      }
    } catch (error) {
      alert('Failed to create election');
    }
  };

  const handleEditElection = (election) => {
    setSelectedElection(election);
    setShowEditElectionModal(true);
  };

  const handleUpdateElection = async () => {
    if (!selectedElection) return;
    
    try {
      const result = await apiService.updateElection(authToken, selectedElection.election_id, selectedElection);
      if (result.success) {
        alert('Election updated successfully!');
        setShowEditElectionModal(false);
        setSelectedElection(null);
        loadElectionsData();
      } else {
        alert(`Error: ${result.error}`);
      }
    } catch (error) {
      alert('Failed to update election');
    }
  };

  const handleDeleteElection = (electionId) => {
    setConfirmAction({
      type: 'deleteElection',
      data: { electionId }
    });
    setShowConfirmModal(true);
  };

  const confirmDeleteElection = async () => {
    if (confirmAction.type === 'deleteElection') {
      try {
        const result = await apiService.deleteElection(authToken, confirmAction.data.electionId);
        if (result.success) {
          alert('Election deleted successfully!');
          loadElectionsData();
        } else {
          alert(`Error: ${result.error}`);
        }
      } catch (error) {
        alert('Failed to delete election');
      } finally {
        setShowConfirmModal(false);
        setConfirmAction({ type: '', data: null });
      }
    }
  };

  // Handle candidate actions
  const handleCreateCandidate = async () => {
    try {
      const result = await apiService.createCandidate(authToken, newCandidate);
      if (result.success) {
        alert('Candidate added successfully!');
        setShowAddCandidateModal(false);
        setNewCandidate({
          positionId: '',
          candidateName: '',
          candidateParty: '',
          biography: '',
          manifesto: '',
          contactEmail: '',
          contactPhone: '',
          websiteUrl: '',
          socialMedia: {}
        });
        loadCandidatesData();
      } else {
        alert(`Error: ${result.error}`);
      }
    } catch (error) {
      alert('Failed to add candidate');
    }
  };

  const handleApproveCandidate = async (candidateId) => {
    try {
      const result = await apiService.updateCandidate(authToken, candidateId, { is_approved: true });
      if (result.success) {
        alert('Candidate approved successfully!');
        loadCandidatesData();
      } else {
        alert(`Error: ${result.error}`);
      }
    } catch (error) {
      alert('Failed to approve candidate');
    }
  };

  const handleRejectCandidate = async (candidateId) => {
    try {
      const result = await apiService.updateCandidate(authToken, candidateId, { status: 'rejected' });
      if (result.success) {
        alert('Candidate rejected successfully!');
        loadCandidatesData();
      } else {
        alert(`Error: ${result.error}`);
      }
    } catch (error) {
      alert('Failed to reject candidate');
    }
  };

  const handleDeleteCandidate = (candidateId) => {
    setConfirmAction({
      type: 'deleteCandidate',
      data: { candidateId }
    });
    setShowConfirmModal(true);
  };

  const confirmDeleteCandidate = async () => {
    if (confirmAction.type === 'deleteCandidate') {
      try {
        const result = await apiService.deleteCandidate(authToken, confirmAction.data.candidateId);
        if (result.success) {
          alert('Candidate deleted successfully!');
          loadCandidatesData();
        } else {
          alert(`Error: ${result.error}`);
        }
      } catch (error) {
        alert('Failed to delete candidate');
      } finally {
        setShowConfirmModal(false);
        setConfirmAction({ type: '', data: null });
      }
    }
  };

  // Handle voter actions
  const handleUpdateVoterStatus = async (voterId, status) => {
    try {
      const result = await apiService.updateVoterStatus(authToken, voterId, { status });
      if (result.success) {
        alert(`Voter status updated to ${status}`);
        loadVotersData();
      } else {
        alert(`Error: ${result.error}`);
      }
    } catch (error) {
      alert('Failed to update voter status');
    }
  };

  // Handle user addition
  const handleUserAdded = (newUser) => {
    alert(`User ${newUser?.fullName || 'added'} successfully!`);
    loadVotersData(); // Refresh voters list
  };

  // Handle notification actions
  const handleMarkNotificationAsRead = async (notificationId) => {
    try {
      await apiService.markNotificationAsRead(authToken, notificationId);
      setNotifications(notifications.map(n => 
        n.notification_id === notificationId ? { ...n, is_read: true } : n
      ));
    } catch (error) {
      console.error('Failed to mark notification as read:', error);
    }
  };

  const handleMarkAllNotificationsAsRead = async () => {
    try {
      await apiService.markAllNotificationsAsRead(authToken);
      setNotifications(notifications.map(n => ({ ...n, is_read: true })));
    } catch (error) {
      console.error('Failed to mark all notifications as read:', error);
    }
  };

  // Handle settings update
  const handleUpdateSetting = async (settingKey, value) => {
    try {
      const result = await apiService.updateSystemSetting(authToken, settingKey, value);
      if (result.success) {
        alert('Setting updated successfully!');
        loadSettingsData();
      } else {
        alert(`Error: ${result.error}`);
      }
    } catch (error) {
      alert('Failed to update setting');
    }
  };

  // Render loading state
  const renderLoading = () => (
    <div className="loading-container">
      <FaSpinner className="spinner" />
      <p>Loading data...</p>
    </div>
  );

  // Render the dashboard content
  const renderDashboard = () => {
    if (loading.dashboard) return renderLoading();

    return (
      <div className="dashboard-content">
        <h1 className="page-title">Dashboard Overview</h1>
        <p className="page-subtitle">
          Welcome back, {adminInfo?.full_name || 'Administrator'}. Here's what's happening with your voting system.
        </p>
        
        {/* Stats Cards */}
        <div className="stats-container">
          {dashboardStats ? (
            <>
              <div className="stat-card">
                <div className="stat-icon" style={{ backgroundColor: '#4CAF50' }}>
                  <FaVoteYea />
                </div>
                <div className="stat-info">
                  <h3>{dashboardStats.totalElections}</h3>
                  <p>Total Elections</p>
                </div>
                <div className="stat-detail">{dashboardStats.activeElections} Active</div>
              </div>
              
              <div className="stat-card">
                <div className="stat-icon" style={{ backgroundColor: '#2196F3' }}>
                  <FaUsers />
                </div>
                <div className="stat-info">
                  <h3>{dashboardStats.totalVoters}</h3>
                  <p>Verified Voters</p>
                </div>
                <div className="stat-detail">
                  {dashboardStats.pendingVoters} Pending
                </div>
              </div>
              
              <div className="stat-card">
                <div className="stat-icon" style={{ backgroundColor: '#FF9800' }}>
                  <FaUserTie />
                </div>
                <div className="stat-info">
                  <h3>{dashboardStats.totalCandidates}</h3>
                  <p>Candidates</p>
                </div>
                <div className="stat-detail">
                  {dashboardStats.pendingCandidates} Pending Approval
                </div>
              </div>
              
              <div className="stat-card">
                <div className="stat-icon" style={{ backgroundColor: '#9C27B0' }}>
                  <FaChartBar />
                </div>
                <div className="stat-info">
                  <h3>{dashboardStats.systemUptimePercentage}%</h3>
                  <p>System Uptime</p>
                </div>
                <div className="stat-detail">Last 30 days</div>
              </div>
            </>
          ) : (
            <p>Loading statistics...</p>
          )}
        </div>
        
        {/* Recent Activity & Elections */}
        <div className="content-row">
          <div className="content-column">
            <div className="card">
              <div className="card-header">
                <h3>Recent Activity</h3>
                <button className="text-button" onClick={() => handleTabChange('audit')}>
                  View All
                </button>
              </div>
              <div className="card-content">
                {recentActivity.length > 0 ? (
                  <ul className="activity-list">
                    {recentActivity.slice(0, 5).map(activity => (
                      <li key={activity.action_id} className="activity-item">
                        <div className="activity-dot"></div>
                        <div className="activity-details">
                          <p className="activity-action">{activity.action_details}</p>
                          <p className="activity-meta">
                            By {activity.admin_name} • {new Date(activity.created_at).toLocaleString()}
                          </p>
                        </div>
                      </li>
                    ))}
                  </ul>
                ) : (
                  <p className="empty-state-text">No recent activity</p>
                )}
              </div>
            </div>
          </div>
          
          <div className="content-column">
            <div className="card">
              <div className="card-header">
                <h3>Active Elections</h3>
                <button className="text-button" onClick={() => handleTabChange('elections')}>
                  Manage All
                </button>
              </div>
              <div className="card-content">
                {elections.length > 0 ? (
                  <table className="data-table">
                    <thead>
                      <tr>
                        <th>Election Name</th>
                        <th>Status</th>
                        <th>Days Left</th>
                        <th>Actions</th>
                      </tr>
                    </thead>
                    <tbody>
                      {elections.slice(0, 5).map(election => (
                        <tr key={election.election_id}>
                          <td>
                            <strong>{election.election_name}</strong>
                            <small>{new Date(election.start_date).toLocaleDateString()} - {new Date(election.end_date).toLocaleDateString()}</small>
                          </td>
                          <td>
                            <span className={`status-badge status-${election.current_status || election.status}`}>
                              {election.current_status || election.status}
                            </span>
                          </td>
                          <td>{election.days_remaining > 0 ? election.days_remaining : 'Ended'}</td>
                          <td>
                            <div className="table-actions">
                              <button 
                                className="icon-button" 
                                title="View Details"
                                onClick={() => {
                                  setSelectedElection(election);
                                  setShowViewReportModal(true);
                                }}
                              >
                                <FaEye />
                              </button>
                              <button 
                                className="icon-button" 
                                title="Edit"
                                onClick={() => handleEditElection(election)}
                              >
                                <FaEdit />
                              </button>
                            </div>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                ) : (
                  <p className="empty-state-text">No active elections</p>
                )}
              </div>
            </div>
          </div>
        </div>
      </div>
    );
  };
  
  // Render the elections management content
  const renderElections = () => {
    if (loading.elections) return renderLoading();

    return (
      <div className="elections-content">
        <div className="page-header">
          <h1 className="page-title">Election Management</h1>
          <button 
            className="primary-button"
            onClick={() => setShowAddElectionModal(true)}
          >
            <FaPlus /> Create New Election
          </button>
        </div>
        
        <div className="filters-bar">
          <div className="search-box">
            <FaSearch />
            <input 
              type="text" 
              placeholder="Search elections..." 
              value={searchTerm}
              onChange={handleSearch}
            />
          </div>
          <div className="filter-options">
            <select 
              className="dropdown-filter"
              value={electionFilter}
              onChange={(e) => {
                setElectionFilter(e.target.value);
                setTimeout(() => loadElectionsData(), 300);
              }}
            >
              <option value="all">All Status</option>
              <option value="draft">Draft</option>
              <option value="active">Active</option>
              <option value="paused">Paused</option>
              <option value="completed">Completed</option>
              <option value="cancelled">Cancelled</option>
            </select>
          </div>
        </div>
        
        <div className="card">
          <div className="card-content">
            {elections.length > 0 ? (
              <table className="data-table">
                <thead>
                  <tr>
                    <th>Election Name</th>
                    <th>Start Date</th>
                    <th>End Date</th>
                    <th>Status</th>
                    <th>Voters</th>
                    <th>Candidates</th>
                    <th>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {elections.map(election => (
                    <tr key={election.election_id}>
                      <td>
                        <div className="election-name">
                          <strong>{election.election_name}</strong>
                          <small>{election.description}</small>
                        </div>
                      </td>
                      <td>{new Date(election.start_date).toLocaleDateString()}</td>
                      <td>{new Date(election.end_date).toLocaleDateString()}</td>
                      <td>
                        <span className={`status-badge status-${election.status}`}>
                          {election.status}
                        </span>
                      </td>
                      <td>{election.registered_voters || 0}</td>
                      <td>{election.total_candidates || 0}</td>
                      <td>
                        <div className="table-actions">
                          <button 
                            className="icon-button" 
                            title="View Results"
                            onClick={() => {
                              setSelectedElection(election);
                              setShowViewReportModal(true);
                            }}
                          >
                            <FaChartBar />
                          </button>
                          <button 
                            className="icon-button" 
                            title="Edit"
                            onClick={() => handleEditElection(election)}
                          >
                            <FaEdit />
                          </button>
                          <button 
                            className="icon-button" 
                            title="Manage Candidates"
                            onClick={() => {
                              handleTabChange('candidates');
                              setCandidateFilter('all');
                              setSearchTerm(election.election_name);
                            }}
                          >
                            <FaUserTie />
                          </button>
                          <button 
                            className="icon-button delete" 
                            title="Delete"
                            onClick={() => handleDeleteElection(election.election_id)}
                          >
                            <FaTrash />
                          </button>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            ) : (
              <div className="empty-state">
                <FaVoteYea className="empty-icon" />
                <h3>No elections found</h3>
                <p>Create your first election to get started</p>
                <button 
                  className="primary-button"
                  onClick={() => setShowAddElectionModal(true)}
                >
                  <FaPlus /> Create Election
                </button>
              </div>
            )}
          </div>
        </div>
      </div>
    );
  };
  
  // Render the voters management content
  const renderVoters = () => {
    if (loading.voters) return renderLoading();

    const voterStats = {
      verified: voters.filter(v => v.status === 'active' && v.is_verified).length,
      pending: voters.filter(v => v.status === 'pending').length,
      suspended: voters.filter(v => v.status === 'suspended').length,
      total: voters.length
    };

    return (
      <div className="voters-content">
        <div className="page-header">
          <h1 className="page-title">Voter Management</h1>
          <button 
            className="primary-button"
            onClick={() => setShowAddUserModal(true)}
          >
            <FaUserPlus /> Add New User
          </button>
        </div>
        
        <div className="stats-bar">
          <div className="stat-item">
            <span className="stat-number">{voterStats.verified}</span>
            <span className="stat-label">Verified</span>
          </div>
          <div className="stat-item">
            <span className="stat-number">{voterStats.pending}</span>
            <span className="stat-label">Pending</span>
          </div>
          <div className="stat-item">
            <span className="stat-number">{voterStats.suspended}</span>
            <span className="stat-label">Suspended</span>
          </div>
          <div className="stat-item">
            <span className="stat-number">{voterStats.total}</span>
            <span className="stat-label">Total Voters</span>
          </div>
        </div>
        
        <div className="filters-bar">
          <div className="search-box">
            <FaSearch />
            <input 
              type="text" 
              placeholder="Search voters by name, email, or username..." 
              value={searchTerm}
              onChange={handleSearch}
            />
          </div>
          <div className="filter-options">
            <select 
              className="dropdown-filter"
              value={voterFilter}
              onChange={(e) => {
                setVoterFilter(e.target.value);
                setTimeout(() => loadVotersData(), 300);
              }}
            >
              <option value="all">All Status</option>
              <option value="active">Active</option>
              <option value="pending">Pending</option>
              <option value="suspended">Suspended</option>
              <option value="inactive">Inactive</option>
            </select>
          </div>
        </div>
        
        <div className="card">
          <div className="card-content">
            {voters.length > 0 ? (
              <table className="data-table">
                <thead>
                  <tr>
                    <th>Voter ID</th>
                    <th>Name</th>
                    <th>Email</th>
                    <th>Username</th>
                    <th>Status</th>
                    <th>Verified</th>
                    <th>Registration Date</th>
                    <th>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {voters.map(voter => (
                    <tr key={voter.user_id}>
                      <td>#{voter.user_id.toString().padStart(4, '0')}</td>
                      <td>{voter.full_name}</td>
                      <td>{voter.email}</td>
                      <td>{voter.username}</td>
                      <td>
                        <span className={`status-badge status-${voter.status}`}>
                          {voter.status}
                        </span>
                      </td>
                      <td>
                        {voter.is_verified ? (
                          <FaCheckCircle className="text-success" title="Verified" />
                        ) : (
                          <FaTimesCircle className="text-danger" title="Not Verified" />
                        )}
                      </td>
                      <td>{new Date(voter.registration_date).toLocaleDateString()}</td>
                      <td>
                        <div className="table-actions">
                          <button 
                            className="icon-button" 
                            title="View Details"
                            onClick={() => {
                              alert(`Voter Details:\nName: ${voter.full_name}\nEmail: ${voter.email}\nStatus: ${voter.status}`);
                            }}
                          >
                            <FaEye />
                          </button>
                          
                          {voter.status === 'pending' && (
                            <>
                              <button 
                                className="icon-button approve" 
                                title="Approve"
                                onClick={() => handleUpdateVoterStatus(voter.user_id, 'active')}
                              >
                                <FaUserCheck />
                              </button>
                              <button 
                                className="icon-button delete" 
                                title="Reject"
                                onClick={() => handleUpdateVoterStatus(voter.user_id, 'suspended')}
                              >
                                <FaUserTimes />
                              </button>
                            </>
                          )}
                          
                          {voter.status === 'active' && (
                            <button 
                              className="icon-button suspend" 
                              title="Suspend"
                              onClick={() => handleUpdateVoterStatus(voter.user_id, 'suspended')}
                            >
                              <FaUserSlash />
                            </button>
                          )}
                          
                          {voter.status === 'suspended' && (
                            <button 
                              className="icon-button approve" 
                              title="Reinstate"
                              onClick={() => handleUpdateVoterStatus(voter.user_id, 'active')}
                            >
                              <FaUserCheck />
                            </button>
                          )}
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            ) : (
              <div className="empty-state">
                <FaUsers className="empty-icon" />
                <h3>No voters found</h3>
                <p>Try adjusting your search or filter criteria</p>
                <button 
                  className="primary-button"
                  onClick={() => setShowAddUserModal(true)}
                  style={{marginTop: '15px'}}
                >
                  <FaUserPlus /> Add Your First User
                </button>
              </div>
            )}
          </div>
        </div>

        {/* Add User Modal */}
        <AddUserModal 
          isOpen={showAddUserModal}
          onClose={() => setShowAddUserModal(false)}
          onUserAdded={handleUserAdded}
        />
      </div>
    );
  };
  
  // Render the candidates management content
  const renderCandidates = () => {
    if (loading.candidates) return renderLoading();

    const candidateStats = {
      approved: candidates.filter(c => c.status === 'approved').length,
      pending: candidates.filter(c => c.status === 'pending').length,
      rejected: candidates.filter(c => c.status === 'rejected').length,
      total: candidates.length
    };

    return (
      <div className="candidates-content">
        <div className="page-header">
          <h1 className="page-title">Candidate Management</h1>
          <button 
            className="primary-button" 
            onClick={() => setShowAddCandidateModal(true)}
          >
            <FaPlus /> Add New Candidate
          </button>
        </div>
        
        <div className="stats-bar">
          <div className="stat-item">
            <span className="stat-number">{candidateStats.approved}</span>
            <span className="stat-label">Approved</span>
          </div>
          <div className="stat-item">
            <span className="stat-number">{candidateStats.pending}</span>
            <span className="stat-label">Pending</span>
          </div>
          <div className="stat-item">
            <span className="stat-number">{candidateStats.rejected}</span>
            <span className="stat-label">Rejected</span>
          </div>
          <div className="stat-item">
            <span className="stat-number">{candidateStats.total}</span>
            <span className="stat-label">Total Candidates</span>
          </div>
        </div>
        
        <div className="filters-bar">
          <div className="search-box">
            <FaSearch />
            <input 
              type="text" 
              placeholder="Search candidates by name, position, or election..." 
              value={searchTerm}
              onChange={handleSearch}
            />
          </div>
          <div className="filter-options">
            <select 
              className="dropdown-filter"
              value={candidateFilter}
              onChange={(e) => {
                setCandidateFilter(e.target.value);
                setTimeout(() => loadCandidatesData(), 300);
              }}
            >
              <option value="all">All Status</option>
              <option value="approved">Approved</option>
              <option value="pending">Pending</option>
              <option value="rejected">Rejected</option>
              <option value="suspended">Suspended</option>
            </select>
          </div>
        </div>
        
        <div className="card">
          <div className="card-content">
            {candidates.length > 0 ? (
              <table className="data-table">
                <thead>
                  <tr>
                    <th>Candidate</th>
                    <th>Position</th>
                    <th>Election</th>
                    <th>Status</th>
                    <th>Votes</th>
                    <th>Registration Date</th>
                    <th>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {candidates.map(candidate => (
                    <tr key={candidate.candidate_id}>
                      <td>
                        <div className="candidate-info">
                          <div className="candidate-avatar">
                            {candidate.candidate_photo ? (
                              <img src={candidate.candidate_photo} alt={candidate.candidate_name} />
                            ) : (
                              <span>{candidate.candidate_name?.charAt(0) || 'C'}</span>
                            )}
                          </div>
                          <div className="candidate-details">
                            <strong>{candidate.candidate_name}</strong>
                            <small>{candidate.candidate_party || 'Independent'}</small>
                          </div>
                        </div>
                      </td>
                      <td>{candidate.position_name}</td>
                      <td>{candidate.election_name}</td>
                      <td>
                        <span className={`status-badge status-${candidate.status}`}>
                          {candidate.status}
                        </span>
                      </td>
                      <td>{candidate.total_votes || 0}</td>
                      <td>{new Date(candidate.registration_date).toLocaleDateString()}</td>
                      <td>
                        <div className="table-actions">
                          <button 
                            className="icon-button" 
                            title="View Profile"
                            onClick={() => {
                              alert(`Candidate Profile:\nName: ${candidate.candidate_name}\nPosition: ${candidate.position_name}\nElection: ${candidate.election_name}\nParty: ${candidate.candidate_party || 'Independent'}\nVotes: ${candidate.total_votes || 0}`);
                            }}
                          >
                            <FaEye />
                          </button>
                          
                          <button 
                            className="icon-button" 
                            title="Edit"
                            onClick={() => {
                              setSelectedCandidate(candidate);
                              setShowEditCandidateModal(true);
                            }}
                          >
                            <FaEdit />
                          </button>
                          
                          {candidate.status === 'pending' && (
                            <>
                              <button 
                                className="icon-button approve" 
                                title="Approve"
                                onClick={() => handleApproveCandidate(candidate.candidate_id)}
                              >
                                <FaCheck />
                              </button>
                              <button 
                                className="icon-button delete" 
                                title="Reject"
                                onClick={() => handleRejectCandidate(candidate.candidate_id)}
                              >
                                <FaTimes />
                              </button>
                            </>
                          )}
                          
                          <button 
                            className="icon-button delete" 
                            title="Delete"
                            onClick={() => handleDeleteCandidate(candidate.candidate_id)}
                          >
                            <FaTrash />
                          </button>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            ) : (
              <div className="empty-state">
                <FaUserTie className="empty-icon" />
                <h3>No candidates found</h3>
                <p>Try adjusting your search or filter criteria</p>
                <button 
                  className="primary-button"
                  onClick={() => setShowAddCandidateModal(true)}
                >
                  <FaPlus /> Add Candidate
                </button>
              </div>
            )}
          </div>
        </div>
      </div>
    );
  };
  
  // Render the results content
  const renderResults = () => {
    if (loading.results) return renderLoading();

    return (
      <div className="results-content">
        <h1 className="page-title">Election Results & Analytics</h1>
        
        <div className="card">
          <div className="card-header">
            <h3>Generated Reports</h3>
            <button className="secondary-button">
              <FaDownload /> Export All
            </button>
          </div>
          <div className="card-content">
            {reports.length > 0 ? (
              <table className="data-table">
                <thead>
                  <tr>
                    <th>Report Name</th>
                    <th>Type</th>
                    <th>Generated By</th>
                    <th>Generated At</th>
                    <th>Downloads</th>
                    <th>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {reports.map(report => (
                    <tr key={report.report_id}>
                      <td>
                        <strong>{report.report_name}</strong>
                        <small>Period: {new Date(report.report_period_start).toLocaleDateString()} - {new Date(report.report_period_end).toLocaleDateString()}</small>
                      </td>
                      <td>
                        <span className={`badge badge-${report.report_type}`}>
                          {report.report_type.replace('_', ' ')}
                        </span>
                      </td>
                      <td>{report.generated_by_name || 'System'}</td>
                      <td>{new Date(report.generated_at).toLocaleString()}</td>
                      <td>{report.download_count || 0}</td>
                      <td>
                        <div className="table-actions">
                          <button 
                            className="icon-button" 
                            title="View Report"
                            onClick={() => {
                              setSelectedReport(report);
                              setShowViewReportModal(true);
                            }}
                          >
                            <FaEye />
                          </button>
                          <button 
                            className="icon-button" 
                            title="Download"
                            onClick={() => {
                              alert('Downloading report...');
                              // In a real app, this would trigger a download
                            }}
                          >
                            <FaDownload />
                          </button>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            ) : (
              <div className="empty-state">
                <FaChartBar className="empty-icon" />
                <h3>No reports generated yet</h3>
                <p>Generate your first report to see analytics</p>
                <button className="primary-button">
                  <FaFileExport /> Generate Report
                </button>
              </div>
            )}
          </div>
        </div>

        {/* Quick Stats Section */}
        <div className="content-row">
          <div className="content-column">
            <div className="card">
              <div className="card-header">
                <h3>Top Performing Elections</h3>
              </div>
              <div className="card-content">
                <div className="stats-grid">
                  <div className="stat-box">
                    <FaCrown className="stat-icon" />
                    <div className="stat-info">
                      <h4>Highest Turnout</h4>
                      <p className="stat-value">Board of Directors</p>
                      <p className="stat-detail">100% turnout</p>
                    </div>
                  </div>
                  <div className="stat-box">
                    <FaPoll className="stat-icon" />
                    <div className="stat-info">
                      <h4>Most Votes</h4>
                      <p className="stat-value">Student Council 2023</p>
                      <p className="stat-detail">850 votes</p>
                    </div>
                  </div>
                  <div className="stat-box">
                    <FaUserTie className="stat-icon" />
                    <div className="stat-info">
                      <h4>Most Candidates</h4>
                      <p className="stat-value">Student Council 2023</p>
                      <p className="stat-detail">8 candidates</p>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    );
  };
  
  // Render the settings content
  const renderSettings = () => {
    if (loading.settings) return renderLoading();

    const handleSettingChange = (category, settingKey, value) => {
      // Update local state
      setSystemSettings(prev => ({
        ...prev,
        [category]: prev[category].map(setting => 
          setting.setting_key === settingKey ? { ...setting, parsed_value: value } : setting
        )
      }));
    };

    const handleSaveSettings = async (category) => {
      const categorySettings = systemSettings[category] || [];
      for (const setting of categorySettings) {
        try {
          await handleUpdateSetting(setting.setting_key, setting.parsed_value);
        } catch (error) {
          console.error(`Failed to update setting ${setting.setting_key}:`, error);
        }
      }
    };

    return (
      <div className="settings-content">
        <h1 className="page-title">System Settings</h1>
        
        <div className="settings-grid">
          {/* General Settings */}
          <div className="card">
            <div className="card-header">
              <h3>General Settings</h3>
              <button 
                className="text-button"
                onClick={() => handleSaveSettings('general')}
              >
                Save
              </button>
            </div>
            <div className="card-content">
              {systemSettings.general?.map(setting => (
                <div key={setting.setting_key} className="form-group">
                  <label>{setting.description || setting.setting_key.replace('_', ' ')}</label>
                  {setting.setting_type === 'boolean' ? (
                    <div className="toggle-switch">
                      <input 
                        type="checkbox" 
                        id={setting.setting_key}
                        checked={setting.parsed_value}
                        onChange={(e) => handleSettingChange('general', setting.setting_key, e.target.checked)}
                      />
                      <label htmlFor={setting.setting_key} className="toggle-slider"></label>
                    </div>
                  ) : setting.setting_type === 'string' ? (
                    <input 
                      type="text" 
                      value={setting.parsed_value || ''}
                      onChange={(e) => handleSettingChange('general', setting.setting_key, e.target.value)}
                    />
                  ) : setting.setting_type === 'integer' ? (
                    <input 
                      type="number" 
                      value={setting.parsed_value || 0}
                      onChange={(e) => handleSettingChange('general', setting.setting_key, parseInt(e.target.value))}
                    />
                  ) : (
                    <input 
                      type="text" 
                      value={setting.parsed_value || ''}
                      onChange={(e) => handleSettingChange('general', setting.setting_key, e.target.value)}
                    />
                  )}
                </div>
              ))}
            </div>
          </div>
          
          {/* Security Settings */}
          <div className="card">
            <div className="card-header">
              <h3>Security Settings</h3>
              <button 
                className="text-button"
                onClick={() => handleSaveSettings('security')}
              >
                Save
              </button>
            </div>
            <div className="card-content">
              {systemSettings.security?.map(setting => (
                <div key={setting.setting_key} className="form-group">
                  <label>{setting.description || setting.setting_key.replace('_', ' ')}</label>
                  {setting.setting_type === 'boolean' ? (
                    <div className="toggle-switch">
                      <input 
                        type="checkbox" 
                        id={setting.setting_key}
                        checked={setting.parsed_value}
                        onChange={(e) => handleSettingChange('security', setting.setting_key, e.target.checked)}
                      />
                      <label htmlFor={setting.setting_key} className="toggle-slider"></label>
                    </div>
                  ) : setting.setting_type === 'string' ? (
                    <select 
                      value={setting.parsed_value || ''}
                      onChange={(e) => handleSettingChange('security', setting.setting_key, e.target.value)}
                    >
                      <option value="true">Enabled</option>
                      <option value="false">Disabled</option>
                      <option value="15">15 minutes</option>
                      <option value="30">30 minutes</option>
                      <option value="60">60 minutes</option>
                    </select>
                  ) : (
                    <input 
                      type={setting.setting_type === 'integer' ? 'number' : 'text'}
                      value={setting.parsed_value || ''}
                      onChange={(e) => handleSettingChange('security', setting.setting_key, 
                        setting.setting_type === 'integer' ? parseInt(e.target.value) : e.target.value
                      )}
                    />
                  )}
                </div>
              ))}
            </div>
          </div>
          
          {/* Admin Account */}
          <div className="card">
            <div className="card-header">
              <h3>Admin Account</h3>
            </div>
            <div className="card-content">
              {adminInfo && (
                <div className="admin-profile">
                  <div className="admin-avatar">
                    {adminInfo.profile_picture ? (
                      <img src={adminInfo.profile_picture} alt={adminInfo.full_name} />
                    ) : (
                      <FaUserCircle />
                    )}
                  </div>
                  <div className="admin-info">
                    <h4>{adminInfo.full_name}</h4>
                    <p>{adminInfo.email}</p>
                    <p className="last-login">
                      Last login: {adminInfo.last_login ? new Date(adminInfo.last_login).toLocaleString() : 'Never'}
                    </p>
                    <p className="admin-role">
                      <FaShieldAlt /> System Administrator
                    </p>
                  </div>
                </div>
              )}
              
              <div className="form-group">
                <label>Change Password</label>
                <input type="password" placeholder="Enter new password" />
              </div>
              <div className="form-group">
                <label>Confirm Password</label>
                <input type="password" placeholder="Confirm new password" />
              </div>
              <button className="primary-button">Update Password</button>
              
              <div className="danger-zone">
                <h4>Danger Zone</h4>
                <p>Irreversible actions. Proceed with caution.</p>
                <button className="danger-button">
                  <FaTrash /> Delete Admin Account
                </button>
              </div>
            </div>
          </div>
        </div>
      </div>
    );
  };

  // Render Audit Logs
  const renderAuditLogs = () => {
    return (
      <div className="audit-content">
        <div className="page-header">
          <h1 className="page-title">Audit Logs</h1>
          <button className="secondary-button">
            <FaDownload /> Export Logs
          </button>
        </div>
        
        <div className="filters-bar">
          <div className="search-box">
            <FaSearch />
            <input 
              type="text" 
              placeholder="Search audit logs..." 
              value={searchTerm}
              onChange={handleSearch}
            />
          </div>
          <div className="filter-options">
            <select className="dropdown-filter">
              <option value="all">All Actions</option>
              <option value="create">Create</option>
              <option value="update">Update</option>
              <option value="delete">Delete</option>
              <option value="login">Login</option>
            </select>
            <select className="dropdown-filter">
              <option value="all">All Tables</option>
              <option value="users">Users</option>
              <option value="elections">Elections</option>
              <option value="candidates">Candidates</option>
              <option value="votes">Votes</option>
            </select>
          </div>
        </div>
        
        <div className="card">
          <div className="card-content">
            {auditLogs.length > 0 ? (
              <table className="data-table">
                <thead>
                  <tr>
                    <th>Timestamp</th>
                    <th>User</th>
                    <th>Action</th>
                    <th>Table</th>
                    <th>Record ID</th>
                    <th>Details</th>
                  </tr>
                </thead>
                <tbody>
                  {auditLogs.slice(0, 20).map(log => (
                    <tr key={log.log_id}>
                      <td>{new Date(log.created_at).toLocaleString()}</td>
                      <td>{log.user_username || 'System'}</td>
                      <td>
                        <span className={`badge badge-${log.action_type}`}>
                          {log.action_type}
                        </span>
                      </td>
                      <td>{log.table_name}</td>
                      <td>{log.record_id || 'N/A'}</td>
                      <td>
                        <button 
                          className="text-button"
                          onClick={() => {
                            alert(`Old Values: ${JSON.stringify(log.old_values, null, 2)}\n\nNew Values: ${JSON.stringify(log.new_values, null, 2)}`);
                          }}
                        >
                          View Details
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            ) : (
              <div className="empty-state">
                <FaHistory className="empty-icon" />
                <h3>No audit logs found</h3>
                <p>System audit logs will appear here</p>
              </div>
            )}
          </div>
        </div>
      </div>
    );
  };

  // Render Security Logs
  const renderSecurityLogs = () => {
    return (
      <div className="security-content">
        <div className="page-header">
          <h1 className="page-title">Security Logs</h1>
          <button className="secondary-button">
            <FaDownload /> Export Logs
          </button>
        </div>
        
        <div className="filters-bar">
          <div className="search-box">
            <FaSearch />
            <input 
              type="text" 
              placeholder="Search security logs..." 
              value={searchTerm}
              onChange={handleSearch}
            />
          </div>
          <div className="filter-options">
            <select className="dropdown-filter">
              <option value="all">All Severity</option>
              <option value="info">Info</option>
              <option value="warning">Warning</option>
              <option value="error">Error</option>
              <option value="critical">Critical</option>
            </select>
            <select className="dropdown-filter">
              <option value="all">All Status</option>
              <option value="resolved">Resolved</option>
              <option value="unresolved">Unresolved</option>
            </select>
          </div>
        </div>
        
        <div className="card">
          <div className="card-content">
            {securityLogs.length > 0 ? (
              <table className="data-table">
                <thead>
                  <tr>
                    <th>Timestamp</th>
                    <th>Severity</th>
                    <th>Event Type</th>
                    <th>User</th>
                    <th>IP Address</th>
                    <th>Status</th>
                    <th>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {securityLogs.slice(0, 20).map(log => (
                    <tr key={log.log_id}>
                      <td>{new Date(log.created_at).toLocaleString()}</td>
                      <td>
                        <span className={`severity-badge severity-${log.severity}`}>
                          {log.severity}
                        </span>
                      </td>
                      <td>{log.event_type}</td>
                      <td>{log.user_username || 'Unknown'}</td>
                      <td>{log.ip_address || 'N/A'}</td>
                      <td>
                        {log.resolved ? (
                          <span className="status-badge status-resolved">Resolved</span>
                        ) : (
                          <span className="status-badge status-pending">Pending</span>
                        )}
                      </td>
                      <td>
                        <div className="table-actions">
                          <button 
                            className="icon-button"
                            title="View Details"
                            onClick={() => {
                              alert(`Security Event Details:\n\nType: ${log.event_type}\nSeverity: ${log.severity}\nDetails: ${log.details}\nUser Agent: ${log.user_agent || 'N/A'}`);
                            }}
                          >
                            <FaEye />
                          </button>
                          {!log.resolved && (
                            <button 
                              className="icon-button approve"
                              title="Mark as Resolved"
                              onClick={() => {
                                // In a real app, this would call an API
                                alert('Marking as resolved...');
                              }}
                            >
                              <FaCheck />
                            </button>
                          )}
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            ) : (
              <div className="empty-state">
                <FaShieldAlt className="empty-icon" />
                <h3>No security logs found</h3>
                <p>All systems are secure</p>
              </div>
            )}
          </div>
        </div>
      </div>
    );
  };

  // Render the appropriate content based on active tab
  const renderContent = () => {
    switch(activeTab) {
      case 'dashboard': return renderDashboard();
      case 'elections': return renderElections();
      case 'voters': return renderVoters();
      case 'candidates': return renderCandidates();
      case 'results': return renderResults();
      case 'settings': return renderSettings();
      case 'audit': return renderAuditLogs();
      case 'security': return renderSecurityLogs();
      default: return renderDashboard();
    }
  };

  // Render modals
  const renderAddElectionModal = () => {
    if (!showAddElectionModal) return null;
    
    return (
      <div className="modal-overlay">
        <div className="modal">
          <div className="modal-header">
            <h3>Create New Election</h3>
            <button className="icon-button" onClick={() => setShowAddElectionModal(false)}>
              <FaTimes />
            </button>
          </div>
          <div className="modal-content">
            <div className="form-group">
              <label>Election Name *</label>
              <input 
                type="text" 
                value={newElection.electionName}
                onChange={(e) => setNewElection({...newElection, electionName: e.target.value})}
                placeholder="Enter election name"
              />
            </div>
            <div className="form-group">
              <label>Description</label>
              <textarea 
                value={newElection.description}
                onChange={(e) => setNewElection({...newElection, description: e.target.value})}
                placeholder="Enter election description"
                rows="3"
              />
            </div>
            <div className="form-row">
              <div className="form-group">
                <label>Start Date *</label>
                <input 
                  type="datetime-local" 
                  value={newElection.startDate}
                  onChange={(e) => setNewElection({...newElection, startDate: e.target.value})}
                />
              </div>
              <div className="form-group">
                <label>End Date *</label>
                <input 
                  type="datetime-local" 
                  value={newElection.endDate}
                  onChange={(e) => setNewElection({...newElection, endDate: e.target.value})}
                />
              </div>
            </div>
            <div className="form-group">
              <label>
                <input 
                  type="checkbox" 
                  checked={newElection.isSecretBallot}
                  onChange={(e) => setNewElection({...newElection, isSecretBallot: e.target.checked})}
                />
                Secret Ballot
              </label>
            </div>
            <div className="form-group">
              <label>Results Visibility</label>
              <select 
                value={newElection.resultsVisible}
                onChange={(e) => setNewElection({...newElection, resultsVisible: e.target.value})}
              >
                <option value="immediate">Show immediately</option>
                <option value="after_vote">Show after vote</option>
                <option value="after_election">Show after election ends</option>
              </select>
            </div>
            <div className="form-row">
              <div className="form-group">
                <label>Min Votes per Voter</label>
                <input 
                  type="number" 
                  min="1"
                  value={newElection.minVotesPerVoter}
                  onChange={(e) => setNewElection({...newElection, minVotesPerVoter: parseInt(e.target.value)})}
                />
              </div>
              <div className="form-group">
                <label>Max Votes per Voter</label>
                <input 
                  type="number" 
                  min="1"
                  value={newElection.maxVotesPerVoter}
                  onChange={(e) => setNewElection({...newElection, maxVotesPerVoter: parseInt(e.target.value)})}
                />
              </div>
            </div>
          </div>
          <div className="modal-footer">
            <button className="secondary-button" onClick={() => setShowAddElectionModal(false)}>
              Cancel
            </button>
            <button className="primary-button" onClick={handleCreateElection}>
              Create Election
            </button>
          </div>
        </div>
      </div>
    );
  };

  const renderAddCandidateModal = () => {
    if (!showAddCandidateModal) return null;
    
    return (
      <div className="modal-overlay">
        <div className="modal">
          <div className="modal-header">
            <h3>Add New Candidate</h3>
            <button className="icon-button" onClick={() => setShowAddCandidateModal(false)}>
              <FaTimes />
            </button>
          </div>
          <div className="modal-content">
            <div className="form-group">
              <label>Full Name *</label>
              <input 
                type="text" 
                value={newCandidate.candidateName}
                onChange={(e) => setNewCandidate({...newCandidate, candidateName: e.target.value})}
                placeholder="Enter candidate's full name"
              />
            </div>
            <div className="form-group">
              <label>Email Address</label>
              <input 
                type="email" 
                value={newCandidate.contactEmail}
                onChange={(e) => setNewCandidate({...newCandidate, contactEmail: e.target.value})}
                placeholder="Enter candidate's email"
              />
            </div>
            <div className="form-group">
              <label>Position *</label>
              <input 
                type="text" 
                value={newCandidate.positionId}
                onChange={(e) => setNewCandidate({...newCandidate, positionId: e.target.value})}
                placeholder="Enter position (e.g., President)"
              />
            </div>
            <div className="form-group">
              <label>Party/Affiliation</label>
              <input 
                type="text" 
                value={newCandidate.candidateParty}
                onChange={(e) => setNewCandidate({...newCandidate, candidateParty: e.target.value})}
                placeholder="Enter party or affiliation"
              />
            </div>
            <div className="form-group">
              <label>Candidate Bio</label>
              <textarea 
                value={newCandidate.biography}
                onChange={(e) => setNewCandidate({...newCandidate, biography: e.target.value})}
                placeholder="Brief description of the candidate's qualifications and platform"
                rows="4"
              />
            </div>
            <div className="form-group">
              <label>Manifesto/Platform</label>
              <textarea 
                value={newCandidate.manifesto}
                onChange={(e) => setNewCandidate({...newCandidate, manifesto: e.target.value})}
                placeholder="Candidate's election promises and platform"
                rows="4"
              />
            </div>
          </div>
          <div className="modal-footer">
            <button className="secondary-button" onClick={() => setShowAddCandidateModal(false)}>
              Cancel
            </button>
            <button className="primary-button" onClick={handleCreateCandidate}>
              Add Candidate
            </button>
          </div>
        </div>
      </div>
    );
  };

  const renderEditElectionModal = () => {
    if (!showEditElectionModal || !selectedElection) return null;
    
    return (
      <div className="modal-overlay">
        <div className="modal">
          <div className="modal-header">
            <h3>Edit Election: {selectedElection.election_name}</h3>
            <button className="icon-button" onClick={() => setShowEditElectionModal(false)}>
              <FaTimes />
            </button>
          </div>
          <div className="modal-content">
            <div className="form-group">
              <label>Election Name</label>
              <input 
                type="text" 
                value={selectedElection.election_name}
                onChange={(e) => setSelectedElection({...selectedElection, election_name: e.target.value})}
              />
            </div>
            <div className="form-group">
              <label>Description</label>
              <textarea 
                value={selectedElection.description || ''}
                onChange={(e) => setSelectedElection({...selectedElection, description: e.target.value})}
                rows="3"
              />
            </div>
            <div className="form-row">
              <div className="form-group">
                <label>Start Date</label>
                <input 
                  type="datetime-local" 
                  value={selectedElection.start_date ? selectedElection.start_date.slice(0, 16) : ''}
                  onChange={(e) => setSelectedElection({...selectedElection, start_date: e.target.value})}
                />
              </div>
              <div className="form-group">
                <label>End Date</label>
                <input 
                  type="datetime-local" 
                  value={selectedElection.end_date ? selectedElection.end_date.slice(0, 16) : ''}
                  onChange={(e) => setSelectedElection({...selectedElection, end_date: e.target.value})}
                />
              </div>
            </div>
            <div className="form-group">
              <label>Status</label>
              <select 
                value={selectedElection.status}
                onChange={(e) => setSelectedElection({...selectedElection, status: e.target.value})}
              >
                <option value="draft">Draft</option>
                <option value="active">Active</option>
                <option value="paused">Paused</option>
                <option value="completed">Completed</option>
                <option value="cancelled">Cancelled</option>
              </select>
            </div>
          </div>
          <div className="modal-footer">
            <button className="secondary-button" onClick={() => setShowEditElectionModal(false)}>
              Cancel
            </button>
            <button className="primary-button" onClick={handleUpdateElection}>
              Save Changes
            </button>
          </div>
        </div>
      </div>
    );
  };

  const renderConfirmModal = () => {
    if (!showConfirmModal) return null;

    const getModalContent = () => {
      switch(confirmAction.type) {
        case 'deleteElection':
          return {
            title: 'Delete Election',
            message: 'Are you sure you want to delete this election? This action cannot be undone and will delete all related data including positions, candidates, and votes.',
            confirmText: 'Delete Election',
            confirmClass: 'danger-button'
          };
        case 'deleteCandidate':
          return {
            title: 'Delete Candidate',
            message: 'Are you sure you want to delete this candidate? This action cannot be undone.',
            confirmText: 'Delete Candidate',
            confirmClass: 'danger-button'
          };
        default:
          return {
            title: 'Confirm Action',
            message: 'Are you sure you want to proceed?',
            confirmText: 'Confirm',
            confirmClass: 'primary-button'
          };
      }
    };

    const { title, message, confirmText, confirmClass } = getModalContent();

    return (
      <div className="modal-overlay">
        <div className="modal modal-sm">
          <div className="modal-header">
            <h3>{title}</h3>
            <button className="icon-button" onClick={() => setShowConfirmModal(false)}>
              <FaTimes />
            </button>
          </div>
          <div className="modal-content">
            <p>{message}</p>
          </div>
          <div className="modal-footer">
            <button 
              className="secondary-button" 
              onClick={() => setShowConfirmModal(false)}
            >
              Cancel
            </button>
            <button 
              className={confirmClass}
              onClick={() => {
                if (confirmAction.type === 'deleteElection') {
                  confirmDeleteElection();
                } else if (confirmAction.type === 'deleteCandidate') {
                  confirmDeleteCandidate();
                }
              }}
            >
              {confirmText}
            </button>
          </div>
        </div>
      </div>
    );
  };

  // Check if user is authenticated, redirect if not
  if (!authToken || !adminInfo) {
    return (
      <div className="loading-container">
        <FaSpinner className="spinner" />
        <p>Loading admin panel...</p>
      </div>
    );
  }

  return (
    <div className="admin-panel">
      {/* Top Navigation Bar */}
      <nav className="top-navbar">
        <div className="navbar-left">
          <div className="logo">
            <FaVoteYea className="logo-icon" />
            <span className="logo-text">SecureVote Admin</span>
          </div>
        </div>
        
        <div className="navbar-center">
          <div className="nav-menu">
            <button 
              className={`nav-item ${activeTab === 'dashboard' ? 'active' : ''}`}
              onClick={() => handleTabChange('dashboard')}
            >
              <FaTachometerAlt /> Dashboard
            </button>
            <button 
              className={`nav-item ${activeTab === 'elections' ? 'active' : ''}`}
              onClick={() => handleTabChange('elections')}
            >
              <FaVoteYea /> Elections
            </button>
            <button 
              className={`nav-item ${activeTab === 'candidates' ? 'active' : ''}`}
              onClick={() => handleTabChange('candidates')}
            >
              <FaUserTie /> Candidates
            </button>
            <button 
              className={`nav-item ${activeTab === 'voters' ? 'active' : ''}`}
              onClick={() => handleTabChange('voters')}
            >
              <FaUsers /> Voters
            </button>
            <button 
              className={`nav-item ${activeTab === 'results' ? 'active' : ''}`}
              onClick={() => handleTabChange('results')}
            >
              <FaChartBar /> Results
            </button>
            <button 
              className={`nav-item ${activeTab === 'audit' ? 'active' : ''}`}
              onClick={() => handleTabChange('audit')}
            >
              <FaHistory /> Audit
            </button>
            <button 
              className={`nav-item ${activeTab === 'security' ? 'active' : ''}`}
              onClick={() => handleTabChange('security')}
            >
              <FaShieldAlt /> Security
            </button>
            <button 
              className={`nav-item ${activeTab === 'settings' ? 'active' : ''}`}
              onClick={() => handleTabChange('settings')}
            >
              <FaCog /> Settings
            </button>
          </div>
        </div>
        
        <div className="navbar-right">
          <div className="notification-dropdown">
            <button className="icon-button notification-button">
              <FaBell />
              {notifications.filter(n => !n.is_read).length > 0 && (
                <span className="notification-badge">
                  {notifications.filter(n => !n.is_read).length}
                </span>
              )}
            </button>
            <div className="notification-dropdown-content">
              <div className="notification-header">
                <h4>Notifications</h4>
                <button 
                  className="text-button"
                  onClick={handleMarkAllNotificationsAsRead}
                >
                  Mark all as read
                </button>
              </div>
              <div className="notification-list">
                {notifications.slice(0, 5).map(notification => (
                  <div 
                    key={notification.notification_id} 
                    className={`notification-item ${notification.is_read ? 'read' : 'unread'}`}
                    onClick={() => handleMarkNotificationAsRead(notification.notification_id)}
                  >
                    <p>{notification.title}</p>
                    <span className="notification-time">
                      {new Date(notification.created_at).toLocaleString()}
                    </span>
                  </div>
                ))}
              </div>
              <div className="notification-footer">
                <button 
                  className="text-button"
                  onClick={() => {
                    // View all notifications
                    alert('View all notifications');
                  }}
                >
                  View all notifications
                </button>
              </div>
            </div>
          </div>
          
          <div className="admin-dropdown">
            <button className="admin-profile-button">
              <FaUserCircle className="admin-avatar-small" />
              <span className="admin-name">
                {adminInfo?.full_name?.split(' ')[0] || 'Admin'}
              </span>
            </button>
            <div className="admin-dropdown-content">
              <div className="admin-dropdown-header">
                <FaUserCircle className="admin-avatar-large" />
                <div className="admin-info-dropdown">
                  <h4>{adminInfo?.full_name || 'System Admin'}</h4>
                  <p>{adminInfo?.email || 'admin@system.com'}</p>
                  <p className="role-badge">
                    <FaShieldAlt /> Administrator
                  </p>
                </div>
              </div>
              <div className="admin-dropdown-menu">
                <button 
                  className="dropdown-item"
                  onClick={() => handleTabChange('settings')}
                >
                  <FaUserCircle /> My Profile
                </button>
                <button 
                  className="dropdown-item"
                  onClick={() => handleTabChange('settings')}
                >
                  <FaCog /> Account Settings
                </button>
                <button 
                  className="dropdown-item"
                  onClick={() => {
                    apiService.getSystemHealth(authToken).then(result => {
                      alert(`System Status: ${result.status}\nDatabase: ${result.database}\nUptime: ${Math.floor(result.uptime / 60)} minutes`);
                    });
                  }}
                >
                  <FaDatabase /> System Health
                </button>
                <div className="dropdown-divider"></div>
                <button 
                  className="dropdown-item logout" 
                  onClick={handleLogout}
                >
                  <FaSignOutAlt /> Logout
                </button>
              </div>
            </div>
          </div>
        </div>
      </nav>
      
      {/* Main Content Area */}
      <main className="main-content">
        {renderContent()}
      </main>
      
      {/* Footer */}
      <footer className="admin-footer">
        <p>SecureVote Admin Panel v2.1 • © 2024 SecureVote Systems • All rights reserved</p>
        <p>
          Last updated: {new Date().toLocaleString()} • 
          System Status: <span className="status-online">Online</span> • 
          {dashboardStats && ` Uptime: ${dashboardStats.systemUptimePercentage}%`}
        </p>
      </footer>
      
      {/* Modals */}
      {renderAddElectionModal()}
      {renderAddCandidateModal()}
      {renderEditElectionModal()}
      {renderConfirmModal()}
    </div>
  );
};

export default AdminPanel;