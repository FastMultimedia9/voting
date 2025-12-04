// src/App.js
import React, { useState, useEffect } from 'react';
import { BrowserRouter, Routes, Route, Navigate, Outlet } from 'react-router-dom';
import './App.css';

// Component imports
import Header from './components/Header/Header.jsx';
import Footer from './components/Footer/Footer.jsx';
import Login from './components/Login/Login.jsx';
import Register from './components/Register/Register.jsx';
import ForgotPassword from './components/ForgotPassword/ForgotPassword.jsx';
import AdminPanel from './components/AdminPanel/AdminPanel.jsx';
import SimpleResetPassword from './components/SimpleResetPassword/SimpleResetPassword.jsx';
import AddUserModal from './components/AdminPanel/AddUserModal.jsx';

// Page imports
import HomePage from './pages/HomePage/HomePage.jsx';
import VotingPage from './pages/VotingPage/VotingPage.jsx';
import ResultsPage from './pages/ResultsPage/ResultsPage.jsx';
import AboutPage from './pages/AboutPage/AboutPage.jsx';

// Loading component
const LoadingSpinner = () => (
  <div className="loading-container">
    <div className="spinner"></div>
    <p>Loading...</p>
  </div>
);

// Protected Route wrapper
const ProtectedRoute = ({ children, requiredRole = null }) => {
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    checkAuth();
  }, []);

  const checkAuth = () => {
    const token = localStorage.getItem('token') || localStorage.getItem('adminToken');
    const userData = localStorage.getItem('user') || localStorage.getItem('adminInfo');
    
    if (token && userData) {
      try {
        setIsAuthenticated(true);
        setUser(JSON.parse(userData));
      } catch (error) {
        console.error('Error parsing user data:', error);
        localStorage.removeItem('token');
        localStorage.removeItem('user');
        localStorage.removeItem('adminToken');
        localStorage.removeItem('adminInfo');
      }
    }
    setLoading(false);
  };

  if (loading) {
    return <LoadingSpinner />;
  }

  if (!isAuthenticated) {
    return <Navigate to="/login" replace />;
  }

  // Check role if required
  if (requiredRole && user?.role !== requiredRole) {
    // Redirect to appropriate dashboard based on role
    if (user?.role === 'admin') {
      return <Navigate to="/adminpanel/adminpanel" replace />;
    } else if (user?.role === 'voter') {
      return <Navigate to="/home" replace />;
    } else if (user?.role === 'candidate') {
      return <Navigate to="/candidate/dashboard" replace />;
    }
    return <Navigate to="/home" replace />;
  }

  return children;
};

// Layout with Header and Footer
const MainLayout = () => {
  return (
    <div className="app">
      <Header />
      <main className="main-content">
        <Outlet />
      </main>
      <Footer />
    </div>
  );
};

// Layout without Header and Footer (for Auth pages)
const AuthLayout = () => {
  return (
    <div className="auth-layout">
      <Outlet />
    </div>
  );
};

// Layout for Forgot Password
const SimpleLayout = () => {
  return (
    <div className="simple-layout">
      <Outlet />
    </div>
  );
};

// Admin Layout without Header/Footer
const AdminLayout = () => {
  return (
    <div className="admin-layout">
      <Outlet />
    </div>
  );
};

function App() {
  return (
    <BrowserRouter>
      <Routes>
        {/* Redirect root to login */}
        <Route path="/" element={<Navigate to="/login" replace />} />

        {/* Auth routes without Header/Footer */}
        <Route element={<AuthLayout />}>
          <Route path="/login" element={<Login />} />
          <Route path="/register" element={<Register />} />
        </Route>

        {/* Forgot Password routes */}
        <Route element={<SimpleLayout />}>
          <Route path="/forgot-password" element={<ForgotPassword />} />
          <Route path="/reset-password" element={<SimpleResetPassword />} />
        </Route>

        {/* Admin Panel routes (no Header/Footer needed as AdminPanel has its own) */}
        <Route element={<AdminLayout />}>
          <Route 
            path="/admin" 
            element={
              <ProtectedRoute requiredRole="admin">
                <AdminPanel />
              </ProtectedRoute>
            } 
          />
          <Route 
            path="/adminpanel" 
            element={
              <ProtectedRoute requiredRole="admin">
                <AdminPanel />
              </ProtectedRoute>
            } 
          />
          <Route 
            path="/adminpanel/adminpanel" 
            element={
              <ProtectedRoute requiredRole="admin">
                <AdminPanel />
              </ProtectedRoute>
            } 
          />
        </Route>

        {/* Protected routes with Header/Footer */}
        <Route element={<MainLayout />}>
          <Route 
            path="/home" 
            element={
              <ProtectedRoute>
                <HomePage />
              </ProtectedRoute>
            } 
          />
          <Route 
            path="/vote" 
            element={
              <ProtectedRoute>
                <VotingPage />
              </ProtectedRoute>
            } 
          />
          <Route 
            path="/results" 
            element={
              <ProtectedRoute>
                <ResultsPage />
              </ProtectedRoute>
            } 
          />
          <Route 
            path="/about" 
            element={
              <ProtectedRoute>
                <AboutPage />
              </ProtectedRoute>
            } 
          />
          
          {/* Candidate routes */}
          <Route 
            path="/candidate/dashboard" 
            element={
              <ProtectedRoute requiredRole="candidate">
                <CandidateDashboard />
              </ProtectedRoute>
            } 
          />
          <Route 
            path="/candidate/profile" 
            element={
              <ProtectedRoute requiredRole="candidate">
                <CandidateProfile />
              </ProtectedRoute>
            } 
          />
          <Route 
            path="/candidate/campaign" 
            element={
              <ProtectedRoute requiredRole="candidate">
                <CandidateCampaign />
              </ProtectedRoute>
            } 
          />

          {/* Voter specific routes */}
          <Route 
            path="/voter/profile" 
            element={
              <ProtectedRoute requiredRole="voter">
                <VoterProfile />
              </ProtectedRoute>
            } 
          />
          <Route 
            path="/voter/history" 
            element={
              <ProtectedRoute requiredRole="voter">
                <VotingHistory />
              </ProtectedRoute>
            } 
          />

          {/* Utility routes */}
          <Route 
            path="/settings" 
            element={
              <ProtectedRoute>
                <UserSettings />
              </ProtectedRoute>
            } 
          />
          <Route 
            path="/profile" 
            element={
              <ProtectedRoute>
                <UserProfile />
              </ProtectedRoute>
            } 
          />
          
          {/* Test route for AddUserModal (for debugging) */}
          <Route 
            path="/test-add-user" 
            element={
              <ProtectedRoute requiredRole="admin">
                <TestAddUserPage />
              </ProtectedRoute>
            } 
          />
        </Route>

        {/* 404 Page */}
        <Route path="*" element={
          <div className="not-found">
            <h1>404 - Page Not Found</h1>
            <p>The page you are looking for doesn't exist.</p>
            <a href="/home">Go to Home</a>
          </div>
        } />
      </Routes>
    </BrowserRouter>
  );
}

// ============================================
// COMPONENT PLACEHOLDERS
// ============================================

const CandidateDashboard = () => (
  <div className="candidate-dashboard">
    <h1>Candidate Dashboard</h1>
    <p>Welcome to the candidate portal!</p>
    <p>Manage your campaign, view election progress, and connect with voters.</p>
    <div style={{ marginTop: '20px' }}>
      <button style={buttonStyle}>View Campaign Stats</button>
      <button style={buttonStyle}>Update Profile</button>
      <button style={buttonStyle}>View Election Results</button>
    </div>
  </div>
);

const CandidateProfile = () => (
  <div className="candidate-profile">
    <h1>Candidate Profile</h1>
    <p>Manage your candidate profile information.</p>
  </div>
);

const CandidateCampaign = () => (
  <div className="candidate-campaign">
    <h1>Campaign Management</h1>
    <p>Manage your campaign materials and updates.</p>
  </div>
);

const VoterProfile = () => (
  <div className="voter-profile">
    <h1>Voter Profile</h1>
    <p>View and manage your voter profile.</p>
  </div>
);

const VotingHistory = () => (
  <div className="voting-history">
    <h1>Voting History</h1>
    <p>View your past voting records.</p>
  </div>
);

const UserSettings = () => (
  <div className="user-settings">
    <h1>Account Settings</h1>
    <p>Manage your account preferences and security settings.</p>
  </div>
);

const UserProfile = () => (
  <div className="user-profile">
    <h1>User Profile</h1>
    <p>View and edit your personal information.</p>
  </div>
);

const TestAddUserPage = () => {
  const [showModal, setShowModal] = useState(true);
  
  return (
    <div style={{ padding: '20px' }}>
      <h1>Test Add User Modal</h1>
      <p>This page is for testing the AddUserModal component.</p>
      <button style={buttonStyle} onClick={() => setShowModal(true)}>
        Open Add User Modal
      </button>
      
      {showModal && (
        <AddUserModal
          isOpen={showModal}
          onClose={() => setShowModal(false)}
          onUserAdded={(newUser) => {
            console.log('User added:', newUser);
            alert(`User ${newUser?.fullName || 'added'} successfully!`);
          }}
        />
      )}
    </div>
  );
};

const buttonStyle = {
  padding: '10px 20px',
  margin: '0 10px 10px 0',
  backgroundColor: '#007bff',
  color: 'white',
  border: 'none',
  borderRadius: '5px',
  cursor: 'pointer'
};

// ============================================
// APP.CSS STYLES (Add these if not present)
// ============================================
/*
.app {
  display: flex;
  flex-direction: column;
  min-height: 100vh;
}

.main-content {
  flex: 1;
  padding: 20px;
}

.auth-layout {
  min-height: 100vh;
  display: flex;
  align-items: center;
  justify-content: center;
  background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
}

.simple-layout {
  min-height: 100vh;
  display: flex;
  align-items: center;
  justify-content: center;
  background: #f5f5f5;
}

.admin-layout {
  min-height: 100vh;
  background: #f8f9fa;
}

.loading-container {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  min-height: 100vh;
}

.spinner {
  border: 4px solid rgba(0, 0, 0, 0.1);
  border-left-color: #007bff;
  border-radius: 50%;
  width: 40px;
  height: 40px;
  animation: spin 1s linear infinite;
  margin-bottom: 20px;
}

@keyframes spin {
  to {
    transform: rotate(360deg);
  }
}

.not-found {
  text-align: center;
  padding: 100px 20px;
}

.not-found h1 {
  font-size: 48px;
  color: #dc3545;
  margin-bottom: 20px;
}

.not-found p {
  font-size: 18px;
  color: #666;
  margin-bottom: 30px;
}

.not-found a {
  color: #007bff;
  text-decoration: none;
  font-weight: bold;
}
*/

export default App;