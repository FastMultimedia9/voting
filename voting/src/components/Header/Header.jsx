// src/components/Header/Header.jsx
import React, { useState, useEffect } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import './Header.css';

// Icons
const HomeIcon = () => <span className="icon">🏠</span>;
const VoteIcon = () => <span className="icon">🗳️</span>;
const ResultsIcon = () => <span className="icon">📊</span>;
const AboutIcon = () => <span className="icon">ℹ️</span>;
const AdminIcon = () => <span className="icon">⚙️</span>;
const ProfileIcon = () => <span className="icon">👤</span>;
const LogoutIcon = () => <span className="icon">🚪</span>;
const LoginIcon = () => <span className="icon">🔑</span>;
const CandidateIcon = () => <span className="icon">🎯</span>;

const Header = () => {
  const [user, setUser] = useState(null);
  const [showProfileDropdown, setShowProfileDropdown] = useState(false);
  const navigate = useNavigate();

  useEffect(() => {
    // Load user data from localStorage on component mount
    const userData = localStorage.getItem('user');
    if (userData) {
      try {
        setUser(JSON.parse(userData));
      } catch (error) {
        console.error('Error parsing user data:', error);
        localStorage.removeItem('user');
      }
    }

    // Listen for storage changes (for logout/login from other tabs)
    const handleStorageChange = () => {
      const updatedUser = localStorage.getItem('user');
      setUser(updatedUser ? JSON.parse(updatedUser) : null);
    };

    window.addEventListener('storage', handleStorageChange);
    return () => window.removeEventListener('storage', handleStorageChange);
  }, []);

  const handleLogout = () => {
    // Clear all auth data
    localStorage.removeItem('token');
    localStorage.removeItem('user');
    setUser(null);
    setShowProfileDropdown(false);
    
    // Redirect to login page
    navigate('/login');
  };

  const toggleProfileDropdown = () => {
    setShowProfileDropdown(!showProfileDropdown);
  };

  // Close dropdown when clicking outside
  useEffect(() => {
    const handleClickOutside = (event) => {
      if (showProfileDropdown && !event.target.closest('.profile-dropdown-container')) {
        setShowProfileDropdown(false);
      }
    };

    document.addEventListener('click', handleClickOutside);
    return () => document.removeEventListener('click', handleClickOutside);
  }, [showProfileDropdown]);

  // Navigation items for different user roles
  const getNavItems = () => {
    const baseItems = [
      { path: '/home', label: 'Home', icon: <HomeIcon /> },
      { path: '/vote', label: 'Vote', icon: <VoteIcon /> },
      { path: '/results', label: 'Results', icon: <ResultsIcon /> },
      { path: '/about', label: 'About', icon: <AboutIcon /> },
    ];

    // Add role-specific items
    if (user) {
      switch (user.role) {
        case 'admin':
          baseItems.push({ path: '/admin', label: 'Admin Panel', icon: <AdminIcon /> });
          break;
        case 'candidate':
          baseItems.push({ path: '/candidate/dashboard', label: 'Dashboard', icon: <CandidateIcon /> });
          break;
        case 'voter':
          // Voters get basic navigation only
          break;
        default:
          break;
      }
    }

    return baseItems;
  };

  const formatRole = (role) => {
    const roleMap = {
      'admin': 'Administrator',
      'voter': 'Voter',
      'candidate': 'Candidate',
      'auditor': 'Auditor'
    };
    return roleMap[role] || role;
  };

  const getRoleColor = (role) => {
    const colorMap = {
      'admin': 'admin-badge',
      'voter': 'voter-badge',
      'candidate': 'candidate-badge',
      'auditor': 'auditor-badge'
    };
    return colorMap[role] || 'default-badge';
  };

  return (
    <header className="header">
      <nav className="navbar">
        {/* Logo Section */}
        <div className="logo">
          <Link to="/home">
            <span className="logo-icon">🗳️</span>
            <span className="logo-text">SecureVote</span>
          </Link>
        </div>

        {/* Navigation Menu */}
        <ul className="nav-menu">
          {getNavItems().map((item) => (
            <li key={item.path} className="nav-item">
              <Link to={item.path} className="nav-link">
                {item.icon}
                <span className="nav-text">{item.label}</span>
              </Link>
            </li>
          ))}
        </ul>

        {/* User Section */}
        <div className="user-section">
          {user ? (
            <div className="profile-dropdown-container">
              <button 
                className="profile-btn" 
                onClick={toggleProfileDropdown}
                aria-expanded={showProfileDropdown}
                aria-label="User profile"
              >
                <div className="profile-avatar">
                  {user.full_name?.charAt(0) || user.username?.charAt(0) || 'U'}
                </div>
                <div className="profile-info">
                  <span className="profile-name">{user.full_name || user.username}</span>
                  <span className={`profile-role ${getRoleColor(user.role)}`}>
                    {formatRole(user.role)}
                  </span>
                </div>
                <span className="dropdown-arrow">▼</span>
              </button>

              {/* Profile Dropdown */}
              {showProfileDropdown && (
                <div className="profile-dropdown">
                  <div className="dropdown-header">
                    <div className="dropdown-avatar">
                      {user.full_name?.charAt(0) || user.username?.charAt(0) || 'U'}
                    </div>
                    <div className="dropdown-user-info">
                      <h4>{user.full_name || user.username}</h4>
                      <p className="user-email">{user.email}</p>
                      <p className={`user-role ${getRoleColor(user.role)}`}>
                        {formatRole(user.role)}
                      </p>
                    </div>
                  </div>

                  <div className="dropdown-divider"></div>

                  <Link to="/profile" className="dropdown-item" onClick={() => setShowProfileDropdown(false)}>
                    <ProfileIcon />
                    <span>My Profile</span>
                  </Link>

                  {user.role === 'admin' && (
                    <Link to="/admin/settings" className="dropdown-item" onClick={() => setShowProfileDropdown(false)}>
                      <AdminIcon />
                      <span>Admin Settings</span>
                    </Link>
                  )}

                  {user.role === 'candidate' && (
                    <Link to="/candidate/profile" className="dropdown-item" onClick={() => setShowProfileDropdown(false)}>
                      <CandidateIcon />
                      <span>Candidate Profile</span>
                    </Link>
                  )}

                  <div className="dropdown-divider"></div>

                  <button className="dropdown-item logout-item" onClick={handleLogout}>
                    <LogoutIcon />
                    <span>Logout</span>
                  </button>
                </div>
              )}
            </div>
          ) : (
            <Link to="/login" className="login-btn">
              <LoginIcon />
              <span>Login / Register</span>
            </Link>
          )}
        </div>

        {/* Mobile Menu Toggle (optional) */}
        <button className="mobile-menu-toggle" aria-label="Toggle menu">
          <span></span>
          <span></span>
          <span></span>
        </button>
      </nav>
    </header>
  );
};

export default Header;