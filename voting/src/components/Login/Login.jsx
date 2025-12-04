// src/components/Login.jsx
import React, { useState } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import axios from 'axios';
import './Login.css';

// Icons (you can also use an icon library or SVG)
const UserIcon = () => <span className="icon">👤</span>;
const KeyIcon = () => <span className="icon">🔑</span>;
const ShieldIcon = () => <span className="icon">🛡️</span>;
const VoteIcon = () => <span className="icon">🗳️</span>;
const CandidateIcon = () => <span className="icon">🎯</span>;
const AdminIcon = () => <span className="icon">⚙️</span>;
const ErrorIcon = () => <span className="icon error">⚠️</span>;
const CheckIcon = () => <span className="icon success">✓</span>;
const LockIcon = () => <span className="icon">🔒</span>;

// Configure axios
const API = axios.create({
  baseURL: 'http://localhost:5000/api',
});

const Login = () => {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [userType, setUserType] = useState('voter');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const [rememberMe, setRememberMe] = useState(false);
  const navigate = useNavigate();

  const userTypes = [
    {
      id: 'voter',
      name: 'Voter',
      description: 'Cast your vote securely',
      icon: <VoteIcon />,
      className: 'voter'
    },
    {
      id: 'candidate',
      name: 'Candidate',
      description: 'Manage your campaign',
      icon: <CandidateIcon />,
      className: 'candidate'
    },
    {
      id: 'admin',
      name: 'Administrator',
      description: 'Manage election system',
      icon: <AdminIcon />,
      className: 'admin'
    }
  ];

  
// In the handleSubmit function of Login.jsx, update this section:
const handleSubmit = async (e) => {
  e.preventDefault();
  setError('');
  
  if (!username.trim()) {
    setError('Please enter your username');
    return;
  }
  
  if (!password) {
    setError('Please enter your password');
    return;
  }

  setLoading(true);

  try {
    const response = await API.post('/auth/login', {
      username,
      password,
      userType
    });

    if (response.data.success) {
      const userData = response.data.user;
      const token = response.data.token;
      
      // Store in localStorage
      localStorage.setItem('token', token);
      localStorage.setItem('user', JSON.stringify(userData));
      
      // If user is admin, also store admin-specific keys
      if (userData.role === 'admin') {
        localStorage.setItem('adminToken', token);
        localStorage.setItem('adminInfo', JSON.stringify(userData));
      }
      
      API.defaults.headers.common['Authorization'] = `Bearer ${token}`;

      // Redirect based on role
      redirectUser(userData.role, userData.userId || userData.user_id);
    } else {
      setError(response.data.error || 'Login failed. Please try again.');
    }
  } catch (err) {
    handleLoginError(err);
  } finally {
    setLoading(false);
  }
};

// Also fix the redirectUser function to match what AdminPanel expects:
const redirectUser = (role, userId) => {
  switch (role) {
    case 'admin':
      navigate('/adminpanel/adminpanel');
      break;
    case 'candidate':
      navigate('/candidate/dashboard');
      break;
    case 'voter':
      navigate('/home');
      break;
    default:
      navigate('/home');
  }
};


  const handleLoginError = (err) => {
    console.error('Login error:', err);
    
    if (err.response) {
      switch (err.response.status) {
        case 401:
          setError('Invalid username or password');
          break;
        case 403:
          if (err.response.data.error?.includes('verified')) {
            setError('Account not verified. Please contact administrator.');
          } else if (err.response.data.error?.includes('deactivated')) {
            setError('Account is deactivated. Contact support.');
          } else if (err.response.data.error?.includes('role')) {
            setError('Invalid login type. Please select correct role.');
          } else {
            setError(err.response.data.error || 'Access denied');
          }
          break;
        case 404:
          setError('Account not found');
          break;
        case 400:
          setError('Invalid request. Please check your input.');
          break;
        case 500:
          setError('Server error. Please try again later.');
          break;
        default:
          setError('Login failed. Please try again.');
      }
    } else if (err.request) {
      setError('Unable to connect to server. Please check your connection.');
    } else {
      setError('An unexpected error occurred.');
    }
  };

  const handleUserTypeSelect = (type) => {
    setUserType(type);
    setError('');
    setUsername('');
    setPassword('');
  };

  const selectedUserType = userTypes.find(type => type.id === userType);

  return (
    <div className="login-page">
      <div className="login-container">
        {/* Left Panel - Branding & Info */}
        <div className="login-left-panel">
          <div className="brand-header">
            <div className="brand-logo">
              <ShieldIcon />
            </div>
            <h1 className="brand-title">SecureVote</h1>
            <p className="brand-subtitle">Election Management System</p>
          </div>

          

          <div className="role-selection-panel">
            {userTypes.map((type) => (
              <div 
                key={type.id}
                className={`role-item ${type.className} ${userType === type.id ? 'active' : ''}`}
                onClick={() => handleUserTypeSelect(type.id)}
              >
                <div className="role-icon-wrapper">
                  {type.icon}
                </div>
                <div className="role-info">
                  <h3>{type.name}</h3>
                  <p>{type.description}</p>
                </div>
                {userType === type.id && (
                  <div className="role-check">
                    <CheckIcon />
                  </div>
                )}
              </div>
            ))}
          </div>

         
        </div>

        {/* Right Panel - Login Form */}
        <div className="login-right-panel">
          <div className="login-header">
            <div className="user-type-badge">
              <span className={`badge ${selectedUserType.className}`}>
                {selectedUserType.name}
              </span>
            </div>
            <h2>Sign In to Your Account</h2>
            <p className="login-subtitle">
              Enter your credentials to access the {selectedUserType.name.toLowerCase()} portal
            </p>
          </div>

          <form onSubmit={handleSubmit} className="login-form">
            <div className="form-group">
              <label htmlFor="username" className="form-label">
                <UserIcon />
                Username
              </label>
              <input
                id="username"
                type="text"
                required
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                disabled={loading}
                className="form-input"
                placeholder={`Enter ${selectedUserType.name.toLowerCase()} username`}
              />
            </div>

            <div className="form-group">
              <div className="form-label-row">
                <label htmlFor="password" className="form-label">
                  <KeyIcon />
                  Password
                </label>
                <Link to="/forgot-password" className="forgot-password">
                  Forgot password?
                </Link>
              </div>
              <input
                id="password"
                type="password"
                required
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                disabled={loading}
                className="form-input"
                placeholder="Enter your password"
              />
            </div>

            {error && (
              <div className="error-message">
                <ErrorIcon />
                <span>{error}</span>
              </div>
            )}

            <div className="form-options">
              <label className="checkbox-label">
                <input
                  type="checkbox"
                  checked={rememberMe}
                  onChange={(e) => setRememberMe(e.target.checked)}
                  disabled={loading}
                  className="checkbox-input"
                />
                <span className="checkbox-custom"></span>
                <span className="checkbox-text">Keep me signed in for 30 days</span>
              </label>
            </div>

            <button
              type="submit"
              disabled={loading}
              className={`submit-btn ${selectedUserType.className} ${loading ? 'loading' : ''}`}
            >
              {loading ? (
                <>
                  <span className="spinner"></span>
                  Authenticating...
                </>
              ) : (
                <>
                  Sign In as {selectedUserType.name}
                  <span className="btn-arrow">→</span>
                </>
              )}
            </button>

            <div className="security-notice">
              <LockIcon />
              <span>Your session is protected with 256-bit SSL encryption</span>
            </div>
          </form>

          
        
        </div>
      </div>
    </div>
  );
};

export default Login;