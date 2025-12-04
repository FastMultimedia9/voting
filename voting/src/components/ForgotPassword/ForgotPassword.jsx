import React, { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import axios from 'axios';

const API = axios.create({
  baseURL: 'http://localhost:5000/api',
});

const SimpleResetPassword = () => {
  const navigate = useNavigate();
  const [identifier, setIdentifier] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const [debugInfo, setDebugInfo] = useState('');

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    setSuccess('');
    setDebugInfo('');

    if (!identifier) {
      setError('Please enter your username or email');
      return;
    }

    if (!password) {
      setError('Please enter a new password');
      return;
    }

    if (password.length < 6) {
      setError('Password must be at least 6 characters');
      return;
    }

    if (password !== confirmPassword) {
      setError('Passwords do not match');
      return;
    }

    setLoading(true);

    try {
      console.log('Sending reset request with:', { identifier, password });
      
      const response = await API.post('/auth/simple-reset', {
        identifier,
        password,
        confirmPassword
      });

      console.log('Reset response:', response.data);

      if (response.data.success) {
        setSuccess('Password reset successful! You can now login.');
        setDebugInfo(`Response: ${JSON.stringify(response.data)}`);
        
        // Clear form
        setIdentifier('');
        setPassword('');
        setConfirmPassword('');
        
        // Redirect to login after 3 seconds
        setTimeout(() => {
          navigate('/login');
        }, 3000);
      } else {
        setError(response.data.error || 'Failed to reset password');
        setDebugInfo(`Error: ${JSON.stringify(response.data)}`);
      }
    } catch (err) {
      console.error('Reset error details:', err);
      
      if (err.response) {
        console.log('Error response:', err.response.data);
        console.log('Error status:', err.response.status);
        
        if (err.response.status === 400) {
          const errors = err.response.data.errors;
          if (errors && errors.length > 0) {
            setError(errors[0].msg || 'Invalid input');
          } else {
            setError(err.response.data.error || 'Invalid request');
          }
        } else if (err.response.status === 404) {
          setError('Account not found. Try: admin, voter1, or James');
        } else {
          setError(err.response.data?.error || 'An error occurred');
        }
        setDebugInfo(`Status: ${err.response.status}, Data: ${JSON.stringify(err.response.data)}`);
      } else if (err.request) {
        setError('Unable to connect to server. Please check your connection.');
        setDebugInfo('No response received from server');
      } else {
        setError('An unexpected error occurred.');
        setDebugInfo(`Error: ${err.message}`);
      }
    } finally {
      setLoading(false);
    }
  };

  return (
    <div style={styles.container}>
      <div style={styles.card}>
        <Link to="/login" style={styles.backLink}>← Back to Login</Link>
        
        <h2 style={styles.title}>Reset Password</h2>
        
        <p style={styles.subtitle}>
          Enter your username or email and new password
          <br />
          <small style={{fontSize: '12px', color: '#666'}}>
            Try: admin, voter1, or James
          </small>
        </p>
        
        {error && <div style={styles.error}>{error}</div>}
        {success && <div style={styles.success}>{success}</div>}
        
        {debugInfo && (
          <div style={styles.debug}>
            <small>Debug: {debugInfo}</small>
          </div>
        )}

        <form onSubmit={handleSubmit} style={styles.form}>
          <div style={styles.formGroup}>
            <label style={styles.label}>Username or Email</label>
            <input
              type="text"
              value={identifier}
              onChange={(e) => setIdentifier(e.target.value)}
              style={styles.input}
              placeholder="Enter username or email (try: admin)"
              required
              disabled={loading}
            />
          </div>

          <div style={styles.formGroup}>
            <label style={styles.label}>New Password</label>
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              style={styles.input}
              placeholder="Minimum 6 characters"
              required
              disabled={loading}
            />
          </div>

          <div style={styles.formGroup}>
            <label style={styles.label}>Confirm Password</label>
            <input
              type="password"
              value={confirmPassword}
              onChange={(e) => setConfirmPassword(e.target.value)}
              style={styles.input}
              placeholder="Re-enter new password"
              required
              disabled={loading}
            />
          </div>

          <button
            type="submit"
            disabled={loading}
            style={{...styles.button, ...(loading && styles.buttonLoading)}}
          >
            {loading ? 'Resetting...' : 'Reset Password'}
          </button>
        </form>

        <div style={styles.footer}>
          Remember your password? <Link to="/login" style={styles.link}>Login here</Link>
        </div>
      </div>
    </div>
  );
};

const styles = {
  container: { display: 'flex', justifyContent: 'center', alignItems: 'center', minHeight: '100vh', backgroundColor: '#f5f5f5', padding: '20px' },
  card: { backgroundColor: 'white', padding: '30px', borderRadius: '8px', boxShadow: '0 2px 10px rgba(0,0,0,0.1)', width: '100%', maxWidth: '400px' },
  backLink: { color: '#666', textDecoration: 'none', fontSize: '14px', marginBottom: '20px', display: 'inline-block' },
  title: { margin: '0 0 10px 0', color: '#333' },
  subtitle: { margin: '0 0 20px 0', color: '#666', fontSize: '14px' },
  form: { marginTop: '20px' },
  formGroup: { marginBottom: '20px' },
  label: { display: 'block', marginBottom: '5px', color: '#555', fontSize: '14px', fontWeight: '500' },
  input: { width: '100%', padding: '10px', border: '1px solid #ddd', borderRadius: '4px', fontSize: '16px', boxSizing: 'border-box' },
  button: { width: '100%', padding: '12px', backgroundColor: '#007bff', color: 'white', border: 'none', borderRadius: '4px', fontSize: '16px', cursor: 'pointer', marginTop: '10px' },
  buttonLoading: { opacity: 0.7, cursor: 'not-allowed' },
  error: { backgroundColor: '#f8d7da', color: '#721c24', padding: '10px', borderRadius: '4px', marginBottom: '20px', fontSize: '14px' },
  success: { backgroundColor: '#d4edda', color: '#155724', padding: '10px', borderRadius: '4px', marginBottom: '20px', fontSize: '14px' },
  debug: { backgroundColor: '#f8f9fa', color: '#6c757d', padding: '10px', borderRadius: '4px', marginBottom: '20px', fontSize: '12px', fontFamily: 'monospace', wordBreak: 'break-all' },
  footer: { marginTop: '20px', textAlign: 'center', color: '#666', fontSize: '14px', borderTop: '1px solid #eee', paddingTop: '20px' },
  link: { color: '#007bff', textDecoration: 'none', fontWeight: '500' },
};

export default SimpleResetPassword;