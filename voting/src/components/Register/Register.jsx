// src/components/Register.jsx
import React, { useState, useEffect } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import axios from 'axios';
import './Register.css';

// Configure axios
const API = axios.create({
    baseURL: 'http://localhost:5000/api',
});

const Register = () => {
    const [formData, setFormData] = useState({
        username: '',
        email: '',
        password: '',
        confirmPassword: '',
        fullName: '',
        phone: '',
        dateOfBirth: '',
        nationalId: '',
        address: '',
        termsAccepted: false
    });

    const [errors, setErrors] = useState({});
    const [loading, setLoading] = useState(false);
    const [success, setSuccess] = useState(false);
    const [availableElections, setAvailableElections] = useState([]);
    const [selectedElection, setSelectedElection] = useState('');
    const navigate = useNavigate();

    // Fetch available elections
    useEffect(() => {
        fetchAvailableElections();
    }, []);

    const fetchAvailableElections = async () => {
        try {
            const response = await API.get('/elections/active');
            if (response.data.success) {
                setAvailableElections(response.data.elections);
            }
        } catch (error) {
            console.error('Error fetching elections:', error);
        }
    };

    const handleChange = (e) => {
        const { name, value, type, checked } = e.target;
        setFormData(prev => ({
            ...prev,
            [name]: type === 'checkbox' ? checked : value
        }));
        
        // Clear error for this field when user starts typing
        if (errors[name]) {
            setErrors(prev => ({ ...prev, [name]: '' }));
        }
    };

    const validateForm = () => {
        const newErrors = {};

        // Username validation
        if (!formData.username.trim()) {
            newErrors.username = 'Username is required';
        } else if (formData.username.length < 3) {
            newErrors.username = 'Username must be at least 3 characters';
        } else if (!/^[a-zA-Z0-9_]+$/.test(formData.username)) {
            newErrors.username = 'Username can only contain letters, numbers, and underscores';
        }

        // Email validation
        if (!formData.email.trim()) {
            newErrors.email = 'Email is required';
        } else if (!/\S+@\S+\.\S+/.test(formData.email)) {
            newErrors.email = 'Email is invalid';
        }

        // Password validation
        if (!formData.password) {
            newErrors.password = 'Password is required';
        } else if (formData.password.length < 8) {
            newErrors.password = 'Password must be at least 8 characters';
        } else if (!/(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/.test(formData.password)) {
            newErrors.password = 'Password must contain uppercase, lowercase, and numbers';
        }

        // Confirm password validation
        if (formData.password !== formData.confirmPassword) {
            newErrors.confirmPassword = 'Passwords do not match';
        }

        // Full name validation
        if (!formData.fullName.trim()) {
            newErrors.fullName = 'Full name is required';
        }

        // Date of birth validation
        if (!formData.dateOfBirth) {
            newErrors.dateOfBirth = 'Date of birth is required';
        } else {
            const dob = new Date(formData.dateOfBirth);
            const today = new Date();
            const age = today.getFullYear() - dob.getFullYear();
            
            if (age < 18) {
                newErrors.dateOfBirth = 'You must be at least 18 years old to register';
            }
        }

        // National ID validation
        if (!formData.nationalId.trim()) {
            newErrors.nationalId = 'National ID is required';
        }

        // Terms acceptance validation
        if (!formData.termsAccepted) {
            newErrors.termsAccepted = 'You must accept the terms and conditions';
        }

        return newErrors;
    };

    const handleSubmit = async (e) => {
        e.preventDefault();
        setErrors({});

        const validationErrors = validateForm();
        if (Object.keys(validationErrors).length > 0) {
            setErrors(validationErrors);
            return;
        }

        setLoading(true);

        try {
            // Prepare registration data
            const registrationData = {
                username: formData.username,
                email: formData.email,
                password: formData.password,
                fullName: formData.fullName,
                phone: formData.phone || null,
                dateOfBirth: formData.dateOfBirth,
                nationalId: formData.nationalId,
                address: formData.address || null
            };

            // Send registration request
            const response = await API.post('/auth/register', registrationData);

            if (response.data.success) {
                // If user selected an election, register them for it
                if (selectedElection) {
                    try {
                        const token = response.data.token;
                        const electionResponse = await API.post(
                            `/elections/${selectedElection}/register`,
                            {},
                            {
                                headers: {
                                    'Authorization': `Bearer ${token}`
                                }
                            }
                        );

                        if (electionResponse.data.success) {
                            setSuccess(true);
                            
                            // Store user info and token
                            localStorage.setItem('token', token);
                            localStorage.setItem('user', JSON.stringify(response.data.user));
                            
                            // Auto login and redirect after 3 seconds
                            setTimeout(() => {
                                navigate('/home');
                            }, 3000);
                        }
                    } catch (electionError) {
                        console.error('Election registration error:', electionError);
                        // Still show success for account creation
                        setSuccess(true);
                        setTimeout(() => {
                            navigate('/login');
                        }, 3000);
                    }
                } else {
                    setSuccess(true);
                    setTimeout(() => {
                        navigate('/login');
                    }, 3000);
                }
            } else {
                setErrors({ general: response.data.error || 'Registration failed' });
            }
        } catch (error) {
            console.error('Registration error:', error);
            
            if (error.response) {
                if (error.response.status === 409) {
                    setErrors({ general: 'User with this email or username already exists' });
                } else if (error.response.status === 400) {
                    const backendErrors = error.response.data.errors;
                    if (backendErrors) {
                        const formattedErrors = {};
                        backendErrors.forEach(err => {
                            formattedErrors[err.path] = err.msg;
                        });
                        setErrors(formattedErrors);
                    } else {
                        setErrors({ general: error.response.data.error || 'Validation failed' });
                    }
                } else {
                    setErrors({ general: error.response.data.error || 'Registration failed' });
                }
            } else if (error.request) {
                setErrors({ general: 'Unable to connect to server. Please try again.' });
            } else {
                setErrors({ general: 'An unexpected error occurred' });
            }
        } finally {
            setLoading(false);
        }
    };

    // Mock registration for development
    const mockRegistration = () => {
        setLoading(true);
        setTimeout(() => {
            setSuccess(true);
            setLoading(false);
            setTimeout(() => {
                navigate('/login');
            }, 3000);
        }, 2000);
    };

    if (success) {
        return (
            <div className="register-container">
                <div className="register-card success-card">
                    <div className="success-icon">✅</div>
                    <h2 className="success-title">Registration Successful!</h2>
                    <p className="success-message">
                        Your account has been created successfully. 
                        {selectedElection && ' You have also been registered for the selected election.'}
                    </p>
                    <p className="success-note">
                        {selectedElection 
                            ? 'You will be redirected to your dashboard shortly...'
                            : 'Please check your email to verify your account. Redirecting to login...'}
                    </p>
                    <Link to="/login" className="btn btn-primary">
                        Go to Login
                    </Link>
                </div>
            </div>
        );
    }

    return (
        <div className="register-container">
            <div className="register-card">
                <div className="register-header">
                    <div className="logo-container">
                        <div className="logo">🗳️</div>
                        <h1 className="register-title">Voter Registration</h1>
                    </div>
                    <p className="register-subtitle">
                        Create an account to participate in elections
                    </p>
                </div>

                <form onSubmit={handleSubmit} className="register-form" noValidate>
                    {errors.general && (
                        <div className="error-message general-error">
                            <span className="error-icon">⚠️</span>
                            {errors.general}
                        </div>
                    )}

                    <div className="form-section">
                        <h3 className="section-title">Account Information</h3>
                        
                        <div className="form-row">
                            <div className="form-group">
                                <label htmlFor="username" className="form-label">
                                    Username *
                                </label>
                                <input
                                    type="text"
                                    id="username"
                                    name="username"
                                    value={formData.username}
                                    onChange={handleChange}
                                    placeholder="Choose a username"
                                    className={`form-input ${errors.username ? 'error' : ''}`}
                                    disabled={loading}
                                />
                                {errors.username && (
                                    <span className="field-error">{errors.username}</span>
                                )}
                            </div>

                            <div className="form-group">
                                <label htmlFor="email" className="form-label">
                                    Email Address *
                                </label>
                                <input
                                    type="email"
                                    id="email"
                                    name="email"
                                    value={formData.email}
                                    onChange={handleChange}
                                    placeholder="your.email@example.com"
                                    className={`form-input ${errors.email ? 'error' : ''}`}
                                    disabled={loading}
                                />
                                {errors.email && (
                                    <span className="field-error">{errors.email}</span>
                                )}
                            </div>
                        </div>

                        <div className="form-row">
                            <div className="form-group">
                                <label htmlFor="password" className="form-label">
                                    Password *
                                </label>
                                <input
                                    type="password"
                                    id="password"
                                    name="password"
                                    value={formData.password}
                                    onChange={handleChange}
                                    placeholder="Create a strong password"
                                    className={`form-input ${errors.password ? 'error' : ''}`}
                                    disabled={loading}
                                />
                                {errors.password && (
                                    <span className="field-error">{errors.password}</span>
                                )}
                                <div className="password-hint">
                                    Must be at least 8 characters with uppercase, lowercase, and numbers
                                </div>
                            </div>

                            <div className="form-group">
                                <label htmlFor="confirmPassword" className="form-label">
                                    Confirm Password *
                                </label>
                                <input
                                    type="password"
                                    id="confirmPassword"
                                    name="confirmPassword"
                                    value={formData.confirmPassword}
                                    onChange={handleChange}
                                    placeholder="Re-enter your password"
                                    className={`form-input ${errors.confirmPassword ? 'error' : ''}`}
                                    disabled={loading}
                                />
                                {errors.confirmPassword && (
                                    <span className="field-error">{errors.confirmPassword}</span>
                                )}
                            </div>
                        </div>
                    </div>

                    <div className="form-section">
                        <h3 className="section-title">Personal Information</h3>
                        
                        <div className="form-row">
                            <div className="form-group">
                                <label htmlFor="fullName" className="form-label">
                                    Full Name *
                                </label>
                                <input
                                    type="text"
                                    id="fullName"
                                    name="fullName"
                                    value={formData.fullName}
                                    onChange={handleChange}
                                    placeholder="Enter your full legal name"
                                    className={`form-input ${errors.fullName ? 'error' : ''}`}
                                    disabled={loading}
                                />
                                {errors.fullName && (
                                    <span className="field-error">{errors.fullName}</span>
                                )}
                            </div>

                            <div className="form-group">
                                <label htmlFor="dateOfBirth" className="form-label">
                                    Date of Birth *
                                </label>
                                <input
                                    type="date"
                                    id="dateOfBirth"
                                    name="dateOfBirth"
                                    value={formData.dateOfBirth}
                                    onChange={handleChange}
                                    className={`form-input ${errors.dateOfBirth ? 'error' : ''}`}
                                    disabled={loading}
                                    max={new Date().toISOString().split('T')[0]}
                                />
                                {errors.dateOfBirth && (
                                    <span className="field-error">{errors.dateOfBirth}</span>
                                )}
                            </div>
                        </div>

                        <div className="form-row">
                            <div className="form-group">
                                <label htmlFor="nationalId" className="form-label">
                                    National ID Number *
                                </label>
                                <input
                                    type="text"
                                    id="nationalId"
                                    name="nationalId"
                                    value={formData.nationalId}
                                    onChange={handleChange}
                                    placeholder="Enter your national ID"
                                    className={`form-input ${errors.nationalId ? 'error' : ''}`}
                                    disabled={loading}
                                />
                                {errors.nationalId && (
                                    <span className="field-error">{errors.nationalId}</span>
                                )}
                            </div>

                            <div className="form-group">
                                <label htmlFor="phone" className="form-label">
                                    Phone Number
                                </label>
                                <input
                                    type="tel"
                                    id="phone"
                                    name="phone"
                                    value={formData.phone}
                                    onChange={handleChange}
                                    placeholder="Optional phone number"
                                    className="form-input"
                                    disabled={loading}
                                />
                            </div>
                        </div>

                        <div className="form-group">
                            <label htmlFor="address" className="form-label">
                                Address
                            </label>
                            <textarea
                                id="address"
                                name="address"
                                value={formData.address}
                                onChange={handleChange}
                                placeholder="Enter your residential address (optional)"
                                className="form-input textarea"
                                rows="3"
                                disabled={loading}
                            />
                        </div>
                    </div>

                    <div className="form-section">
                        <h3 className="section-title">Election Registration</h3>
                        
                        <div className="form-group">
                            <label htmlFor="election" className="form-label">
                                Select Election to Join
                            </label>
                            <select
                                id="election"
                                name="election"
                                value={selectedElection}
                                onChange={(e) => setSelectedElection(e.target.value)}
                                className="form-input select"
                                disabled={loading || availableElections.length === 0}
                            >
                                <option value="">-- Select an election (optional) --</option>
                                {availableElections.map(election => (
                                    <option key={election.election_id} value={election.election_id}>
                                        {election.election_name} ({election.status})
                                    </option>
                                ))}
                            </select>
                            {availableElections.length === 0 && (
                                <div className="info-note">
                                    No elections are currently accepting registrations
                                </div>
                            )}
                        </div>
                    </div>

                    <div className="form-section">
                        <div className="terms-container">
                            <label className="checkbox-container">
                                <input
                                    type="checkbox"
                                    id="termsAccepted"
                                    name="termsAccepted"
                                    checked={formData.termsAccepted}
                                    onChange={handleChange}
                                    disabled={loading}
                                />
                                <span className={`checkmark ${errors.termsAccepted ? 'error' : ''}`}></span>
                                <span className="terms-text">
                                    I agree to the{' '}
                                    <a href="/terms" target="_blank" rel="noopener noreferrer">
                                        Terms of Service
                                    </a>{' '}
                                    and{' '}
                                    <a href="/privacy" target="_blank" rel="noopener noreferrer">
                                        Privacy Policy
                                    </a>
                                    *
                                </span>
                            </label>
                            {errors.termsAccepted && (
                                <span className="field-error">{errors.termsAccepted}</span>
                            )}
                        </div>

                        <div className="verification-note">
                            <span className="info-icon">ℹ️</span>
                            <span>
                                After registration, you will need to verify your email address 
                                before you can vote.
                            </span>
                        </div>
                    </div>

                    <div className="form-actions">
                        <button 
                            type="submit" 
                            className="register-btn primary-btn"
                            disabled={loading}
                        >
                            {loading ? (
                                <>
                                    <span className="spinner"></span>
                                    Creating Account...
                                </>
                            ) : (
                                'Complete Registration'
                            )}
                        </button>

                        
                    </div>

                    <div className="register-footer">
                        <p className="login-link">
                            Already have an account?{' '}
                            <Link to="/login" className="login-cta">
                                Sign in here
                            </Link>
                        </p>
                        <div className="security-info">
                            <span className="security-icon">🔒</span>
                            <span className="security-text">
                                All information is encrypted and securely stored
                            </span>
                        </div>
                    </div>
                </form>
            </div>
        </div>
    );
};

export default Register;