// src/pages/HomePage/HomePage.jsx - FIXED
import React from 'react';
import { Link } from 'react-router-dom';
import './HomePage.css';

const HomePage = () => {
  return (
    <div className="home-page">
      <div className="hero">
        <h1>Welcome to Secure Voting System</h1>
        <p className="subtitle">A transparent, secure, and modern voting platform</p>
        <div className="cta-buttons">
          <Link to="/vote" className="btn btn-primary">Start Voting</Link>
          <Link to="/results" className="btn btn-secondary">View Results</Link>
        </div>
      </div>

      {/* ... rest of your HomePage component ... */}
    </div>
  );
};

export default HomePage;