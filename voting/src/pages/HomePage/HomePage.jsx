// src/pages/HomePage.js (rename to HomePage.jsx)
import React from 'react';
import './HomePage.css'; // If you have CSS

const HomePage = () => {
  return (
    <div className="home-page">
      <h1>Welcome to Voting System</h1>
      <p>This is the home page where users can view active elections and their status.</p>
      <div style={{ marginTop: '20px' }}>
        <h3>Features:</h3>
        <ul style={{ marginLeft: '20px', marginTop: '10px' }}>
          <li>View active elections</li>
          <li>Register to vote</li>
          <li>Access voting interface</li>
          <li>View election results</li>
          <li>Manage your profile</li>
        </ul>
      </div>
    </div>
  );
};

export default HomePage; // Changed from module.exports