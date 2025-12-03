// src/components/Header/Header.jsx - FIXED
import React from 'react';
import { Link } from 'react-router-dom';
import './Header.css';

const Header = () => {
  return (
    <header className="header">
      <div className="container">
        <nav className="navbar">
          <div className="logo">
            <Link to="/">🗳️ Voting System</Link>
          </div>
          <ul className="nav-menu">
            <li><Link to="/">Home</Link></li>
            <li><Link to="/vote">Vote</Link></li>
            <li><Link to="/results">Results</Link></li>
            <li><Link to="/about">About</Link></li>
            <li><Link to="/admin">Admin</Link></li>
            <li><Link to="/login" className="login-btn">Login</Link></li>
          </ul>
        </nav>
      </div>
    </header>
  );
};

export default Header;