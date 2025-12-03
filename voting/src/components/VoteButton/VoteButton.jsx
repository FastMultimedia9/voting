import React from 'react';
import './VoteButton.css';

const VoteButton = ({ onClick, disabled, children }) => {
  return (
    <button 
      className={`vote-button ${disabled ? 'disabled' : ''}`}
      onClick={onClick}
      disabled={disabled}
    >
      {children}
    </button>
  );
};

export default VoteButton;