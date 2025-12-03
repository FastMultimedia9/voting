import React from 'react';
import './CandidateCard.css';

const CandidateCard = ({ candidate, onVote, voted }) => {
  const { name, role, party, votes, id } = candidate;

  return (
    <div className="candidate-card">
      <div className="candidate-avatar">
        {name.charAt(0)}
      </div>
      <h3>{name}</h3>
      <p className="role">{role}</p>
      <p className="party">{party}</p>
      <div className="vote-count">
        Votes: <strong>{votes}</strong>
      </div>
      <button 
        className="vote-btn"
        onClick={() => onVote(id)}
        disabled={voted}
      >
        {voted ? 'Voted' : 'Vote'}
      </button>
    </div>
  );
};

export default CandidateCard;