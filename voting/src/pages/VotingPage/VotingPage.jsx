import React, { useState } from 'react';
import './VotingPage.css';

const initialCandidates = [
  { id: 1, name: 'Alice Johnson', role: 'President', party: 'Progressive Party', votes: 0 },
  { id: 2, name: 'Bob Smith', role: 'President', party: 'Unity Party', votes: 0 },
  { id: 3, name: 'Carol Davis', role: 'Vice President', party: 'Progressive Party', votes: 0 },
  { id: 4, name: 'David Wilson', role: 'Vice President', party: 'Green Future Party', votes: 0 },
];

const VotingPage = () => {
  const [candidates, setCandidates] = useState(initialCandidates);
  const [selectedCandidate, setSelectedCandidate] = useState(null);
  const [hasVoted, setHasVoted] = useState(false);

  const handleVote = () => {
    if (!selectedCandidate) {
      alert('Please select a candidate first!');
      return;
    }

    if (hasVoted) {
      alert('You have already voted!');
      return;
    }

    setCandidates(prev =>
      prev.map(candidate =>
        candidate.id === selectedCandidate
          ? { ...candidate, votes: candidate.votes + 1 }
          : candidate
      )
    );
    
    setHasVoted(true);
    alert(`You voted for ${candidates.find(c => c.id === selectedCandidate)?.name}!`);
  };

  return (
    <div className="voting-page">
      <div className="page-header">
        <h1>Cast Your Vote</h1>
        <p>Select your preferred candidate for each position</p>
        {hasVoted && (
          <div className="alert alert-success">
            ✅ Thank you for voting! Your vote has been recorded.
          </div>
        )}
      </div>

      <div className="voting-instructions">
        <h3>Instructions:</h3>
        <ul>
          <li>Select one candidate per position</li>
          <li>You can only vote once</li>
          <li>Review your selection before submitting</li>
        </ul>
      </div>

      <div className="candidates-section">
        <h2>Presidential Candidates</h2>
        <div className="candidates-grid">
          {candidates
            .filter(c => c.role === 'President')
            .map(candidate => (
              <div 
                key={candidate.id}
                className={`candidate-card ${selectedCandidate === candidate.id ? 'selected' : ''}`}
                onClick={() => !hasVoted && setSelectedCandidate(candidate.id)}
              >
                <div className="candidate-avatar">
                  {candidate.name.charAt(0)}
                </div>
                <h3>{candidate.name}</h3>
                <p className="role">{candidate.role}</p>
                <p className="party">{candidate.party}</p>
                <div className="vote-count">
                  Votes: <strong>{candidate.votes}</strong>
                </div>
                <button 
                  className="btn btn-primary vote-btn"
                  onClick={(e) => {
                    e.stopPropagation();
                    setSelectedCandidate(candidate.id);
                  }}
                  disabled={hasVoted}
                >
                  {selectedCandidate === candidate.id ? 'Selected' : 'Select'}
                </button>
              </div>
            ))}
        </div>

        <h2>Vice Presidential Candidates</h2>
        <div className="candidates-grid">
          {candidates
            .filter(c => c.role === 'Vice President')
            .map(candidate => (
              <div 
                key={candidate.id}
                className={`candidate-card ${selectedCandidate === candidate.id ? 'selected' : ''}`}
                onClick={() => !hasVoted && setSelectedCandidate(candidate.id)}
              >
                <div className="candidate-avatar">
                  {candidate.name.charAt(0)}
                </div>
                <h3>{candidate.name}</h3>
                <p className="role">{candidate.role}</p>
                <p className="party">{candidate.party}</p>
                <div className="vote-count">
                  Votes: <strong>{candidate.votes}</strong>
                </div>
                <button 
                  className="btn btn-primary vote-btn"
                  onClick={(e) => {
                    e.stopPropagation();
                    setSelectedCandidate(candidate.id);
                  }}
                  disabled={hasVoted}
                >
                  {selectedCandidate === candidate.id ? 'Selected' : 'Select'}
                </button>
              </div>
            ))}
        </div>
      </div>

      <div className="voting-actions">
        <button 
          className="btn btn-success submit-vote"
          onClick={handleVote}
          disabled={hasVoted || !selectedCandidate}
        >
          {hasVoted ? 'Vote Submitted' : 'Submit Vote'}
        </button>
        
        {hasVoted && (
          <button 
            className="btn btn-secondary"
            onClick={() => window.location.reload()}
          >
            View Updated Results
          </button>
        )}
      </div>

      <div className="voting-info">
        <h3>Voting Statistics</h3>
        <div className="stats-grid">
          <div className="stat">
            <span className="stat-label">Total Candidates:</span>
            <span className="stat-value">{candidates.length}</span>
          </div>
          <div className="stat">
            <span className="stat-label">Total Votes Cast:</span>
            <span className="stat-value">{candidates.reduce((sum, c) => sum + c.votes, 0)}</span>
          </div>
          <div className="stat">
            <span className="stat-label">Your Status:</span>
            <span className="stat-value">{hasVoted ? 'Voted' : 'Not Voted'}</span>
          </div>
        </div>
      </div>
    </div>
  );
};

export default VotingPage;