import React from 'react';
import './ResultsPage.css';

const candidates = [
  { id: 1, name: 'Alice Johnson', role: 'President', party: 'Progressive Party', votes: 156, color: '#3b82f6' },
  { id: 2, name: 'Bob Smith', role: 'President', party: 'Unity Party', votes: 98, color: '#10b981' },
  { id: 3, name: 'Carol Davis', role: 'Vice President', party: 'Progressive Party', votes: 142, color: '#8b5cf6' },
  { id: 4, name: 'David Wilson', role: 'Vice President', party: 'Green Future Party', votes: 112, color: '#f59e0b' },
];

const ResultsPage = () => {
  const totalVotes = candidates.reduce((sum, candidate) => sum + candidate.votes, 0);
  
  const getResultsByRole = (role) => {
    return candidates
      .filter(c => c.role === role)
      .sort((a, b) => b.votes - a.votes);
  };

  const presidentResults = getResultsByRole('President');
  const vicePresidentResults = getResultsByRole('Vice President');

  return (
    <div className="results-page">
      <div className="page-header">
        <h1>Live Voting Results</h1>
        <p className="subtitle">Real-time updates of the election results</p>
        <div className="total-votes">
          <span className="total-label">Total Votes Cast:</span>
          <span className="total-value">{totalVotes}</span>
        </div>
      </div>

      <div className="results-overview">
        <div className="overview-card">
          <h3>🏆 Current Leaders</h3>
          <div className="leaders">
            <div className="leader">
              <span className="position">President:</span>
              <span className="leader-name">{presidentResults[0]?.name}</span>
              <span className="leader-votes">{presidentResults[0]?.votes} votes</span>
            </div>
            <div className="leader">
              <span className="position">Vice President:</span>
              <span className="leader-name">{vicePresidentResults[0]?.name}</span>
              <span className="leader-votes">{vicePresidentResults[0]?.votes} votes</span>
            </div>
          </div>
        </div>
      </div>

      <div className="results-by-position">
        <div className="position-results">
          <h2>Presidential Race</h2>
          <div className="results-list">
            {presidentResults.map((candidate, index) => {
              const percentage = totalVotes > 0 ? (candidate.votes / totalVotes * 100).toFixed(1) : 0;
              return (
                <div key={candidate.id} className="result-item">
                  <div className="result-rank">
                    <span className="rank-number">{index + 1}</span>
                    <div className="candidate-info">
                      <h4>{candidate.name}</h4>
                      <span className="candidate-party">{candidate.party}</span>
                    </div>
                  </div>
                  <div className="result-stats">
                    <div className="vote-bar-container">
                      <div 
                        className="vote-bar"
                        style={{ 
                          width: `${percentage}%`,
                          backgroundColor: candidate.color
                        }}
                      ></div>
                    </div>
                    <div className="vote-numbers">
                      <span className="vote-count">{candidate.votes} votes</span>
                      <span className="vote-percentage">{percentage}%</span>
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        <div className="position-results">
          <h2>Vice Presidential Race</h2>
          <div className="results-list">
            {vicePresidentResults.map((candidate, index) => {
              const percentage = totalVotes > 0 ? (candidate.votes / totalVotes * 100).toFixed(1) : 0;
              return (
                <div key={candidate.id} className="result-item">
                  <div className="result-rank">
                    <span className="rank-number">{index + 1}</span>
                    <div className="candidate-info">
                      <h4>{candidate.name}</h4>
                      <span className="candidate-party">{candidate.party}</span>
                    </div>
                  </div>
                  <div className="result-stats">
                    <div className="vote-bar-container">
                      <div 
                        className="vote-bar"
                        style={{ 
                          width: `${percentage}%`,
                          backgroundColor: candidate.color
                        }}
                      ></div>
                    </div>
                    <div className="vote-numbers">
                      <span className="vote-count">{candidate.votes} votes</span>
                      <span className="vote-percentage">{percentage}%</span>
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      </div>

      <div className="results-summary">
        <h3>Summary Statistics</h3>
        <div className="summary-grid">
          <div className="summary-card">
            <h4>Voter Turnout</h4>
            <div className="summary-value">78%</div>
            <p>Based on registered voters</p>
          </div>
          <div className="summary-card">
            <h4>Leading Margin</h4>
            <div className="summary-value">58 votes</div>
            <p>Difference between top candidates</p>
          </div>
          <div className="summary-card">
            <h4>Last Update</h4>
            <div className="summary-value">Just now</div>
            <p>Results update every minute</p>
          </div>
        </div>
      </div>

      <div className="results-actions">
        <button className="btn btn-primary">Refresh Results</button>
        <button className="btn btn-secondary">Download Report</button>
        <button className="btn btn-secondary">Share Results</button>
      </div>
    </div>
  );
};

export default ResultsPage;