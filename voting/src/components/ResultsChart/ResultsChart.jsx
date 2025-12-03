import React from 'react';
import './ResultsChart.css';

const ResultsChart = ({ candidates }) => {
  const totalVotes = candidates.reduce((sum, c) => sum + c.votes, 0);

  return (
    <div className="results-chart">
      <h3>Live Results</h3>
      <div className="chart-container">
        {candidates.map((candidate, index) => {
          const percentage = totalVotes > 0 ? (candidate.votes / totalVotes * 100) : 0;
          const colors = ['#3b82f6', '#10b981', '#8b5cf6', '#f59e0b'];
          
          return (
            <div key={candidate.id} className="chart-item">
              <div className="chart-label">
                <span className="candidate-name">{candidate.name}</span>
                <span className="candidate-votes">{candidate.votes} votes ({percentage.toFixed(1)}%)</span>
              </div>
              <div className="chart-bar-container">
                <div 
                  className="chart-bar"
                  style={{ 
                    width: `${percentage}%`,
                    backgroundColor: colors[index % colors.length]
                  }}
                ></div>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
};

export default ResultsChart;