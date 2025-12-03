import React, { useState } from 'react';
import './AdminPanel.css';

const AdminPanel = ({ onResetVotes, onAddCandidate }) => {
  const [newCandidate, setNewCandidate] = useState({
    name: '',
    role: 'President',
    party: ''
  });

  const handleSubmit = (e) => {
    e.preventDefault();
    if (newCandidate.name && newCandidate.party) {
      onAddCandidate(newCandidate);
      setNewCandidate({ name: '', role: 'President', party: '' });
    }
  };

  return (
    <div className="admin-panel">
      <h3>Admin Controls</h3>
      
      <div className="admin-section">
        <h4>Reset Votes</h4>
        <p>Warning: This will reset all votes to zero.</p>
        <button 
          className="btn btn-danger"
          onClick={onResetVotes}
        >
          Reset All Votes
        </button>
      </div>

      <div className="admin-section">
        <h4>Add New Candidate</h4>
        <form onSubmit={handleSubmit}>
          <div className="form-group">
            <label>Name</label>
            <input
              type="text"
              value={newCandidate.name}
              onChange={(e) => setNewCandidate({...newCandidate, name: e.target.value})}
              placeholder="Candidate name"
              required
            />
          </div>
          
          <div className="form-group">
            <label>Position</label>
            <select
              value={newCandidate.role}
              onChange={(e) => setNewCandidate({...newCandidate, role: e.target.value})}
            >
              <option value="President">President</option>
              <option value="Vice President">Vice President</option>
              <option value="Secretary">Secretary</option>
            </select>
          </div>
          
          <div className="form-group">
            <label>Party</label>
            <input
              type="text"
              value={newCandidate.party}
              onChange={(e) => setNewCandidate({...newCandidate, party: e.target.value})}
              placeholder="Political party"
              required
            />
          </div>
          
          <button type="submit" className="btn btn-primary">
            Add Candidate
          </button>
        </form>
      </div>
    </div>
  );
};

export default AdminPanel;