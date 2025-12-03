import React, { createContext, useState, useContext, useEffect } from 'react';

const VotingContext = createContext();

export const useVoting = () => useContext(VotingContext);

const initialCandidates = [
  { 
    id: 1, 
    name: 'Alice Johnson', 
    role: 'President', 
    votes: 42,
    description: 'Experienced leader with 10 years in public service',
    party: 'Progressive Party',
    image: null
  },
  { 
    id: 2, 
    name: 'Bob Smith', 
    role: 'President', 
    votes: 38,
    description: 'Business entrepreneur focused on economic growth',
    party: 'Unity Party',
    image: null
  },
  { 
    id: 3, 
    name: 'Carol Davis', 
    role: 'Vice President', 
    votes: 56,
    description: 'Education reform advocate and former teacher',
    party: 'Progressive Party',
    image: null
  },
  { 
    id: 4, 
    name: 'David Wilson', 
    role: 'Vice President', 
    votes: 45,
    description: 'Technology innovator and environmental activist',
    party: 'Green Future Party',
    image: null
  },
];

export const VotingProvider = ({ children }) => {
  const [candidates, setCandidates] = useState(() => {
    const saved = localStorage.getItem('voting-system-candidates');
    return saved ? JSON.parse(saved) : initialCandidates;
  });

  const [voted, setVoted] = useState(() => {
    return localStorage.getItem('voting-system-voted') === 'true';
  });

  const [voterId, setVoterId] = useState(() => {
    return localStorage.getItem('voting-system-voterId');
  });

  const [votesHistory, setVotesHistory] = useState(() => {
    const saved = localStorage.getItem('voting-system-history');
    return saved ? JSON.parse(saved) : [];
  });

  useEffect(() => {
    localStorage.setItem('voting-system-candidates', JSON.stringify(candidates));
  }, [candidates]);

  useEffect(() => {
    localStorage.setItem('voting-system-voted', voted.toString());
  }, [voted]);

  useEffect(() => {
    if (voterId) {
      localStorage.setItem('voting-system-voterId', voterId);
    }
  }, [voterId]);

  useEffect(() => {
    localStorage.setItem('voting-system-history', JSON.stringify(votesHistory));
  }, [votesHistory]);

  const castVote = (candidateId) => {
    if (voted) {
      return { success: false, message: 'You have already voted!' };
    }

    const candidate = candidates.find(c => c.id === candidateId);
    if (!candidate) {
      return { success: false, message: 'Candidate not found' };
    }

    const updatedCandidates = candidates.map(candidate =>
      candidate.id === candidateId
        ? { ...candidate, votes: candidate.votes + 1 }
        : candidate
    );

    setCandidates(updatedCandidates);
    setVoted(true);
    
    const newVoterId = 'VOTER-' + Date.now();
    setVoterId(newVoterId);

    const voteRecord = {
      voterId: newVoterId,
      candidateId,
      candidateName: candidate.name,
      role: candidate.role,
      timestamp: new Date().toISOString()
    };

    setVotesHistory(prev => [...prev, voteRecord]);

    return { 
      success: true, 
      message: 'Vote cast successfully!',
      voterId: newVoterId,
      candidate: candidate.name
    };
  };

  const resetVotes = () => {
    setCandidates(candidates.map(c => ({ ...c, votes: 0 })));
    setVoted(false);
    setVoterId(null);
    setVotesHistory([]);
  };

  const addCandidate = (candidate) => {
    const newCandidate = {
      id: candidates.length > 0 ? Math.max(...candidates.map(c => c.id)) + 1 : 1,
      ...candidate,
      votes: 0,
      image: null
    };
    
    setCandidates([...candidates, newCandidate]);
    return newCandidate;
  };

  const removeCandidate = (candidateId) => {
    setCandidates(candidates.filter(c => c.id !== candidateId));
  };

  const getResultsByRole = () => {
    const roles = [...new Set(candidates.map(c => c.role))];
    return roles.map(role => ({
      role,
      candidates: candidates
        .filter(c => c.role === role)
        .sort((a, b) => b.votes - a.votes)
    }));
  };

  const getTotalVotes = () => {
    return candidates.reduce((total, candidate) => total + candidate.votes, 0);
  };

  const value = {
    candidates,
    voted,
    voterId,
    votesHistory,
    castVote,
    resetVotes,
    addCandidate,
    removeCandidate,
    getResultsByRole,
    getTotalVotes
  };

  return (
    <VotingContext.Provider value={value}>
      {children}
    </VotingContext.Provider>
  );
};