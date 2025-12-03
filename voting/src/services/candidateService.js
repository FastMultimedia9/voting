const candidateService = {
  getCandidates: async () => {
    const candidates = localStorage.getItem('candidates');
    return candidates ? JSON.parse(candidates) : [];
  },

  saveCandidates: async (candidates) => {
    localStorage.setItem('candidates', JSON.stringify(candidates));
    return { success: true };
  },

  addCandidate: async (candidate) => {
    const candidates = await candidateService.getCandidates();
    const newCandidate = {
      ...candidate,
      id: candidates.length > 0 ? Math.max(...candidates.map(c => c.id)) + 1 : 1,
      votes: 0
    };
    candidates.push(newCandidate);
    await candidateService.saveCandidates(candidates);
    return newCandidate;
  }
};

export default candidateService;