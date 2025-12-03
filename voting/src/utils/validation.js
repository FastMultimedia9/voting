export const validateEmail = (email) => {
  const re = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return re.test(email);
};

export const validatePassword = (password) => {
  return password.length >= 6;
};

export const validateCandidate = (candidate) => {
  const errors = {};
  
  if (!candidate.name || candidate.name.trim().length < 2) {
    errors.name = 'Name must be at least 2 characters';
  }
  
  if (!candidate.role) {
    errors.role = 'Role is required';
  }
  
  if (!candidate.party || candidate.party.trim().length < 2) {
    errors.party = 'Party name is required';
  }
  
  return {
    isValid: Object.keys(errors).length === 0,
    errors
  };
};