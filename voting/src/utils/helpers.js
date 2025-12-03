export const formatNumber = (num) => {
  return new Intl.NumberFormat().format(num);
};

export const calculatePercentage = (votes, totalVotes) => {
  if (totalVotes === 0) return 0;
  return ((votes / totalVotes) * 100).toFixed(1);
};

export const generateVoterId = () => {
  return 'VOTER-' + Date.now() + '-' + Math.random().toString(36).substr(2, 9);
};

export const formatDate = (date) => {
  return new Date(date).toLocaleDateString('en-US', {
    year: 'numeric',
    month: 'long',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit'
  });
};