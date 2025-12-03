const authService = {
  login: async (email, password) => {
    // Simulate API call
    return new Promise((resolve) => {
      setTimeout(() => {
        if (email === 'admin@vote.com' && password === 'password123') {
          resolve({
            success: true,
            user: {
              id: 1,
              email,
              name: 'Admin User',
              role: 'admin'
            },
            token: 'fake-jwt-token'
          });
        } else if (email === 'user@vote.com' && password === 'password123') {
          resolve({
            success: true,
            user: {
              id: 2,
              email,
              name: 'Regular User',
              role: 'user'
            },
            token: 'fake-jwt-token'
          });
        } else {
          resolve({
            success: false,
            message: 'Invalid credentials'
          });
        }
      }, 1000);
    });
  },

  logout: () => {
    return Promise.resolve({ success: true });
  },

  getCurrentUser: () => {
    const user = localStorage.getItem('currentUser');
    return user ? JSON.parse(user) : null;
  }
};

export default authService;