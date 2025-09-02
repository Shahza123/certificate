import React, { createContext, useContext, useState, useEffect } from 'react';

const AuthContext = createContext();

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};

export const AuthProvider = ({ children }) => {
  const [currentUser, setCurrentUser] = useState(null);
  const [loading, setLoading] = useState(true);
  const [isAuthenticated, setIsAuthenticated] = useState(false);

  // Mock user data - in real app, this would come from your backend
  const mockUsers = [
    {
      id: 1,
      username: 'admin',
      email: 'admin@wacman.com',
      role: 'admin',
      name: 'System Administrator',
      permissions: ['read', 'write', 'delete', 'admin']
    },
    {
      id: 2,
      username: 'ca-manager',
      email: 'ca-manager@wacman.com',
      role: 'ca-manager',
      name: 'CA Manager',
      permissions: ['read', 'write', 'validate']
    },
    {
      id: 3,
      username: 'user',
      email: 'user@wacman.com',
      role: 'user',
      name: 'Regular User',
      permissions: ['read']
    }
  ];

  useEffect(() => {
    // Check if user is logged in (check localStorage or session)
    const savedUser = localStorage.getItem('wacman_user');
    if (savedUser) {
      try {
        const user = JSON.parse(savedUser);
        setCurrentUser(user);
        setIsAuthenticated(true);
      } catch (error) {
        console.error('Error parsing saved user:', error);
        localStorage.removeItem('wacman_user');
      }
    }
    setLoading(false);
  }, []);

  const login = async (credentials) => {
    try {
      setLoading(true);
      
      // Simulate API call delay
      await new Promise(resolve => setTimeout(resolve, 1000));
      
      // Find user in mock data
      const user = mockUsers.find(u => 
        u.username === credentials.username && 
        credentials.password === 'password' // In real app, this would be hashed
      );
      
      if (user) {
        const userData = {
          ...user,
          loginTime: new Date().toISOString(),
          sessionId: Math.random().toString(36).substr(2, 9)
        };
        
        setCurrentUser(userData);
        setIsAuthenticated(true);
        localStorage.setItem('wacman_user', JSON.stringify(userData));
        
        return { success: true, user: userData };
      } else {
        throw new Error('Invalid credentials');
      }
    } catch (error) {
      return { success: false, error: error.message };
    } finally {
      setLoading(false);
    }
  };

  const logout = () => {
    setCurrentUser(null);
    setIsAuthenticated(false);
    localStorage.removeItem('wacman_user');
  };

  const hasPermission = (permission) => {
    if (!currentUser) return false;
    return currentUser.permissions.includes(permission);
  };

  const hasRole = (role) => {
    if (!currentUser) return false;
    return currentUser.role === role;
  };

  const value = {
    currentUser,
    isAuthenticated,
    loading,
    login,
    logout,
    hasPermission,
    hasRole
  };

  return (
    <AuthContext.Provider value={value}>
      {children}
    </AuthContext.Provider>
  );
};
