import { createContext, useContext, useState, useEffect } from 'react';
import { api } from '../api/client';

const AuthContext = createContext(null);

export function AuthProvider({ children }) {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const token = api.getToken();
    if (token) {
      api.get('/auth/me', { noRedirect: true })
        .then(data => setUser(data.user))
        .catch(() => api.setToken(null))
        .finally(() => setLoading(false));
    } else {
      setLoading(false);
    }
  }, []);

  const login = async (email, password) => {
    const data = await api.post('/auth/login', { email, password });
    api.setToken(data.token);
    setUser(data.user);
    return data;
  };

  const register = async (name, email, password) => {
    const data = await api.post('/auth/register', { name, email, password });
    api.setToken(data.token);
    setUser(data.user);
    return data;
  };

  const logout = () => {
    api.setToken(null);
    setUser(null);
  };

  const refreshUser = async () => {
    try {
      const data = await api.get('/auth/me', { noRedirect: true });
      setUser(data.user);
    } catch { /* ignore */ }
  };

  return (
    <AuthContext.Provider value={{ user, loading, login, register, logout, refreshUser }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error('useAuth must be used within AuthProvider');
  return ctx;
}
