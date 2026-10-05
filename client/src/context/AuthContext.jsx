import { createContext, useCallback, useContext, useEffect, useMemo, useState } from 'react';
import { api, setUnauthorizedHandler, tokenStore } from '../services/api.js';
import { closeSocket } from '../services/socket.js';

const AuthContext = createContext(null);
const LEVEL = { VIEWER: 1, ANALYST: 2, ADMIN: 3 };

export function AuthProvider({ children }) {
  const [user, setUser] = useState(null);
  const [ready, setReady] = useState(false);

  const clear = useCallback(() => { tokenStore.clear(); closeSocket(); setUser(null); }, []);

  useEffect(() => {
    setUnauthorizedHandler(clear);
    if (!tokenStore.get()) { setReady(true); return; }
    api('get', '/auth/me').then(({ data }) => setUser(data.user)).catch(clear).finally(() => setReady(true));
  }, [clear]);

  const login = useCallback(async (email, password) => {
    const { data } = await api('post', '/auth/login', { email, password });
    tokenStore.set(data.token); setUser(data.user);
  }, []);
  const register = useCallback(async (name, email, password) => {
    const { data } = await api('post', '/auth/register', { name, email, password });
    tokenStore.set(data.token); setUser(data.user);
  }, []);
  const logout = useCallback(async () => {
    try { await api('post', '/auth/logout'); } catch { /* token may already be invalid */ }
    clear();
  }, [clear]);

  const can = useCallback((role) => !!user && LEVEL[user.role] >= LEVEL[role], [user]);
  const value = useMemo(() => ({ user, ready, login, register, logout, can }), [user, ready, login, register, logout, can]);
  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export const useAuth = () => useContext(AuthContext);
