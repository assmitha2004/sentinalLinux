import axios from 'axios';
import { demoAdapter } from './demo.js';

export const DEMO_MODE = import.meta.env.VITE_DEMO_MODE === 'true';
const TOKEN_KEY = 'sentinel_token';

export const tokenStore = {
  get: () => { try { return sessionStorage.getItem(TOKEN_KEY); } catch { return null; } },
  set: (t) => { try { sessionStorage.setItem(TOKEN_KEY, t); } catch { /* storage unavailable */ } },
  clear: () => { try { sessionStorage.removeItem(TOKEN_KEY); } catch { /* ignore */ } },
};

export const http = axios.create({
  baseURL: import.meta.env.VITE_API_URL || 'http://localhost:5000/api/v1',
  timeout: 30000,
  ...(DEMO_MODE ? { adapter: demoAdapter } : {}),
});

http.interceptors.request.use((cfg) => {
  const t = tokenStore.get();
  if (t) cfg.headers.Authorization = `Bearer ${t}`;
  return cfg;
});

let onUnauthorized = () => {};
export const setUnauthorizedHandler = (fn) => { onUnauthorized = fn; };

http.interceptors.response.use((r) => r, (err) => {
  if (err.response?.status === 401 && !err.config?.url?.startsWith('/auth/')) onUnauthorized();
  return Promise.reject(err);
});

/** Unwraps the {success, data, meta} envelope. */
export async function api(method, url, body, params) {
  const r = await http.request({ method, url, data: body, params });
  return { data: r.data.data, meta: r.data.meta };
}

export function errorMessage(err) {
  const e = err?.response?.data?.error;
  if (e?.details?.length) return `${e.message}: ${e.details.map((d) => `${d.path} ${d.message}`).join('; ')}`;
  if (e?.message) return e.message;
  if (err?.code === 'ERR_NETWORK') return 'Cannot reach the SentinelAI server. Check that the backend is running and VITE_API_URL is correct.';
  return err?.message || 'Request failed';
}
