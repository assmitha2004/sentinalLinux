export const SEVERITIES = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];
export const SEV_COLOR = { CRITICAL: 'var(--sev-critical)', HIGH: 'var(--sev-high)', MEDIUM: 'var(--sev-medium)', LOW: 'var(--sev-low)', INFO: 'var(--sev-info)' };

export function bytes(n) {
  if (n == null || Number.isNaN(n)) return '—';
  const u = ['B', 'KB', 'MB', 'GB', 'TB'];
  let i = 0; let v = n;
  while (v >= 1024 && i < u.length - 1) { v /= 1024; i += 1; }
  return `${v.toFixed(v < 10 && i ? 1 : 0)} ${u[i]}`;
}
export const rate = (n) => (n == null ? '—' : `${bytes(n)}/s`);
export const pct = (n) => (n == null ? '—' : `${Math.round(n)}%`);

export function ago(t) {
  if (!t) return 'never';
  const s = Math.max(0, Math.round((Date.now() - new Date(t).getTime()) / 1000));
  if (s < 60) return `${s}s ago`;
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  return `${Math.floor(s / 86400)}d ago`;
}
export const dateTime = (t) => (t ? new Date(t).toLocaleString() : '—');
export function duration(sec) {
  if (sec == null) return '—';
  const d = Math.floor(sec / 86400); const h = Math.floor((sec % 86400) / 3600); const m = Math.floor((sec % 3600) / 60);
  return d ? `${d}d ${h}h` : h ? `${h}h ${m}m` : `${m}m`;
}
export const levelText = (l) => (l ? l.replace('_', ' ').toLowerCase().replace(/^\w/, (c) => c.toUpperCase()) : '—');
export const statusText = (s) => (s ? s.replace(/_/g, ' ').toLowerCase().replace(/^\w/, (c) => c.toUpperCase()) : '—');
export const healthWord = (h) => (h == null ? 'No data' : h >= 85 ? 'Healthy' : h >= 65 ? 'Under pressure' : 'Degraded');
