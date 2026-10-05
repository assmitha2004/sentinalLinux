import { useState } from 'react';
import { Async, Command, Empty } from '../components/ui.jsx';
import { useAuth } from '../context/AuthContext.jsx';
import { useApi } from '../hooks/useApi.js';
import { api, errorMessage } from '../services/api.js';
import { ago, dateTime } from '../utils/format.js';

function Enrollment() {
  const q = useApi('/agent/enrollment-tokens');
  const [form, setForm] = useState({ label: '', ttlHours: 24, maxUses: 1 });
  const [created, setCreated] = useState(null);
  const [err, setErr] = useState(null);
  const create = async (e) => {
    e.preventDefault(); setErr(null);
    try {
      const { data } = await api('post', '/agent/enrollment-tokens', { ...form, ttlHours: Number(form.ttlHours), maxUses: Number(form.maxUses) });
      setCreated(data); q.reload(true);
    } catch (e2) { setErr(errorMessage(e2)); }
  };
  const revoke = async (id) => { await api('delete', `/agent/enrollment-tokens/${id}`); q.reload(true); };
  const server = (import.meta.env.VITE_API_URL || 'http://localhost:5000/api/v1').replace(/\/api\/v1$/, '');
  return (
    <section className="panel">
      <div className="panel-head"><h2>Enroll a host</h2><p>Tokens are shown once and stored only as a hash.</p></div>
      <form className="row" onSubmit={create}>
        <label className="field">Label<input value={form.label} onChange={(e) => setForm({ ...form, label: e.target.value })} placeholder="e.g. lab workstations" /></label>
        <label className="field">Valid for (hours)<input type="number" min="1" max="720" value={form.ttlHours} onChange={(e) => setForm({ ...form, ttlHours: e.target.value })} /></label>
        <label className="field">Hosts it can enroll<input type="number" min="1" max="1000" value={form.maxUses} onChange={(e) => setForm({ ...form, maxUses: e.target.value })} /></label>
        <button type="submit" className="btn btn-primary" style={{ alignSelf: 'flex-end' }}>Create token</button>
      </form>
      {err && <p className="st-ERROR small" role="alert">{err}</p>}
      {created && (
        <div className="notice" style={{ marginTop: 14 }}>
          <p><strong>Copy this token now; it will not be shown again.</strong></p>
          <Command command={created.token} />
          <p className="small">Install the agent on the BOSS 10 host:</p>
          <Command modifying command={`sudo SENTINEL_SERVER_URL=${server} SENTINEL_AGENT_TOKEN=${created.token} ./install.sh`} note="Run from the agent/ directory of the SentinelAI repository on the host." />
        </div>
      )}
      <Async q={q} what="tokens">{(rows) => (rows.length ? (
        <div className="table-wrap" style={{ marginTop: 14 }}><table>
          <thead><tr><th>Label</th><th>Created</th><th>Expires</th><th className="num">Used</th><th>State</th><th /></tr></thead>
          <tbody>{rows.map((t) => {
            const state = t.revoked ? 'Revoked' : new Date(t.expiresAt) < new Date() ? 'Expired' : t.uses >= t.maxUses ? 'Used up' : 'Active';
            return <tr key={t._id}><td>{t.label || '—'}</td><td className="muted">{ago(t.createdAt)}</td><td className="muted">{dateTime(t.expiresAt)}</td><td className="num">{t.uses}/{t.maxUses}</td><td>{state}</td>
              <td>{state === 'Active' && <button type="button" className="btn btn-small btn-danger" onClick={() => revoke(t._id)}>Revoke</button>}</td></tr>;
          })}</tbody>
        </table></div>) : null)}</Async>
    </section>
  );
}

function Users() {
  const q = useApi('/users');
  const { user } = useAuth();
  const [err, setErr] = useState(null);
  const setRole = async (id, role) => { setErr(null); try { await api('patch', `/users/${id}`, { role }); q.reload(true); } catch (e) { setErr(errorMessage(e)); } };
  return (
    <section className="panel">
      <div className="panel-head"><h2>People</h2><p>Admins manage hosts and users; analysts run scans and analyses; viewers read only.</p></div>
      {err && <p className="st-ERROR small" role="alert">{err}</p>}
      <Async q={q} what="users">{(rows) => (
        <div className="table-wrap"><table>
          <thead><tr><th>Name</th><th>Email</th><th>Role</th><th>Joined</th></tr></thead>
          <tbody>{rows.map((u) => <tr key={u.id}><td>{u.name}</td><td>{u.email}</td>
            <td><select value={u.role} disabled={u.id === user.id} onChange={(e) => setRole(u.id, e.target.value)} aria-label={`Role for ${u.email}`}>{['ADMIN', 'ANALYST', 'VIEWER'].map((r) => <option key={r} value={r}>{r.charAt(0) + r.slice(1).toLowerCase()}</option>)}</select></td>
            <td className="muted">{ago(u.createdAt)}</td></tr>)}</tbody>
        </table></div>)}</Async>
    </section>
  );
}

function AuditTrail() {
  const q = useApi('/audit-logs', { limit: 50 });
  return (
    <section className="panel">
      <div className="panel-head"><h2>Audit trail</h2><p>Sign-ins, scans, triage and enrollment. Secrets are never recorded.</p></div>
      <Async q={q} what="audit log">{(rows) => (rows.length ? (
        <div className="table-wrap"><table>
          <thead><tr><th>When</th><th>Who</th><th>Action</th><th>Details</th></tr></thead>
          <tbody>{rows.map((l) => <tr key={l._id}><td className="muted" title={dateTime(l.timestamp)}>{ago(l.timestamp)}</td><td>{l.actor || '—'}</td><td className="mono">{l.action}</td><td className="small muted truncate">{l.metadata ? JSON.stringify(l.metadata) : ''}</td></tr>)}</tbody>
        </table></div>) : <Empty title="No activity recorded yet" />)}</Async>
    </section>
  );
}

export default function Settings() {
  const { can } = useAuth();
  const s = useApi('/settings');
  return (
    <>
      <div className="page-head"><div><h1>Settings</h1><p>Server configuration is read from the backend environment file.</p></div></div>
      <div className="stack">
        {can('ADMIN') && <Enrollment />}
        <section className="panel"><h2>Server configuration</h2>
          <Async q={s} what="settings">{(c) => (
            <dl className="kv">
              <dt>Heartbeat</dt><dd>every {c.heartbeatIntervalSec}s; degraded after {c.heartbeatIntervalSec * c.degradedMultiplier}s, offline after {c.heartbeatIntervalSec * c.offlineMultiplier}s</dd>
              <dt>Alert grouping</dt><dd>repeats within {c.alertCooldownMin} minutes are grouped</dd>
              <dt>Retention</dt><dd>metrics {c.retentionDays.metrics}d, resolved findings {c.retentionDays.findings}d, alerts {c.retentionDays.alerts}d, scans {c.retentionDays.scans}d, audit {c.retentionDays.audit}d</dd>
              <dt>AI provider</dt><dd>{c.ai.configured ? `${c.ai.provider} (${c.ai.model})` : 'Not configured; deterministic engine in use'}</dd>
              <dt>Anomaly baseline</dt><dd>needs {c.ml.minSamples} samples; flags robust z-score above {c.ml.zThreshold}</dd>
            </dl>)}</Async>
        </section>
        {can('ADMIN') && <Users />}
        {can('ADMIN') && <AuditTrail />}
      </div>
    </>
  );
}
