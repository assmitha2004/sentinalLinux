import { useEffect, useState } from 'react';
import { useAuth } from '../context/AuthContext.jsx';
import { useApi } from '../hooks/useApi.js';
import { api, errorMessage } from '../services/api.js';
import { dateTime } from '../utils/format.js';
import { Async, Command, Severity } from './ui.jsx';

const STATUSES = [['ACKNOWLEDGED', 'Acknowledge'], ['RESOLVED', 'Mark resolved'], ['FALSE_POSITIVE', 'Mark false positive'], ['OPEN', 'Reopen']];

export default function FindingDrawer({ id, onClose, onChanged }) {
  const q = useApi(`/findings/${id}`);
  const { can } = useAuth();
  const [err, setErr] = useState(null);
  useEffect(() => {
    const onKey = (e) => e.key === 'Escape' && onClose();
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [onClose]);

  const setStatus = async (status) => {
    setErr(null);
    try { await api('patch', `/findings/${id}`, { status }); await q.reload(true); onChanged?.(); } catch (e) { setErr(errorMessage(e)); }
  };

  return (
    <>
      <div className="drawer-back" onClick={onClose} aria-hidden="true" />
      <aside className="drawer" role="dialog" aria-modal="true" aria-label="Finding detail">
        <button type="button" className="btn btn-small" onClick={onClose} style={{ float: 'right' }}>Close</button>
        <Async q={q} what="finding">{(f) => (
          <>
            <div className="row" style={{ marginBottom: 8 }}><Severity value={f.severity} /><span className="muted small">{f.category}, confidence {Math.round((f.confidence ?? 0) * 100)}%</span></div>
            <h2>{f.title}</h2>
            <section><h4>What happened</h4><p>{f.description}</p></section>
            <section><h4>Why it matters</h4><p>{f.whyItMatters}</p></section>
            <section>
              <h4>Evidence</h4>
              <pre className="evidence mono">{JSON.stringify(f.evidence, null, 2)}</pre>
            </section>
            <section>
              <dl className="kv">
                <dt>Host</dt><dd>{f.hostId?.hostname}</dd>
                <dt>Affected resource</dt><dd className="mono">{f.resource || '—'}</dd>
                <dt>Status</dt><dd>{f.status.replace('_', ' ').toLowerCase()}</dd>
                <dt>First seen</dt><dd>{dateTime(f.firstSeen)}</dd>
                <dt>Last seen</dt><dd>{dateTime(f.lastSeen)} ({f.occurrences ?? 1} scans)</dd>
                <dt>Source</dt><dd>{f.source}</dd>
              </dl>
            </section>
            <section>
              <h4>What to do</h4>
              {f.requiresAdminApproval && <p className="approval">Requires administrator approval. SentinelAI never applies this change itself.</p>}
              <p>{f.recommendation}</p>
              {f.remediation?.steps?.length > 1 && <ol>{f.remediation.steps.map((s) => <li key={s}>{s}</li>)}</ol>}
            </section>
            <section>
              <h4>How to verify</h4>
              <Command command={f.verification?.command} />
              {f.remediation?.modifying && <><h4 style={{ marginTop: 12 }}>Possible fix</h4><Command command={f.remediation.modifying} modifying /></>}
            </section>
            {can('ADMIN') && (
              <section>
                <h4>Triage</h4>
                <div className="row">{STATUSES.filter(([s]) => s !== f.status).map(([s, label]) => <button type="button" key={s} className="btn btn-small" onClick={() => setStatus(s)}>{label}</button>)}</div>
                {err && <p className="st-ERROR small" role="alert">{err}</p>}
              </section>
            )}
          </>
        )}</Async>
      </aside>
    </>
  );
}
