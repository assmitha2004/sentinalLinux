import { useState } from 'react';
import { useOutletContext } from 'react-router-dom';
import { Async, Command, Empty, Severity } from '../../components/ui.jsx';
import { useAuth } from '../../context/AuthContext.jsx';
import { useApi } from '../../hooks/useApi.js';
import { api, errorMessage } from '../../services/api.js';
import { dateTime, levelText } from '../../utils/format.js';

function Priority({ p }) {
  const approval = p.recommendation?.startsWith('REQUIRES ADMIN APPROVAL');
  const rec = p.recommendation?.replace(/^REQUIRES ADMIN APPROVAL:\s*/, '');
  return (
    <li className="panel" style={{ background: 'var(--raised)', listStylePosition: 'inside' }}>
      <div className="row" style={{ display: 'inline-flex', marginLeft: 4 }}><Severity value={p.severity} /><strong>{p.title}</strong></div>
      <dl className="kv" style={{ marginTop: 10 }}>
        <dt>Why</dt><dd>{p.reason}</dd>
        <dt>What to do</dt><dd>{approval && <span className="approval" style={{ display: 'inline-block', marginBottom: 6 }}>Requires administrator approval</span>}<div>{rec}</div></dd>
        <dt>Verify</dt><dd><Command command={p.verification} /></dd>
      </dl>
    </li>
  );
}

export default function AI() {
  const { host } = useOutletContext();
  const { can } = useAuth();
  const q = useApi(`/hosts/${host.id}/ai/insights`, { limit: 5 });
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState(null);
  const run = async () => {
    setBusy(true); setErr(null);
    try { await api('post', `/hosts/${host.id}/ai/analyze`); await q.reload(true); } catch (e) { setErr(errorMessage(e)); } finally { setBusy(false); }
  };
  return (
    <div className="stack">
      <section className="panel">
        <div className="panel-head">
          <div><h2>Security analysis</h2><p className="small muted">Explains open findings in plain language and orders them by risk. It only sees structured findings, never raw files or logs, and it cannot change anything on the host.</p></div>
          {can('ANALYST') && <button type="button" className="btn btn-primary" onClick={run} disabled={busy}>{busy ? 'Analysing…' : 'Analyse now'}</button>}
        </div>
        {err && <p className="st-ERROR small" role="alert">{err}</p>}
        {q.meta && !q.meta.aiConfigured && <p className="notice warn">No AI provider is configured on the server. Analyses use the built-in deterministic engine, which works offline.</p>}
      </section>
      <Async q={q} what="analysis">{(items) => {
        const a = items[0];
        if (!a) return <div className="panel"><Empty title="No analysis yet">Run one to get a prioritised summary of this host.</Empty></div>;
        return (
          <>
            <section className="panel">
              <div className="panel-head"><h2>Summary</h2><p>{dateTime(a.createdAt)}, {a.engine === 'llm' ? `model ${a.model}` : 'deterministic engine'}</p></div>
              {a.fallbackReason && a.engine !== 'llm' && <p className="small muted">{a.fallbackReason}</p>}
              <p style={{ fontSize: 17, maxWidth: '72ch' }}>{a.summary}</p>
              <p className="small muted">Risk {a.riskScore}/100 ({levelText(a.riskLevel)}), health {a.healthScore ?? '—'}/100.</p>
            </section>
            <section className="panel">
              <h2>Top priorities</h2>
              {a.priorities?.length ? <ol className="stack" style={{ padding: 0, margin: 0 }}>{a.priorities.map((p) => <Priority key={p.title} p={p} />)}</ol> : <Empty title="Nothing to prioritise" />}
            </section>
            <div className="grid cols-2">
              <section className="panel"><h3>Observations</h3>{a.observations?.length ? <ul>{a.observations.map((o) => <li key={o}>{o}</li>)}</ul> : <p className="muted">None.</p>}</section>
              <section className="panel"><h3>What is uncertain</h3>{a.uncertainties?.length ? <ul>{a.uncertainties.map((o) => <li key={o}>{o}</li>)}</ul> : <p className="muted">None reported.</p>}</section>
            </div>
            <section className="panel">
              <h3>Anomaly detection</h3>
              {a.ml?.status === 'LEARNING' ? <p className="muted">Learning: {a.ml.samples} of {a.ml.required} metric samples collected. No predictions are made until the baseline is ready.</p>
                : a.ml?.anomalies?.length ? <ul>{a.ml.anomalies.map((x) => <li key={x.feature}>Unusual {x.feature}: {x.value} against a baseline median of {x.baselineMedian} (z = {x.zScore}).</li>)}</ul>
                  : <p className="muted">Baseline active ({a.ml?.model}); current behaviour is within the normal range.</p>}
            </section>
          </>
        );
      }}</Async>
    </div>
  );
}
