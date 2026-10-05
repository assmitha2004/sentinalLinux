import { statusText } from '../utils/format.js';

export const Severity = ({ value }) => <span className={`sev sev-${value}`}>{value?.toLowerCase().replace(/^\w/, (c) => c.toUpperCase())}</span>;

export const Status = ({ value, dot }) => (
  <span className={`st-${value}`} style={{ fontWeight: 600 }}>
    {dot && <span className={`dot st-${value}`} style={{ marginRight: 6 }} />}{statusText(value)}
  </span>
);

export const Loading = ({ what = 'data' }) => <div className="state" role="status">Loading {what}…</div>;

export const ErrorState = ({ error, onRetry }) => (
  <div className="state state-error" role="alert">
    <strong>Couldn’t load this view</strong>
    <p>{error}</p>
    {onRetry && <button type="button" className="btn btn-small" onClick={() => onRetry()}>Try again</button>}
  </div>
);

export const Empty = ({ title, children }) => (
  <div className="state"><strong>{title}</strong>{children}</div>
);

/** Wraps a useApi() result: shows loading / error, else renders children(data). */
export function Async({ q, what, children }) {
  if (q.loading && q.data == null) return <Loading what={what} />;
  if (q.error && q.data == null) return <ErrorState error={q.error} onRetry={q.reload} />;
  return children(q.data, q.meta);
}

/** Commands are display-only and labelled with their effect (spec §73). Never executed. */
export function Command({ command, modifying = false, note }) {
  if (!command) return null;
  const copy = () => navigator.clipboard?.writeText(command);
  return (
    <div className="cmd">
      <div className="cmd-head">
        <span className={`cmd-mode ${modifying ? 'mod' : 'ro'}`}>{modifying ? 'Modifying — run only after review' : 'Read-only check'}</span>
        <button type="button" className="btn btn-small" onClick={copy} aria-label="Copy command">Copy</button>
      </div>
      <pre>{command}</pre>
      {note && <div className="small muted" style={{ padding: '0 10px 8px' }}>{note}</div>}
    </div>
  );
}

export function SeverityBar({ counts }) {
  const order = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];
  const total = order.reduce((a, k) => a + (counts?.[k] || 0), 0);
  if (!total) return <div className="sevbar" aria-label="No open findings" />;
  return (
    <div className="sevbar" role="img" aria-label={order.map((k) => `${counts[k] || 0} ${k.toLowerCase()}`).join(', ')}>
      {order.map((k) => counts[k] ? <span key={k} style={{ width: `${(100 * counts[k]) / total}%`, background: `var(--sev-${k.toLowerCase()})` }} /> : null)}
    </div>
  );
}

export function Meter({ label, value, warn = 80, high = 90 }) {
  const v = Math.max(0, Math.min(100, value ?? 0));
  const color = v >= high ? 'var(--sev-critical)' : v >= warn ? 'var(--sev-medium)' : 'var(--accent)';
  return (
    <div className="meter">
      <span className="muted">{label}</span>
      <div className="progress" role="meter" aria-valuenow={v} aria-valuemin={0} aria-valuemax={100} aria-label={label}>
        <span style={{ width: `${v}%`, background: color }} />
      </div>
      <span style={{ textAlign: 'right', fontVariantNumeric: 'tabular-nums' }}>{value == null ? '—' : `${Math.round(v)}%`}</span>
    </div>
  );
}
