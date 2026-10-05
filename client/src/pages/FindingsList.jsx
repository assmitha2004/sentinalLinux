import { useState } from 'react';
import FindingDrawer from '../components/FindingDrawer.jsx';
import { Async, Empty, Severity } from '../components/ui.jsx';
import { useApi } from '../hooks/useApi.js';
import { useSocket } from '../hooks/useSocket.js';
import { ago } from '../utils/format.js';

const CATEGORIES = ['ssh', 'users', 'auth', 'permissions', 'filesystem', 'process', 'network', 'firewall', 'kernel', 'logging', 'authentication', 'rootkit', 'benchmark', 'vulnerability', 'health'];

/** Filterable findings table used on the global page and on host tabs. */
export default function FindingsList({ hostId, fixed = {}, compact = false, hosts }) {
  const [f, setF] = useState({ severity: '', status: '', category: '', q: '', hostId: '', page: 1 });
  const [open, setOpen] = useState(null);
  const params = Object.fromEntries(Object.entries({ ...f, ...fixed, hostId: hostId || f.hostId, limit: compact ? 20 : 50 }).filter(([, v]) => v !== '' && v != null));
  const url = '/findings';
  const q = useApi(url, params);
  useSocket({ 'finding:new': () => q.reload(true), 'scan:completed': () => q.reload(true) });
  const set = (k) => (e) => setF((s) => ({ ...s, [k]: e.target.value, page: 1 }));

  return (
    <>
      {!compact && (
        <div className="filters">
          <select value={f.severity} onChange={set('severity')} aria-label="Severity"><option value="">Any severity</option>{['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'].map((s) => <option key={s} value={s}>{s.charAt(0) + s.slice(1).toLowerCase()}</option>)}</select>
          <select value={f.status} onChange={set('status')} aria-label="Status"><option value="">Open and acknowledged</option><option value="OPEN">Open</option><option value="ACKNOWLEDGED">Acknowledged</option><option value="RESOLVED">Resolved</option><option value="FALSE_POSITIVE">False positive</option><option value="ALL">All</option></select>
          <select value={f.category} onChange={set('category')} aria-label="Category"><option value="">Any category</option>{CATEGORIES.map((c) => <option key={c}>{c}</option>)}</select>
          {hosts && <select value={f.hostId} onChange={set('hostId')} aria-label="Host"><option value="">All hosts</option>{hosts.map((h) => <option key={h.id} value={h.id}>{h.hostname}</option>)}</select>}
          <input type="date" aria-label="Seen since" onChange={set('from')} />
          <input type="search" placeholder="Search titles" value={f.q} onChange={set('q')} aria-label="Search findings" />
        </div>
      )}
      <Async q={q} what="findings">{(rows, meta) => (rows.length === 0 ? <Empty title="No findings match">Checks that ran found nothing here. Checks that could not run are listed under Scans.</Empty> : (
        <>
          <div className="table-wrap"><table>
            <thead><tr><th>Severity</th><th>Finding</th>{!hostId && <th>Host</th>}<th>Category</th><th className="num">Confidence</th><th>Status</th><th>Last seen</th></tr></thead>
            <tbody>{rows.map((x) => (
              <tr key={x._id} className="clickable" tabIndex={0} onClick={() => setOpen(x._id)} onKeyDown={(e) => e.key === 'Enter' && setOpen(x._id)}>
                <td><Severity value={x.severity} /></td><td>{x.title}</td>{!hostId && <td>{x.hostId?.hostname}</td>}
                <td className="muted">{x.category}</td><td className="num">{Math.round((x.confidence ?? 0) * 100)}%</td>
                <td className="muted">{x.status.replace('_', ' ').toLowerCase()}</td><td className="muted">{ago(x.lastSeen)}</td>
              </tr>))}</tbody>
          </table></div>
          {!compact && meta?.total > meta?.limit && (
            <div className="row" style={{ marginTop: 12 }}>
              <button type="button" className="btn btn-small" disabled={f.page <= 1} onClick={() => setF((s) => ({ ...s, page: s.page - 1 }))}>Previous</button>
              <span className="small muted">Page {meta.page} of {Math.ceil(meta.total / meta.limit)}</span>
              <button type="button" className="btn btn-small" disabled={meta.page * meta.limit >= meta.total} onClick={() => setF((s) => ({ ...s, page: s.page + 1 }))}>Next</button>
            </div>
          )}
        </>
      ))}</Async>
      {open && <FindingDrawer id={open} onClose={() => setOpen(null)} onChanged={() => q.reload(true)} />}
    </>
  );
}
