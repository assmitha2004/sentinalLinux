import { useState } from 'react';
import { Link } from 'react-router-dom';
import { Async, Empty, Severity } from '../components/ui.jsx';
import { useAuth } from '../context/AuthContext.jsx';
import { useApi } from '../hooks/useApi.js';
import { useSocket } from '../hooks/useSocket.js';
import { api, errorMessage } from '../services/api.js';
import { ago } from '../utils/format.js';

export default function Alerts() {
  const [ack, setAck] = useState('false');
  const q = useApi('/alerts', { acknowledged: ack || undefined, limit: 100 }, [ack]);
  const { can } = useAuth();
  const [err, setErr] = useState(null);
  useSocket({ 'security:alert': () => q.reload(true) });
  const acknowledge = async (id) => {
    try { await api('patch', `/alerts/${id}/acknowledge`); q.reload(true); } catch (e) { setErr(errorMessage(e)); }
  };
  return (
    <>
      <div className="page-head"><div><h1>Alerts</h1><p>Raised for high-severity findings, suspicious activity, resource spikes, offline hosts and failed scans. Repeats are grouped.</p></div>
        <select value={ack} onChange={(e) => setAck(e.target.value)} aria-label="Show alerts"><option value="false">Needs attention</option><option value="true">Acknowledged</option><option value="">All</option></select>
      </div>
      {err && <p className="st-ERROR" role="alert">{err}</p>}
      <section className="panel">
        <Async q={q} what="alerts">{(rows) => (rows.length ? (
          <div className="table-wrap"><table>
            <thead><tr><th>Severity</th><th>Alert</th><th>Host</th><th className="num">Times</th><th>Raised</th><th /></tr></thead>
            <tbody>{rows.map((a) => (
              <tr key={a._id}>
                <td><Severity value={a.severity} /></td>
                <td><div>{a.title}</div><div className="small muted">{a.message}</div></td>
                <td>{a.hostId ? <Link to={`/hosts/${a.hostId._id}`}>{a.hostId.hostname}</Link> : '—'}</td>
                <td className="num">{a.count}</td><td className="muted">{ago(a.createdAt)}</td>
                <td>{!a.acknowledged && can('ANALYST') && <button type="button" className="btn btn-small" onClick={() => acknowledge(a._id)}>Acknowledge</button>}{a.acknowledged && <span className="small muted">Acknowledged</span>}</td>
              </tr>))}</tbody>
          </table></div>) : <Empty title={ack === 'false' ? 'Nothing needs attention' : 'No alerts'} />)}</Async>
      </section>
    </>
  );
}
