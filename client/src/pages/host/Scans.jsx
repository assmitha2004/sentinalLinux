import { Fragment, useState } from 'react';
import { useOutletContext } from 'react-router-dom';
import { Async, Empty, Status } from '../../components/ui.jsx';
import { useApi } from '../../hooks/useApi.js';
import { useSocket } from '../../hooks/useSocket.js';
import { ago, dateTime, statusText } from '../../utils/format.js';
import ScanControl from './ScanControl.jsx';

function ScanDetail({ hostId, scanId }) {
  const q = useApi(`/hosts/${hostId}/scans/${scanId}`, undefined, [scanId]);
  return (
    <Async q={q} what="scan">{(s) => (
      <div className="table-wrap" style={{ marginTop: 12 }}><table>
        <thead><tr><th>Check</th><th>Result</th><th className="num">Findings</th><th className="num">Time</th><th>Notes</th></tr></thead>
        <tbody>{(s.checks || []).map((c) => (
          <tr key={c.check}><td>{c.check.replace(/_/g, ' ')}</td><td><Status value={c.status} /></td><td className="num">{c.findingCount}</td>
            <td className="num muted">{c.durationMs != null ? `${c.durationMs} ms` : '—'}</td>
            <td className="small muted">{c.reason || c.errors?.join('; ') || ''}</td></tr>))}</tbody>
      </table></div>
    )}</Async>
  );
}

export default function Scans() {
  const { host } = useOutletContext();
  const q = useApi(`/hosts/${host.id}/scans`);
  const [open, setOpen] = useState(null);
  useSocket({ 'scan:completed': (p) => p.hostId === host.id && q.reload(true), 'scan:started': (p) => p.hostId === host.id && q.reload(true), 'scan:queued': (p) => p.hostId === host.id && q.reload(true) }, host.id);
  return (
    <div className="stack">
      <ScanControl hostId={host.id} onQueued={() => q.reload(true)} />
      <section className="panel">
        <div className="panel-head"><h2>Scan history</h2><p>Scheduled scans run every few minutes; a full scan runs daily.</p></div>
        <Async q={q} what="scans">{(rows) => (rows.length ? (
          <div className="table-wrap"><table>
            <thead><tr><th>Type</th><th>Trigger</th><th>Status</th><th>Progress</th><th className="num">Findings</th><th className="num">Risk</th><th>Finished</th></tr></thead>
            <tbody>{rows.map((s) => (
              <Fragment key={s.scanId}>
                <tr className="clickable" tabIndex={0} onClick={() => setOpen(open === s.scanId ? null : s.scanId)} onKeyDown={(e) => e.key === 'Enter' && setOpen(s.scanId)} aria-expanded={open === s.scanId}>
                  <td>{s.scanType.toLowerCase()}</td><td className="muted">{s.trigger.toLowerCase()}</td><td className={s.status === 'COMPLETED' ? 'st-PASS' : s.status === 'FAILED' ? 'st-FAIL' : 'st-WARN'}>{statusText(s.status)}</td>
                  <td style={{ minWidth: 120 }}><div className="progress"><span style={{ width: `${s.progress || 0}%` }} /></div><span className="small muted">{s.checksCompleted}/{s.checksTotal || '?'}{s.currentCheck && s.status === 'RUNNING' ? `, ${s.currentCheck}` : ''}</span></td>
                  <td className="num">{s.summary?.findings ?? '—'}</td><td className="num">{s.scores?.risk ?? '—'}</td>
                  <td className="muted" title={dateTime(s.completedAt)}>{s.completedAt ? ago(s.completedAt) : '—'}</td>
                </tr>
                {open === s.scanId && <tr><td colSpan={7}><ScanDetail hostId={host.id} scanId={s.scanId} /></td></tr>}
              </Fragment>))}</tbody>
          </table></div>) : <Empty title="No scans yet">The agent runs its first scan right after it starts.</Empty>)}</Async>
      </section>
    </div>
  );
}
