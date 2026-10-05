import { useState } from 'react';
import { useOutletContext } from 'react-router-dom';
import { Async, Empty } from '../../components/ui.jsx';
import { useApi } from '../../hooks/useApi.js';
import { useSocket } from '../../hooks/useSocket.js';
import { ago, duration } from '../../utils/format.js';
import FindingsList from '../FindingsList.jsx';

export default function Processes() {
  const { host } = useOutletContext();
  const q = useApi(`/hosts/${host.id}/snapshot`);
  const [filter, setFilter] = useState('');
  useSocket({ 'host:snapshot': () => q.reload(true) }, host.id);
  return (
    <Async q={q} what="processes">{(s) => {
      const p = s.processes;
      if (!p) return <div className="panel"><Empty title="No process snapshot yet" /></div>;
      const now = Date.now() / 1000;
      const rows = p.top.filter((x) => !filter || `${x.name} ${x.user} ${x.cmdline}`.toLowerCase().includes(filter.toLowerCase()));
      return (
        <div className="stack">
          <section className="panel">
            <div className="panel-head"><h2>Top processes</h2><p>{p.count} running, {p.rootCount} as root. Updated {ago(s.snapshotAt)}.</p></div>
            <div className="filters"><input type="search" placeholder="Filter by name, user or command" value={filter} onChange={(e) => setFilter(e.target.value)} aria-label="Filter processes" /></div>
            <div className="table-wrap"><table>
              <thead><tr><th className="num">PID</th><th>Name</th><th>User</th><th className="num">CPU</th><th className="num">Memory</th><th>Running for</th><th>Command</th></tr></thead>
              <tbody>{rows.map((x) => <tr key={x.pid}><td className="num">{x.pid}</td><td>{x.name}</td><td className={x.user === 'root' ? 'st-WARN' : ''}>{x.user}</td><td className="num">{x.cpu}%</td><td className="num">{x.mem}%</td><td className="muted">{x.startTime ? duration(now - x.startTime) : '—'}</td><td className="mono truncate" title={x.cmdline}>{x.cmdline || x.exe}</td></tr>)}</tbody>
            </table></div>
            <p className="small muted" style={{ marginTop: 8 }}>SentinelAI never stops processes. Use the findings below to decide what to investigate.</p>
          </section>
          <section className="panel"><h2>Suspicious processes</h2><FindingsList hostId={host.id} fixed={{ category: 'process' }} compact /></section>
        </div>
      );
    }}</Async>
  );
}
