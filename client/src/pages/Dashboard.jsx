import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { TimeChart } from '../charts/MetricChart.jsx';
import FindingDrawer from '../components/FindingDrawer.jsx';
import RiskGauge from '../components/RiskGauge.jsx';
import { Async, Empty, Meter, Severity, SeverityBar, Status } from '../components/ui.jsx';
import { useApi } from '../hooks/useApi.js';
import { useSocket } from '../hooks/useSocket.js';
import { ago, healthWord, rate } from '../utils/format.js';

export default function Dashboard() {
  const summary = useApi('/dashboard/summary');
  const hosts = useApi('/hosts');
  const [hostId, setHostId] = useState(null);
  const [open, setOpen] = useState(null);
  useEffect(() => { if (!hostId && hosts.data?.length) setHostId(hosts.data[0].id); }, [hosts.data, hostId]);
  const metrics = useApi(hostId ? `/hosts/${hostId}/metrics` : null, { range: '1h' }, [hostId]);
  const host = hosts.data?.find((h) => h.id === hostId);

  useSocket({
    'metric:update': (p) => {
      if (p.hostId === hostId && p.metric) metrics.setData((d) => [...(d || []).slice(-719), p.metric]);
      hosts.setData((list) => list?.map((h) => (h.id === p.hostId ? { ...h, latestMetric: p.metric, scores: { ...h.scores, health: p.health }, status: 'ONLINE' } : h)));
    },
    'scan:completed': () => { summary.reload(true); hosts.reload(true); },
    'finding:new': () => summary.reload(true),
    'security:alert': () => summary.reload(true),
    'host:offline': () => hosts.reload(true),
    'host:online': () => hosts.reload(true),
  });

  return (
    <Async q={summary} what="overview">{(s) => {
      if (!s.hosts.total) {
        return (
          <>
            <div className="page-head"><div><h1>Overview</h1></div></div>
            <div className="panel"><Empty title="No hosts are reporting yet">
              <p>Create an enrollment token in <Link to="/settings">Settings</Link>, then install the agent on a BOSS 10 machine with <code>sudo ./install.sh</code>.</p>
            </Empty></div>
          </>
        );
      }
      const m = host?.latestMetric;
      const worstDisk = m?.disk?.reduce((a, d) => (d.percent > (a?.percent ?? -1) ? d : a), null);
      const single = s.hosts.total === 1;
      return (
        <>
          <div className="page-head">
            <div>
              <h1>Overview</h1>
              <p>{s.hosts.online} of {s.hosts.total} host{s.hosts.total > 1 ? 's' : ''} reporting{s.hosts.offline ? `, ${s.hosts.offline} offline` : ''}.</p>
            </div>
            {hosts.data?.length > 1 && (
              <label className="field">Metrics for
                <select value={hostId || ''} onChange={(e) => setHostId(e.target.value)}>{hosts.data.map((h) => <option key={h.id} value={h.id}>{h.hostname}</option>)}</select>
              </label>
            )}
          </div>

          <div className="grid cols-main" style={{ marginBottom: 16 }}>
            <section className="panel" aria-labelledby="risk-h">
              <div className="panel-head"><h2 id="risk-h">{single ? 'Security risk' : 'Average security risk'}</h2><p>Higher means more exposure</p></div>
              <RiskGauge score={single ? host?.scores?.risk : s.averageRisk} level={single ? host?.scores?.riskLevel : undefined}
                caption={`${Object.values(s.findingsBySeverity).reduce((a, b) => a + b, 0)} open findings. Scores are weighted by severity and evidence confidence, not by count.`} />
              <div style={{ marginTop: 18 }}><SeverityBar counts={s.findingsBySeverity} /></div>
              <div className="row small" style={{ marginTop: 8 }}>
                {['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map((k) => <span key={k}><Severity value={k} /> {s.findingsBySeverity[k]}</span>)}
              </div>
            </section>
            <section className="panel" aria-labelledby="health-h">
              <div className="panel-head"><h2 id="health-h">{host?.hostname || 'Host'} health</h2><p>{healthWord(host?.scores?.health)}</p></div>
              <div className="gauge-score" style={{ fontSize: 44, marginBottom: 14 }}>{host?.scores?.health ?? '—'}<span className="muted" style={{ fontSize: 18 }}>/100</span></div>
              <div className="stack" style={{ gap: 10 }}>
                <Meter label="CPU" value={m?.cpu?.usage} />
                <Meter label="Memory" value={m?.memory?.percent} />
                <Meter label="Disk" value={worstDisk?.percent} />
              </div>
              <p className="small muted" style={{ marginTop: 10 }}>Fullest filesystem: {worstDisk?.mount || '—'}. Updated {ago(m?.timestamp)}.</p>
            </section>
          </div>

          <div className="readouts" style={{ marginBottom: 16 }}>
            <div className="readout"><div className="readout-label">Active alerts</div><div className="readout-value" style={{ color: s.activeAlerts ? 'var(--sev-high)' : undefined }}>{s.activeAlerts}</div><div className="readout-note"><Link to="/alerts">Review alerts</Link></div></div>
            <div className="readout"><div className="readout-label">Hosts online</div><div className="readout-value">{s.hosts.online}/{s.hosts.total}</div><div className="readout-note">{s.hosts.degraded} degraded</div></div>
            <div className="readout"><div className="readout-label">High-risk hosts</div><div className="readout-value">{s.hosts.highRisk + s.hosts.critical}</div><div className="readout-note">{s.hosts.critical} critical</div></div>
            <div className="readout"><div className="readout-label">Average health</div><div className="readout-value">{s.averageHealth ?? '—'}</div><div className="readout-note">out of 100</div></div>
            <div className="readout"><div className="readout-label">Network</div><div className="readout-value" style={{ fontSize: 18, paddingTop: 6 }}>{rate(m?.network?.rxRate)} in</div><div className="readout-note">{rate(m?.network?.txRate)} out</div></div>
          </div>

          <div className="grid cols-2" style={{ marginBottom: 16 }}>
            <section className="panel"><div className="panel-head"><h3>CPU and memory, last hour</h3></div>
              <Async q={metrics} what="metrics">{(rows) => (rows?.length ? <TimeChart data={rows} series={[{ key: 'cpu', name: 'CPU', color: '#8fa8ff', get: (r) => r.cpu?.usage }, { key: 'mem', name: 'Memory', color: '#45c08a', get: (r) => r.memory?.percent }]} /> : <Empty title="No metrics in the last hour" />)}</Async>
            </section>
            <section className="panel"><div className="panel-head"><h3>Network throughput, last hour</h3></div>
              <Async q={metrics} what="metrics">{(rows) => (rows?.length ? <TimeChart data={rows} max={null} format={(v) => rate(v)} series={[{ key: 'rx', name: 'In', color: '#5da9e9', get: (r) => r.network?.rxRate }, { key: 'tx', name: 'Out', color: '#f2a541', get: (r) => r.network?.txRate }]} /> : <Empty title="No metrics in the last hour" />)}</Async>
            </section>
          </div>

          <section className="panel" style={{ marginBottom: 16 }}>
            <div className="panel-head"><h2>What needs attention</h2><Link to="/findings" className="small">All findings</Link></div>
            {s.topFindings.length === 0 ? <Empty title="No medium or higher findings are open">Low-severity items are still listed under Findings.</Empty> : (
              <div className="table-wrap"><table>
                <thead><tr><th>Severity</th><th>Finding</th><th>Host</th><th>First seen</th><th>Recommended action</th></tr></thead>
                <tbody>{s.topFindings.map((f) => (
                  <tr key={f._id} className="clickable" onClick={() => setOpen(f._id)} tabIndex={0} onKeyDown={(e) => e.key === 'Enter' && setOpen(f._id)}>
                    <td><Severity value={f.severity} /></td><td>{f.title}</td><td>{f.hostId?.hostname}</td><td className="muted">{ago(f.firstSeen)}</td><td className="truncate muted">{f.recommendation}</td>
                  </tr>))}</tbody>
              </table></div>
            )}
          </section>

          {!single && (
            <section className="panel">
              <div className="panel-head"><h2>Hosts</h2></div>
              <HostTable hosts={hosts.data || []} />
            </section>
          )}
          {open && <FindingDrawer id={open} onClose={() => setOpen(null)} onChanged={() => summary.reload(true)} />}
        </>
      );
    }}</Async>
  );
}

export function HostTable({ hosts }) {
  return (
    <div className="table-wrap"><table>
      <thead><tr><th>Hostname</th><th>OS</th><th>Status</th><th className="num">Health</th><th className="num">Risk</th><th>Last seen</th><th className="num">Alerts</th></tr></thead>
      <tbody>{hosts.map((h) => (
        <tr key={h.id}>
          <td><Link to={`/hosts/${h.id}`}>{h.hostname}</Link></td>
          <td className="muted">{h.os?.distribution} {h.os?.version}</td>
          <td><Status value={h.status} dot /></td>
          <td className="num">{h.scores?.health ?? '—'}</td>
          <td className="num">{h.scores?.risk ?? '—'}</td>
          <td className="muted">{ago(h.lastSeen)}</td>
          <td className="num">{h.activeAlerts || 0}</td>
        </tr>))}</tbody>
    </table></div>
  );
}

