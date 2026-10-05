import { useState } from 'react';
import { useOutletContext } from 'react-router-dom';
import { TimeChart } from '../../charts/MetricChart.jsx';
import { Async, Empty, Meter } from '../../components/ui.jsx';
import { useApi } from '../../hooks/useApi.js';
import { useSocket } from '../../hooks/useSocket.js';
import { bytes, dateTime, duration } from '../../utils/format.js';

export default function System() {
  const { host } = useOutletContext();
  const [range, setRange] = useState('1h');
  const metrics = useApi(`/hosts/${host.id}/metrics`, { range }, [range]);
  const snap = useApi(`/hosts/${host.id}/snapshot`);
  useSocket({ 'metric:update': (p) => p.hostId === host.id && range === '15m' && metrics.setData((d) => [...(d || []), p.metric]) });
  const m = host.latestMetric;
  return (
    <div className="stack">
      <div className="grid cols-2">
        <section className="panel"><h2>Operating system</h2>
          <Async q={snap} what="system info">{(s) => (
            <dl className="kv">
              <dt>Distribution</dt><dd>{s.system?.prettyName || host.os?.prettyName || '—'}</dd>
              <dt>Version</dt><dd>{host.os?.version} {host.os?.codename ? `(${host.os.codename})` : ''}</dd>
              <dt>Kernel</dt><dd className="mono">{host.kernel}</dd>
              <dt>Architecture</dt><dd>{host.architecture}</dd>
              <dt>Init system</dt><dd>{host.os?.initSystem}</dd>
              <dt>Boot time</dt><dd>{s.system?.bootTime ? dateTime(s.system.bootTime * 1000) : '—'}</dd>
              <dt>Uptime</dt><dd>{duration(m?.uptimeSeconds)}</dd>
            </dl>)}</Async>
        </section>
        <section className="panel"><h2>Filesystems</h2>
          {m?.disk?.length ? <div className="stack" style={{ gap: 10 }}>{m.disk.map((d) => (
            <div key={d.mount}><Meter label={d.mount} value={d.percent} warn={80} high={90} /><div className="small muted" style={{ marginLeft: 90 }}>{bytes(d.used)} of {bytes(d.total)}</div></div>
          ))}</div> : <Empty title="No disk data yet" />}
        </section>
      </div>
      <section className="panel">
        <div className="panel-head"><h2>Resource history</h2>
          <select value={range} onChange={(e) => setRange(e.target.value)} aria-label="Time range">{['15m', '1h', '6h', '24h', '7d'].map((r) => <option key={r}>{r}</option>)}</select>
        </div>
        <Async q={metrics} what="metrics">{(rows) => (rows.length ? (
          <div className="grid cols-2">
            <div><h3 className="muted">CPU and memory</h3><TimeChart data={rows} series={[{ key: 'cpu', name: 'CPU', color: '#8fa8ff', get: (r) => r.cpu?.usage }, { key: 'mem', name: 'Memory', color: '#45c08a', get: (r) => r.memory?.percent }]} /></div>
            <div><h3 className="muted">Load average (5 min)</h3><TimeChart data={rows} max={null} unit="" format={(v) => v?.toFixed?.(1)} series={[{ key: 'l5', name: 'Load 5m', color: '#e3b53c', get: (r) => r.load?.load5 }]} /></div>
            <div><h3 className="muted">Process count</h3><TimeChart data={rows} max={null} unit="" series={[{ key: 'p', name: 'Processes', color: '#5da9e9', get: (r) => r.processCount }]} /></div>
            <div><h3 className="muted">Fullest disk</h3><TimeChart data={rows} series={[{ key: 'd', name: 'Disk', color: '#f2803a', get: (r) => Math.max(0, ...(r.disk || []).map((x) => x.percent)) }]} /></div>
          </div>) : <Empty title="No metrics for this range" />)}</Async>
      </section>
    </div>
  );
}
