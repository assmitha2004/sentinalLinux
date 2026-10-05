import { useState } from 'react';
import { useOutletContext } from 'react-router-dom';
import { Async, Empty } from '../../components/ui.jsx';
import { useApi } from '../../hooks/useApi.js';
import { useSocket } from '../../hooks/useSocket.js';
import { ago, bytes } from '../../utils/format.js';
import FindingsList from '../FindingsList.jsx';

const exposure = (a) => (a === '0.0.0.0' || a === '::' ? 'All interfaces' : a?.startsWith('127.') || a === '::1' ? 'Local only' : a);

export default function Network() {
  const { host } = useOutletContext();
  const q = useApi(`/hosts/${host.id}/snapshot`);
  const [local, setLocal] = useState(false);
  const [all, setAll] = useState(false);
  useSocket({ 'host:snapshot': () => q.reload(true) }, host.id);
  return (
    <Async q={q} what="network">{(s) => {
      const n = s.network;
      if (!n) return <div className="panel"><Empty title="No network snapshot yet">The agent sends one every few seconds once running.</Empty></div>;
      const isLocal = (c) => c.remoteAddress?.startsWith('127.') || c.remoteAddress === '::1';
      const conns = n.established.filter((c) => local || !isLocal(c));
      const shown = all ? conns : conns.slice(0, 25);
      return (
        <div className="stack">
          <div className="readouts">
            <div className="readout"><div className="readout-label">Listening sockets</div><div className="readout-value">{n.counts.listening}</div></div>
            <div className="readout"><div className="readout-label">Established</div><div className="readout-value">{n.counts.established}</div></div>
            <div className="readout"><div className="readout-label">To other hosts</div><div className="readout-value">{n.counts.external}</div></div>
            <div className="readout"><div className="readout-label">Process visibility</div><div className="readout-value" style={{ fontSize: 16, paddingTop: 8 }}>{n.pidVisibility || 'full'}</div><div className="readout-note">Updated {ago(s.snapshotAt)}</div></div>
          </div>
          <section className="panel"><h2>Interfaces</h2>
            <div className="table-wrap"><table>
              <thead><tr><th>Name</th><th>State</th><th>IPv4</th><th>MAC</th><th className="num">Received</th><th className="num">Sent</th></tr></thead>
              <tbody>{n.interfaces.map((i) => <tr key={i.name}><td>{i.name}</td><td className={i.up ? 'st-PASS' : 'st-UNKNOWN'}>{i.up ? 'Up' : 'Down'}</td><td className="mono">{i.ipv4.join(', ') || '—'}</td><td className="mono">{i.mac || '—'}</td><td className="num">{bytes(i.rxBytes)}</td><td className="num">{bytes(i.txBytes)}</td></tr>)}</tbody>
            </table></div>
          </section>
          <section className="panel"><h2>Listening ports</h2>
            <div className="table-wrap"><table>
              <thead><tr><th>Protocol</th><th>Port</th><th>Reachable from</th><th>Process</th><th className="num">PID</th></tr></thead>
              <tbody>{n.listening.map((c, i) => <tr key={i}><td>{c.proto}</td><td className="mono">{c.localPort}</td><td className={exposure(c.localAddress) === 'All interfaces' ? 'st-WARN' : ''}>{exposure(c.localAddress)}</td><td>{c.process || <span className="muted">not visible</span>}</td><td className="num">{c.pid ?? '—'}</td></tr>)}</tbody>
            </table></div>
          </section>
          <section className="panel">
            <div className="panel-head"><h2>Active connections</h2>
              <label className="small muted row" style={{ gap: 6 }}><input type="checkbox" checked={local} onChange={(e) => setLocal(e.target.checked)} />Include connections within this host</label>
            </div>
            {conns.length ? <><div className="table-wrap"><table>
              <thead><tr><th>Process</th><th>Local</th><th>Remote</th><th>User</th></tr></thead>
              <tbody>{shown.map((c, i) => <tr key={i}><td>{c.process || '—'}</td><td className="mono">{c.localAddress}:{c.localPort}</td><td className="mono">{c.remoteAddress}:{c.remotePort}</td><td>{c.user || '—'}</td></tr>)}</tbody>
            </table></div>
            {conns.length > 25 && <button type="button" className="btn btn-small" style={{ marginTop: 10 }} onClick={() => setAll(!all)}>{all ? 'Show fewer' : `Show all ${conns.length}`}</button>}</>
              : <Empty title="No connections to other hosts" />}
          </section>
          <section className="panel">
            <div className="panel-head"><h2>Suspicious connections and exposure</h2><p>Scored on evidence. An external address alone is never treated as malicious.</p></div>
            <FindingsList hostId={host.id} fixed={{ category: 'network' }} compact />
          </section>
        </div>
      );
    }}</Async>
  );
}
