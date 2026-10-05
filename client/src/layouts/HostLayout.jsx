import { NavLink, Outlet, useParams } from 'react-router-dom';
import { Async, Status } from '../components/ui.jsx';
import { useApi } from '../hooks/useApi.js';
import { useSocket } from '../hooks/useSocket.js';
import { ago } from '../utils/format.js';

const TABS = [['', 'Overview'], ['system', 'System'], ['security', 'Security'], ['network', 'Network'], ['processes', 'Processes'],
  ['services', 'Services'], ['findings', 'Findings'], ['scans', 'Scans'], ['ai', 'AI analysis']];

export default function HostLayout() {
  const { id } = useParams();
  const host = useApi(`/hosts/${id}`, undefined, [id]);
  useSocket({
    'host:online': (p) => p.hostId === id && host.reload(true),
    'host:offline': (p) => p.hostId === id && host.reload(true),
    'scan:completed': (p) => p.hostId === id && host.reload(true),
  });
  return (
    <Async q={host} what="host">{(h) => (
      <>
        <div className="page-head">
          <div>
            <h1>{h.hostname}</h1>
            <p>{h.os?.prettyName || `${h.os?.distribution} ${h.os?.version}`}, kernel {h.kernel}, {h.architecture}</p>
            {h.os && !h.os.isBoss10 && <p className="st-WARN small">This host is not BOSS 10; some checks may report “not supported”.</p>}
          </div>
          <div className="small" style={{ textAlign: 'right' }}>
            <Status value={h.status} dot /><div className="muted">Last seen {ago(h.lastSeen)}, agent {h.agentVersion || "unknown"}</div>
            {h.currentScan && <div className="muted">Running a {h.currentScan.toLowerCase()} scan</div>}
          </div>
        </div>
        <nav className="tabs" aria-label="Host sections">
          {TABS.map(([path, label]) => <NavLink key={label} end to={path ? `/hosts/${id}/${path}` : `/hosts/${id}`} className={({ isActive }) => `tab${isActive ? ' active' : ''}`}>{label}</NavLink>)}
        </nav>
        <Outlet context={{ host: h, reloadHost: () => host.reload(true) }} />
      </>
    )}</Async>
  );
}
