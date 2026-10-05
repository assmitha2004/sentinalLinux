import { NavLink, Outlet } from 'react-router-dom';
import { useAuth } from '../context/AuthContext.jsx';
import { useApi } from '../hooks/useApi.js';
import { useSocket } from '../hooks/useSocket.js';

export const Brand = () => (
  <div className="brand">
    <img src="/favicon.svg" alt="" className="brand-mark" />
    <div><div className="brand-name">SentinelAI</div><div className="brand-sub">BOSS 10 health &amp; security</div></div>
  </div>
);

export default function AppLayout() {
  const { user, logout } = useAuth();
  const alerts = useApi('/alerts', { acknowledged: 'false', limit: 1 });
  useSocket({ 'security:alert': () => alerts.reload(true) });
  const open = alerts.meta?.total || 0;
  const link = ({ isActive }) => `nav-link${isActive ? ' active' : ''}`;
  return (
    <>
      <div className="shell">
        <nav className="sidebar" aria-label="Main">
          <Brand />
          <NavLink to="/dashboard" className={link}>Overview</NavLink>
          <NavLink to="/hosts" className={link}>Hosts</NavLink>
          <NavLink to="/findings" className={link}>Findings</NavLink>
          <NavLink to="/alerts" className={link}>Alerts {open > 0 && <span className="nav-count" aria-label={`${open} open alerts`}>{open}</span>}</NavLink>
          <NavLink to="/settings" className={link}>Settings</NavLink>
          <div className="sidebar-foot">
            <strong>{user?.name}</strong>
            {user?.role?.toLowerCase()}
            <div><button type="button" className="btn btn-small" style={{ marginTop: 8 }} onClick={logout}>Sign out</button></div>
          </div>
        </nav>
        <main className="main" id="main"><Outlet /></main>
      </div>
    </>
  );
}
