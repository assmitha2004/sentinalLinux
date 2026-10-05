import { Navigate, Route, Routes, useLocation } from 'react-router-dom';
import { Loading } from './components/ui.jsx';
import { useAuth } from './context/AuthContext.jsx';
import AppLayout from './layouts/AppLayout.jsx';
import HostLayout from './layouts/HostLayout.jsx';
import Alerts from './pages/Alerts.jsx';
import { Login, Register } from './pages/Auth.jsx';
import Dashboard from './pages/Dashboard.jsx';
import Findings from './pages/Findings.jsx';
import Hosts from './pages/Hosts.jsx';
import AI from './pages/host/AI.jsx';
import HostFindings from './pages/host/Findings.jsx';
import Network from './pages/host/Network.jsx';
import Overview from './pages/host/Overview.jsx';
import Processes from './pages/host/Processes.jsx';
import Scans from './pages/host/Scans.jsx';
import Security from './pages/host/Security.jsx';
import Services from './pages/host/Services.jsx';
import System from './pages/host/System.jsx';
import Settings from './pages/Settings.jsx';
import { DEMO_MODE } from './services/api.js';

function RequireAuth({ children }) {
  const { user, ready } = useAuth();
  const loc = useLocation();
  if (!ready) return <Loading what="session" />;
  if (!user) return <Navigate to="/login" replace state={{ from: loc }} />;
  return children;
}

const NotFound = () => <div className="state"><strong>Page not found</strong><p>Use the menu to get back to the overview.</p></div>;

export default function App() {
  return (
    <>
      {DEMO_MODE && <div className="demo-banner" role="status">Demo data, not from a real host. Set VITE_DEMO_MODE=false to use the backend.</div>}
      <Routes>
      <Route path="/login" element={<Login />} />
      <Route path="/register" element={<Register />} />
      <Route element={<RequireAuth><AppLayout /></RequireAuth>}>
        <Route index element={<Navigate to="/dashboard" replace />} />
        <Route path="/dashboard" element={<Dashboard />} />
        <Route path="/hosts" element={<Hosts />} />
        <Route path="/hosts/:id" element={<HostLayout />}>
          <Route index element={<Overview />} />
          <Route path="system" element={<System />} />
          <Route path="security" element={<Security />} />
          <Route path="network" element={<Network />} />
          <Route path="processes" element={<Processes />} />
          <Route path="services" element={<Services />} />
          <Route path="findings" element={<HostFindings />} />
          <Route path="scans" element={<Scans />} />
          <Route path="ai" element={<AI />} />
        </Route>
        <Route path="/findings" element={<Findings />} />
        <Route path="/alerts" element={<Alerts />} />
        <Route path="/settings" element={<Settings />} />
        <Route path="*" element={<NotFound />} />
      </Route>
      </Routes>
    </>
  );
}
