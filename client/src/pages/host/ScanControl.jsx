import { useState } from 'react';
import { useAuth } from '../../context/AuthContext.jsx';
import { useSocket } from '../../hooks/useSocket.js';
import { api, errorMessage } from '../../services/api.js';

const TYPES = {
  QUICK: 'System, network, firewall, kernel and connection checks',
  STANDARD: 'Quick plus processes, services, SSH, accounts, permissions, temp files and logs',
  FULL: 'Every check, including SUID, binaries, rootkit indicators, updates and benchmark',
  NETWORK: 'Network, firewall, connections and SSH exposure',
  PROCESS: 'Processes, temp executables and rootkit indicators',
  FILESYSTEM: 'SUID/SGID, permissions, temp executables and binaries',
  BENCHMARK: 'OpenSCAP benchmark only, if installed on the host',
};

export default function ScanControl({ hostId, onQueued }) {
  const { can } = useAuth();
  const [type, setType] = useState('QUICK');
  const [state, setState] = useState(null);
  useSocket({
    'scan:progress': (p) => p.hostId === hostId && setState((s) => (s?.scanId === p.scanId ? { ...s, progress: p.progress, check: p.currentCheck, phase: 'running' } : s)),
    'scan:completed': (p) => p.hostId === hostId && setState((s) => (s?.scanId === p.scanId ? { ...s, progress: 100, phase: p.status === 'FAILED' ? 'failed' : 'done', summary: p.summary } : s)),
  }, hostId);
  if (!can('ANALYST')) return null;
  const run = async () => {
    try {
      const { data } = await api('post', `/hosts/${hostId}/scan`, { type });
      setState({ scanId: data.scanId, phase: 'queued', progress: 0 });
      onQueued?.();
    } catch (e) { setState({ phase: 'error', error: errorMessage(e) }); }
  };
  return (
    <section className="panel">
      <div className="panel-head"><h2>Run a scan</h2><p>Scans are read-only; nothing on the host is changed.</p></div>
      <div className="row">
        <select value={type} onChange={(e) => setType(e.target.value)} aria-label="Scan type">{Object.keys(TYPES).map((t) => <option key={t} value={t}>{t.charAt(0) + t.slice(1).toLowerCase()}</option>)}</select>
        <button type="button" className="btn btn-primary" onClick={run} disabled={state && ['queued', 'running'].includes(state.phase)}>Start scan</button>
        <span className="small muted">{TYPES[type]}</span>
      </div>
      {state && (
        <div style={{ marginTop: 12 }} aria-live="polite">
          {state.phase === 'error' && <p className="st-ERROR small">{state.error}</p>}
          {state.phase === 'queued' && <p className="small muted">Queued. The agent picks it up on its next heartbeat.</p>}
          {['running', 'done', 'failed'].includes(state.phase) && (
            <>
              <div className="progress"><span style={{ width: `${state.progress}%` }} /></div>
              <p className="small muted" style={{ marginTop: 6 }}>
                {state.phase === 'running' && `${state.progress}%, checking ${state.check}`}
                {state.phase === 'done' && `Scan complete: ${state.summary?.findings ?? 0} findings, ${state.summary?.newFindings ?? 0} new, ${state.summary?.autoResolved ?? 0} resolved.`}
                {state.phase === 'failed' && 'Scan failed. See the Scans tab for details.'}
              </p>
            </>
          )}
        </div>
      )}
    </section>
  );
}
