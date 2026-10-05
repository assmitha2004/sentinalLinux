import { Link, useNavigate, useOutletContext } from 'react-router-dom';
import { useAuth } from '../../context/AuthContext.jsx';
import { api, errorMessage } from '../../services/api.js';
import RiskGauge from '../../components/RiskGauge.jsx';
import { Async, Meter, Severity, SeverityBar } from '../../components/ui.jsx';
import { useApi } from '../../hooks/useApi.js';
import { duration, healthWord } from '../../utils/format.js';
import ScanControl from './ScanControl.jsx';

export default function Overview() {
  const { host } = useOutletContext();
  const { can } = useAuth();
  const nav = useNavigate();
  const remove = async () => {
    // eslint-disable-next-line no-alert
    if (!window.confirm(`Remove ${host.hostname} and all of its metrics, findings, scans and alerts? Uninstall the agent on the host as well, or it will be rejected on its next heartbeat.`)) return;
    try { await api('delete', `/hosts/${host.id}`); nav('/hosts'); } catch (e) { window.alert(errorMessage(e)); } // eslint-disable-line no-alert
  };
  const score = useApi(`/hosts/${host.id}/security-score`, undefined, [host.scores?.updatedAt]);
  const m = host.latestMetric;
  const worstDisk = m?.disk?.reduce((a, d) => (d.percent > (a?.percent ?? -1) ? d : a), null);
  return (
    <div className="stack">
      <div className="grid cols-main">
        <section className="panel">
          <div className="panel-head"><h2>Security risk</h2><Link to="security" className="small">Posture by area</Link></div>
          <RiskGauge score={host.scores?.risk} level={host.scores?.riskLevel} caption={`Overall posture ${host.scores?.posture ?? '—'}/100 combines security and health; each is scored separately.`} />
          <Async q={score} what="findings">{(s) => (
            <div style={{ marginTop: 16 }}><SeverityBar counts={s.bySeverity} />
              <div className="row small" style={{ marginTop: 8 }}>{['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map((k) => <span key={k}><Severity value={k} /> {s.bySeverity[k]}</span>)}</div>
            </div>)}</Async>
        </section>
        <section className="panel">
          <div className="panel-head"><h2>Health {host.scores?.health ?? '—'}</h2><p>{healthWord(host.scores?.health)}</p></div>
          <div className="stack" style={{ gap: 10 }}>
            <Meter label="CPU" value={m?.cpu?.usage} />
            <Meter label="Memory" value={m?.memory?.percent} />
            <Meter label="Disk" value={worstDisk?.percent} />
          </div>
          <dl className="kv small" style={{ marginTop: 14 }}>
            <dt>Uptime</dt><dd>{duration(m?.uptimeSeconds)}</dd>
            <dt>Processes</dt><dd>{m?.processCount ?? '—'}</dd>
            <dt>Load (1/5/15)</dt><dd>{m?.load ? `${m.load.load1.toFixed(2)} / ${m.load.load5.toFixed(2)} / ${m.load.load15.toFixed(2)}` : '—'}</dd>
          </dl>
        </section>
      </div>
      <ScanControl hostId={host.id} />
      <section className="panel">
        <div className="panel-head"><h2>Detected capabilities</h2><p>Discovered on the host at runtime. Missing tools make checks report “not supported”, never “failed”.</p></div>
        <div className="areas">
          {Object.entries(host.capabilities || {}).map(([k, v]) => (
            <div key={k} className="area" style={{ cursor: 'default' }}>
              <div className="area-name" style={{ textTransform: 'none' }}>{k}</div>
              <div className="area-status">{typeof v === 'boolean' ? <span className={v ? 'st-PASS' : 'st-UNKNOWN'}>{v ? 'Available' : 'Not found'}</span> : String(v ?? 'Not found')}</div>
            </div>))}
        </div>
      </section>
      {can('ADMIN') && (
        <section className="panel">
          <div className="panel-head"><h2>Remove host</h2><p>Deletes this host's data from SentinelAI. The agent's credential stops working immediately.</p></div>
          <button type="button" className="btn btn-danger" onClick={remove}>Remove {host.hostname}</button>
        </section>
      )}
    </div>
  );
}
