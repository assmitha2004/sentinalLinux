import { useState } from 'react';
import { useOutletContext } from 'react-router-dom';
import { ScoreHistory } from '../../charts/MetricChart.jsx';
import RiskGauge from '../../components/RiskGauge.jsx';
import { Async, Empty, Status } from '../../components/ui.jsx';
import { useApi } from '../../hooks/useApi.js';
import { ago, statusText } from '../../utils/format.js';
import FindingsList from '../FindingsList.jsx';

const AREA_LABEL = { ssh: 'SSH', firewall: 'Firewall', files: 'File permissions', network: 'Network exposure', processes: 'Processes', users: 'Accounts', rootkit: 'Rootkit indicators', kernel: 'Kernel hardening', logging: 'Audit and logging', benchmark: 'CIS benchmark', vulnerabilities: 'Pending updates' };
const AREA_CATEGORY = { ssh: 'ssh', firewall: 'firewall', files: 'permissions,filesystem', network: 'network', processes: 'process', users: 'users,auth',
  rootkit: 'rootkit', kernel: 'kernel', logging: 'logging', benchmark: 'benchmark', vulnerabilities: 'vulnerability' };

export default function Security() {
  const { host } = useOutletContext();
  const q = useApi(`/hosts/${host.id}/security-score`, undefined, [host.scores?.updatedAt]);
  const [area, setArea] = useState(null);
  return (
    <Async q={q} what="security posture">{(s) => (
      <div className="stack">
        <div className="grid cols-main">
          <section className="panel"><h2>Security risk score</h2>
            <RiskGauge score={s.risk.score} level={s.risk.level} caption={s.risk.factors.length ? `Largest contributors: ${s.risk.factors.slice(0, 3).map((f) => f.category).join(', ')}.` : 'No security findings are open.'} />
          </section>
          <section className="panel"><h2>Risk and health over time</h2>
            {s.history.length ? <ScoreHistory data={s.history} /> : <Empty title="History appears after the first scans" />}
          </section>
        </div>
        <section className="panel">
          <div className="panel-head"><h2>Posture by area</h2><p>Select an area to see its findings.</p></div>
          <div className="areas">
            {s.areas.map((a) => (
              <button type="button" key={a.area} className="area" onClick={() => setArea(a.area)} aria-pressed={area === a.area}
                style={area === a.area ? { boxShadow: 'inset 0 -3px 0 var(--accent)' } : undefined}>
                <div className="area-name">{AREA_LABEL[a.area] || a.area}</div>
                <div className="area-status"><Status value={a.status} />{a.openFindings ? <span className="muted"> ({a.openFindings})</span> : null}</div>
                <div className="area-detail">{(a.detail && (a.area === 'firewall' ? `Firewall ${statusText(a.detail).toLowerCase()}` : a.detail)) || (a.lastChecked ? `Checked ${ago(a.lastChecked)}` : 'Not checked yet')}</div>
              </button>))}
          </div>
        </section>
        {area && (
          <section className="panel">
            <div className="panel-head"><h2>{AREA_LABEL[area]} findings</h2><button type="button" className="btn btn-small" onClick={() => setArea(null)}>Clear</button></div>
            <FindingsList hostId={host.id} fixed={{ category: AREA_CATEGORY[area] }} compact />
          </section>
        )}
      </div>
    )}</Async>
  );
}
