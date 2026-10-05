import { useState } from 'react';
import { useOutletContext } from 'react-router-dom';
import { Async, Empty } from '../../components/ui.jsx';
import { useApi } from '../../hooks/useApi.js';

export default function Services() {
  const { host } = useOutletContext();
  const q = useApi(`/hosts/${host.id}/snapshot`);
  const [show, setShow] = useState('running');
  return (
    <Async q={q} what="services">{(s) => {
      const sv = s.services;
      if (!sv) return <div className="panel"><Empty title="Service list not available">Service enumeration needs systemd on the host. This is reported as “not supported”, not as a failure.</Empty></div>;
      const rows = sv.services.filter((x) => show === 'all' || (show === 'failed' ? x.active === 'failed' : x.sub === 'running'));
      return (
        <section className="panel">
          <div className="panel-head"><h2>Services</h2><p>{sv.running} running, {sv.failed} failed, {sv.total} known to {sv.init}.</p></div>
          <div className="filters" role="group" aria-label="Show services">
            {[['running', 'Running'], ['failed', 'Failed'], ['all', 'All']].map(([k, l]) => <button type="button" key={k} className={`btn btn-small${show === k ? ' btn-primary' : ''}`} onClick={() => setShow(k)}>{l}</button>)}
          </div>
          {rows.length ? <div className="table-wrap"><table>
            <thead><tr><th>Unit</th><th>State</th><th>Description</th></tr></thead>
            <tbody>{rows.map((x) => <tr key={x.name}><td className="mono">{x.name}</td><td className={x.active === 'failed' ? 'st-FAIL' : x.sub === 'running' ? 'st-PASS' : 'muted'}>{x.active} / {x.sub}</td><td className="muted">{x.description}</td></tr>)}</tbody>
          </table></div> : <Empty title={`No ${show} services`} />}
        </section>
      );
    }}</Async>
  );
}
