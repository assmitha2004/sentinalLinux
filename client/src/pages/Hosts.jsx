import { Link } from 'react-router-dom';
import { Async, Empty } from '../components/ui.jsx';
import { useApi } from '../hooks/useApi.js';
import { useSocket } from '../hooks/useSocket.js';
import { HostTable } from './Dashboard.jsx';

export default function Hosts() {
  const hosts = useApi('/hosts');
  useSocket({ 'host:online': () => hosts.reload(true), 'host:offline': () => hosts.reload(true), 'host:status': () => hosts.reload(true), 'scan:completed': () => hosts.reload(true) });
  return (
    <>
      <div className="page-head"><div><h1>Hosts</h1><p>Machines running the SentinelAI agent.</p></div></div>
      <section className="panel">
        <Async q={hosts} what="hosts">{(list) => (list.length ? <HostTable hosts={list} /> : (
          <Empty title="No hosts enrolled"><p>Create an enrollment token in <Link to="/settings">Settings</Link> and run the agent installer on the host.</p></Empty>
        ))}</Async>
      </section>
    </>
  );
}
