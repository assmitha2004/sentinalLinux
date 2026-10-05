import FindingsList from './FindingsList.jsx';
import { useApi } from '../hooks/useApi.js';

export default function Findings() {
  const hosts = useApi('/hosts');
  return (
    <>
      <div className="page-head"><div><h1>Findings</h1><p>Every issue the agents reported, with evidence. Select a row for remediation and verification steps.</p></div></div>
      <section className="panel"><FindingsList hosts={hosts.data || []} /></section>
    </>
  );
}
