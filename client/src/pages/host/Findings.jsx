import { useOutletContext } from 'react-router-dom';
import FindingsList from '../FindingsList.jsx';

export default function HostFindings() {
  const { host } = useOutletContext();
  return <section className="panel"><FindingsList hostId={host.id} /></section>;
}
