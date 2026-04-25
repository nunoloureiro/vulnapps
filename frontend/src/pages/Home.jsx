import { Link } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';

export default function Home() {
  const { user } = useAuth();
  return (
    <div className="hero">
      <h1>Vulnapps</h1>
      <p className="text-secondary">Benchmark security scanners against known-vulnerable applications. Register apps, define vulnerabilities, submit scan results, and measure accuracy with precision, recall, and F1 metrics.</p>
      <div className="flex gap-1 mt-2" style={{ justifyContent: 'center' }}>
        <Link to="/apps" className="btn btn-primary">Browse Apps</Link>
        {!user && <Link to="/register" className="btn btn-outline">Get Started</Link>}
      </div>
    </div>
  );
}
