import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import { api } from '../api/client';

export default function Home() {
  const { user } = useAuth();
  const [version, setVersion] = useState(null);

  useEffect(() => {
    api.get('/version', { noRedirect: true }).then((data) => setVersion(data.version)).catch(() => {});
  }, []);

  return (
    <div className="hero">
      <div className="hero-title">
        <h1>Vulnapps</h1>
        {version && <span className="hero-version">{version}</span>}
      </div>
      <p className="text-secondary">Benchmark security scanners against known-vulnerable applications. Register apps, define vulnerabilities, submit scan results, and measure accuracy with precision, recall, and F1 metrics.</p>
      <div className="flex gap-1 mt-2" style={{ justifyContent: 'center' }}>
        <Link to="/apps" className="btn btn-primary">Browse Apps</Link>
        {!user && <Link to="/register" className="btn btn-outline">Get Started</Link>}
      </div>
    </div>
  );
}
