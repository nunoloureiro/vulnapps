import { useEffect, useState } from 'react';

export default function DeploymentInfo() {
  const [deployment, setDeployment] = useState(null);

  useEffect(() => {
    const controller = new AbortController();
    fetch('/api/deployment', { cache: 'no-store', signal: controller.signal })
      .then(response => response.ok ? response.json() : null)
      .then(setDeployment)
      .catch(() => {});
    return () => controller.abort();
  }, []);

  if (!deployment?.deployed_at) return null;

  return (
    <footer className="container" style={{ padding: '1rem', opacity: 0.65, fontSize: '0.8rem' }}>
      Deployed <time dateTime={deployment.deployed_at}>{deployment.deployed_at.replace('T', ' ').replace('Z', ' UTC')}</time>
      {deployment.revision && deployment.revision !== 'unknown' && ` · ${deployment.revision.slice(0, 7)}`}
    </footer>
  );
}
