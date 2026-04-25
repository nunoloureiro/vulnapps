import { useState, useEffect } from 'react';
import { useParams, Link } from 'react-router-dom';
import { api } from '../api/client';

export default function VulnDetail() {
  const { appId, id } = useParams();

  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    async function load() {
      setLoading(true);
      setError(null);
      try {
        const result = await api.get('/api/apps/' + appId + '/vulns/' + id);
        setData(result);
      } catch (err) {
        setError(err.message || 'Failed to load vulnerability');
      } finally {
        setLoading(false);
      }
    }
    load();
  }, [appId, id]);

  if (loading) {
    return <div className="container"><div className="empty-state"><p>Loading...</p></div></div>;
  }

  if (error) {
    return <div className="container"><div className="alert alert-error">{error}</div></div>;
  }

  if (!data) return null;

  const { vuln, app, can_edit } = data;

  return (
    <div className="container">
      <div className="page-header">
        <div>
          <h1 className="page-title">{vuln.title}</h1>
          <p className="text-sm text-secondary mt-1">{app.name}</p>
        </div>
        <div className="flex gap-1">
          {can_edit && (
            <Link to={'/apps/' + appId + '/vulns/' + id + '/edit'} className="btn btn-outline">Edit</Link>
          )}
          <Link to={'/apps/' + appId} className="btn btn-outline">Back to App</Link>
        </div>
      </div>

      <div className="card">
        <div className="detail-grid">
          <span className="detail-label">Vuln ID</span>
          <span className="detail-value font-mono">{vuln.vuln_id}</span>

          <span className="detail-label">Title</span>
          <span className="detail-value">{vuln.title}</span>

          <span className="detail-label">Severity</span>
          <span className="detail-value">
            <span className={'badge badge-' + vuln.severity}>{vuln.severity}</span>
          </span>

          <span className="detail-label">Type</span>
          <span className="detail-value">{vuln.vuln_type || '-'}</span>

          <span className="detail-label">HTTP Method</span>
          <span className="detail-value font-mono">{vuln.http_method || '-'}</span>

          <span className="detail-label">URL</span>
          <span className="detail-value font-mono">{vuln.url || '-'}</span>

          <span className="detail-label">Parameter</span>
          <span className="detail-value font-mono">{vuln.parameter || '-'}</span>

          <span className="detail-label">Filename</span>
          <span className="detail-value font-mono">
            {vuln.filename
              ? vuln.filename + (vuln.line_number ? ':' + vuln.line_number : '')
              : '-'}
          </span>

          <span className="detail-label">Code Location</span>
          <span className="detail-value font-mono">{vuln.code_location || '-'}</span>
        </div>
      </div>

      {vuln.description && (
        <div className="card mt-2">
          <h3 className="card-title mb-2">Description</h3>
          <p className="text-sm">{vuln.description}</p>
        </div>
      )}

      {vuln.poc && (
        <div className="card mt-2">
          <h3 className="card-title mb-2">Proof of Concept</h3>
          <pre style={{
            background: 'var(--bg)',
            border: '1px solid var(--border)',
            borderRadius: 'var(--radius)',
            padding: '1rem',
            overflowX: 'auto',
          }}>
            <code className="font-mono text-sm">{vuln.poc}</code>
          </pre>
        </div>
      )}

      {vuln.remediation && (
        <div className="card mt-2">
          <h3 className="card-title mb-2">Remediation</h3>
          <p className="text-sm">{vuln.remediation}</p>
        </div>
      )}
    </div>
  );
}
