import { useState, useEffect, useMemo } from 'react';
import { useParams, Link } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import { api } from '../api/client';
import { Badge } from '../components/Badge';
import { LabelBadge } from '../components/LabelBadge';

export default function ScanDetail() {
  const { id } = useParams();
  const { user } = useAuth();
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  const load = () => {
    api.get(`/scans/${id}`).then(d => { setData(d); setLoading(false); }).catch(e => { setError(e.message); setLoading(false); });
  };
  useEffect(load, [id]);

  if (loading) return <p className="text-muted">Loading...</p>;
  if (error) return <div className="alert alert-error">{error}</div>;
  if (!data) return null;

  const { scan, app, metrics, findings, missed_vulns, known_vulns, labels, can_edit, can_view_cost } = data;

  return (
    <>
      <div className="page-header">
        <h1 className="page-title">{scan.scanner_name}</h1>
        <Link to={`/apps/${app.id}`} className="btn btn-outline">Back to App</Link>
      </div>

      <ScanMeta scan={scan} app={app} labels={labels || []} canEdit={can_edit} canViewCost={can_view_cost} scanId={id} onUpdate={load} />
      <Metrics metrics={metrics} />
      <Findings findings={findings} knownVulns={known_vulns || []} canEdit={can_edit} scanId={id} appId={app.id} onUpdate={load} />
      {missed_vulns && missed_vulns.length > 0 && <MissedVulns vulns={missed_vulns} appId={app.id} />}
    </>
  );
}

function ScanMeta({ scan, app, labels, canEdit, canViewCost, scanId, onUpdate }) {
  const [showLabelInput, setShowLabelInput] = useState(false);
  const [labelName, setLabelName] = useState('');
  const [allLabels, setAllLabels] = useState([]);

  useEffect(() => {
    api.get('/labels').then(d => setAllLabels(d.labels || []));
  }, []);

  const addLabel = async (name, color = '#f97316') => {
    await api.post(`/scans/${scanId}/labels`, { name, color });
    setLabelName('');
    setShowLabelInput(false);
    onUpdate();
  };

  const removeLabel = async (labelId) => {
    await api.del(`/scans/${scanId}/labels/${labelId}`);
    onUpdate();
  };

  return (
    <div className="card">
      <div className="detail-grid">
        <span className="detail-label">Scanner</span>
        <span className="detail-value">{scan.scanner_name}</span>
        <span className="detail-label">App</span>
        <span className="detail-value"><Link to={`/apps/${app.id}`}>{app.name}</Link></span>
        <span className="detail-label">Scan Date</span>
        <span className="detail-value">{scan.scan_date}</span>
        <span className="detail-label">Authenticated</span>
        <span className="detail-value">{scan.authenticated ? 'Yes' : 'No'}</span>
        <span className="detail-label">Submitted By</span>
        <span className="detail-value text-secondary">{scan.submitter_name || scan.submitted_by}</span>
        <span className="detail-label">Labels</span>
        <span className="detail-value">
          <div className="scan-labels-cell">
            {labels.map(l => <LabelBadge key={l.id} label={l} onRemove={canEdit ? removeLabel : undefined} />)}
            {canEdit && !showLabelInput && (
              <button className="btn btn-outline btn-sm" onClick={() => setShowLabelInput(true)} style={{ height: 22, padding: '0 0.4rem', fontSize: '0.7rem' }}>+ Label</button>
            )}
            {showLabelInput && (
              <div style={{ display: 'flex', gap: 4, alignItems: 'center' }}>
                <input className="form-input" value={labelName} onChange={e => setLabelName(e.target.value)} placeholder="Label name..." style={{ width: 120, padding: '2px 6px', fontSize: '0.8rem' }}
                  onKeyDown={e => { if (e.key === 'Enter' && labelName.trim()) addLabel(labelName.trim()); if (e.key === 'Escape') setShowLabelInput(false); }}
                  list="label-suggestions" autoFocus />
                <datalist id="label-suggestions">
                  {allLabels.map(l => <option key={l.id} value={l.name} />)}
                </datalist>
                <button className="btn btn-primary btn-sm" onClick={() => labelName.trim() && addLabel(labelName.trim())} style={{ height: 22, padding: '0 0.4rem', fontSize: '0.7rem' }}>Add</button>
              </div>
            )}
          </div>
        </span>
        {canViewCost && scan.cost != null && (
          <>
            <span className="detail-label">Cost <span className="text-muted text-xs">(private)</span></span>
            <span className="detail-value font-mono">${scan.cost.toFixed(4)}</span>
          </>
        )}
        {scan.notes && (
          <>
            <span className="detail-label">Notes</span>
            <span className="detail-value">{scan.notes}</span>
          </>
        )}
      </div>
    </div>
  );
}

function Metrics({ metrics }) {
  const fmt = v => v != null ? `${(v * 100).toFixed(1)}%` : 'N/A';
  return (
    <>
      <h2 className="page-title mt-3 mb-2">Metrics</h2>
      <div className="metrics-grid mb-2">
        <div className="metric-card"><div className="metric-value text-success">{metrics.tp}</div><div className="metric-label">True Positives</div></div>
        <div className="metric-card"><div className="metric-value text-error">{metrics.fp}</div><div className="metric-label">False Positives</div></div>
        <div className="metric-card"><div className="metric-value text-error">{metrics.fn}</div><div className="metric-label">False Negatives</div></div>
        <div className="metric-card"><div className="metric-value text-accent">{fmt(metrics.precision)}</div><div className="metric-label">Precision</div></div>
        <div className="metric-card"><div className="metric-value text-accent">{fmt(metrics.recall)}</div><div className="metric-label">Recall</div></div>
        <div className="metric-card"><div className="metric-value text-accent">{fmt(metrics.f1)}</div><div className="metric-label">F1 Score</div></div>
      </div>
    </>
  );
}

function Findings({ findings, knownVulns, canEdit, scanId, appId, onUpdate }) {
  const matchFinding = async (findingId, vulnId) => {
    await api.post(`/scans/${scanId}/findings/${findingId}/match`, { vuln_id: vulnId });
    onUpdate();
  };

  const markFP = async (findingId) => {
    await api.post(`/scans/${scanId}/findings/${findingId}/mark-fp`, {});
    onUpdate();
  };

  const rematch = async () => {
    if (!confirm('Re-run automatic matching for all findings?')) return;
    await api.post(`/scans/${scanId}/rematch`, {});
    onUpdate();
  };

  return (
    <>
      <div className="flex items-center justify-between mt-3 mb-2">
        <h2 className="page-title">Findings <span className="text-muted text-sm">({findings.length})</span></h2>
        {canEdit && <button className="btn btn-outline btn-sm" onClick={rematch}>Re-match All</button>}
      </div>
      {findings.length > 0 ? (
        <div className="card">
          <div className="table-wrap">
            <table>
              <thead><tr><th>Type</th><th>Method</th><th>Location</th><th>Parameter</th><th>Status</th><th>Matched Vuln</th>{canEdit && <th></th>}</tr></thead>
              <tbody>
                {findings.map(f => (
                  <tr key={f.id}>
                    <td>{f.vuln_type}</td>
                    <td className="font-mono">{f.http_method || '-'}</td>
                    <td className="font-mono text-sm">{f.url || f.filename || '-'}</td>
                    <td className="font-mono">{f.parameter || '-'}</td>
                    <td>
                      {f.matched_vuln_id ? <Badge severity="low">TP</Badge> :
                       f.is_false_positive ? <Badge severity="critical">FP</Badge> :
                       <Badge severity="pending">Pending</Badge>}
                    </td>
                    <td>
                      {canEdit ? (
                        <select className="form-select" style={{ width: 'auto', padding: '2px 4px', fontSize: '0.8rem' }}
                          value={f.matched_vuln_id || ''} onChange={e => matchFinding(f.id, e.target.value ? parseInt(e.target.value) : null)}>
                          <option value="">-- Unmapped --</option>
                          {knownVulns.map(v => <option key={v.id} value={v.id}>{v.vuln_id} - {v.title}</option>)}
                        </select>
                      ) : (
                        f.matched_vuln_id ? knownVulns.find(v => v.id === f.matched_vuln_id)?.title || 'Matched' :
                        f.is_false_positive ? <span className="text-muted">FP</span> : <span className="text-muted">Unmapped</span>
                      )}
                    </td>
                    {canEdit && (
                      <td>
                        {!f.matched_vuln_id && !f.is_false_positive && (
                          <button className="btn btn-outline btn-sm" onClick={() => markFP(f.id)}>FP</button>
                        )}
                      </td>
                    )}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      ) : <div className="empty-state"><p>No findings in this scan.</p></div>}
    </>
  );
}

function MissedVulns({ vulns, appId }) {
  return (
    <>
      <h2 className="page-title mt-3 mb-2">Missed Vulnerabilities <span className="text-muted text-sm">({vulns.length})</span></h2>
      <div className="card">
        <div className="table-wrap">
          <table>
            <thead><tr><th>ID</th><th>Title</th><th>Type</th><th>Severity</th><th>Location</th></tr></thead>
            <tbody>
              {vulns.map(v => (
                <tr key={v.id}>
                  <td className="font-mono">{v.vuln_id}</td>
                  <td><Link to={`/apps/${appId}/vulns/${v.id}`}>{v.title}</Link></td>
                  <td>{v.vuln_type}</td>
                  <td><Badge severity={v.severity} /></td>
                  <td className="font-mono text-sm">{v.url || v.filename || '-'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </>
  );
}
