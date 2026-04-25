import { useState, useEffect } from 'react';
import { useParams, useSearchParams, Link } from 'react-router-dom';
import { api } from '../api/client';
import { Badge } from '../components/Badge';
import { LabelBadge } from '../components/LabelBadge';

export default function ScanCompare() {
  const { id: appId } = useParams();
  const [searchParams, setSearchParams] = useSearchParams();
  const [app, setApp] = useState(null);
  const [available, setAvailable] = useState([]);
  const [comparison, setComparison] = useState(null);
  const [selected, setSelected] = useState(new Set());
  const [loading, setLoading] = useState(true);

  const scanIds = searchParams.get('scans') || '';

  useEffect(() => {
    const qs = scanIds ? `?scans=${scanIds}` : '';
    api.get(`/apps/${appId}/compare${qs}`).then(data => {
      setApp(data.app);
      setAvailable(data.available_scans || []);
      if (data.scanners) setComparison(data);
      setLoading(false);
    });
  }, [appId, scanIds]);

  const toggleScan = (id) => {
    setSelected(prev => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id); else if (next.size < 7) next.add(id);
      return next;
    });
  };

  const doCompare = () => {
    setSearchParams({ scans: Array.from(selected).join(',') });
  };

  if (loading) return <p className="text-muted">Loading...</p>;

  return (
    <>
      <div className="page-header">
        <h1 className="page-title">Compare Scans <span className="text-muted text-sm">{app?.name}{app?.version ? ` v${app.version}` : ''}</span></h1>
        <Link to={`/apps/${appId}`} className="btn btn-outline">Back to App</Link>
      </div>

      {!comparison ? (
        <ScanSelector scans={available} selected={selected} onToggle={toggleScan} onCompare={doCompare} />
      ) : (
        <ComparisonView data={comparison} appId={appId} />
      )}
    </>
  );
}

function ScanSelector({ scans, selected, onToggle, onCompare }) {
  return (
    <div className="card">
      <h3 className="card-title mb-2">Select scans to compare <span className="text-muted text-sm">(max 7)</span></h3>
      {scans.length > 0 ? (
        <>
          <div className="table-wrap">
            <table>
              <thead><tr><th style={{ width: 40 }}></th><th>Scanner</th><th>Date</th><th>Auth</th><th>Submitted by</th></tr></thead>
              <tbody>
                {scans.map(s => (
                  <tr key={s.id}>
                    <td><input type="checkbox" checked={selected.has(s.id)} onChange={() => onToggle(s.id)} disabled={!selected.has(s.id) && selected.size >= 7} style={{ accentColor: 'var(--accent)' }} /></td>
                    <td><strong>{s.scanner_name}</strong></td>
                    <td>{s.scan_date}</td>
                    <td>{s.authenticated ? 'Yes' : 'No'}</td>
                    <td className="text-secondary">{s.submitter_name || s.submitted_by}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <div className="mt-2">
            <button className="btn btn-primary" onClick={onCompare} disabled={selected.size < 2}>Compare Selected</button>
            <span className="text-muted text-sm" style={{ marginLeft: '0.75rem' }}>{selected.size} selected</span>
          </div>
        </>
      ) : <div className="empty-state"><p>No scans available for this app yet.</p></div>}
    </div>
  );
}

function ComparisonView({ data, appId }) {
  const { scanners, matrix, fp_matrix, known_vuln_count } = data;

  const ScannerHeader = ({ s }) => (
    <>
      <Link to={`/scans/${s.scan.id}`}>{s.scan.scanner_name}</Link><br />
      <span className="text-muted text-xs">{s.short_date}</span>
      {s.labels && s.labels.length > 0 && (
        <div className="scan-labels-cell" style={{ justifyContent: 'center', marginTop: '0.25rem' }}>
          {s.labels.map(l => <LabelBadge key={l.id} label={l} />)}
        </div>
      )}
    </>
  );

  const pctColor = v => v >= 0.7 ? 'text-success' : v >= 0.4 ? 'text-warning' : 'text-error';

  return (
    <>
      <div className="card mb-2">
        <h3 className="card-title mb-2">Metrics Comparison</h3>
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Metric</th>
                {scanners.map(s => <th key={s.scan.id} className="text-center"><ScannerHeader s={s} /></th>)}
              </tr>
            </thead>
            <tbody>
              {['tp', 'fp', 'fn', 'pending'].map(k => (
                <tr key={k}>
                  <td className="detail-label">{k === 'tp' ? 'True Positives' : k === 'fp' ? 'False Positives' : k === 'fn' ? 'False Negatives' : 'Pending'}</td>
                  {scanners.map(s => (
                    <td key={s.scan.id} className={`text-center font-mono ${k === 'tp' ? 'text-success' : k === 'fp' || k === 'fn' ? 'text-error' : 'text-warning'}`}>{s.metrics[k]}</td>
                  ))}
                </tr>
              ))}
              {['precision', 'recall', 'f1'].map(k => (
                <tr key={k}>
                  <td className="detail-label">{k === 'f1' ? 'F1 Score' : k.charAt(0).toUpperCase() + k.slice(1)}</td>
                  {scanners.map(s => (
                    <td key={s.scan.id} className={`text-center font-mono ${pctColor(s.metrics[k])}`}>{(s.metrics[k] * 100).toFixed(1)}%</td>
                  ))}
                </tr>
              ))}
              <tr>
                <td className="detail-label">Detection Rate</td>
                {scanners.map(s => {
                  const rate = known_vuln_count > 0 ? s.metrics.tp / known_vuln_count : 0;
                  return <td key={s.scan.id} className="text-center font-mono text-accent">{(rate * 100).toFixed(1)}% ({s.metrics.tp}/{known_vuln_count})</td>;
                })}
              </tr>
            </tbody>
          </table>
        </div>
      </div>

      <div className="card mb-2">
        <h3 className="card-title mb-2">Detection Matrix</h3>
        <div className="table-wrap">
          <table className="matrix-table">
            <thead>
              <tr>
                <th>ID</th><th>Vulnerability</th><th>Severity</th>
                {scanners.map(s => <th key={s.scan.id} className="text-center matrix-header"><ScannerHeader s={s} /></th>)}
                <th className="text-center">Found</th>
              </tr>
            </thead>
            <tbody>
              {matrix.map((row, i) => (
                <tr key={i}>
                  <td className="font-mono text-sm">{row.vuln.vuln_id}</td>
                  <td>{row.vuln.title}</td>
                  <td><Badge severity={row.vuln.severity} /></td>
                  {row.detections.map((d, j) => (
                    <td key={j} className={`text-center ${d ? 'matrix-hit' : 'matrix-miss'}`}>{d ? '✓' : '✗'}</td>
                  ))}
                  <td className={`text-center font-mono ${row.found_by === scanners.length ? 'text-success' : row.found_by === 0 ? 'text-error' : 'text-warning'}`}>
                    {row.found_by}/{scanners.length}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {fp_matrix && fp_matrix.length > 0 && (
        <div className="card">
          <h3 className="card-title mb-2">False Positives</h3>
          <div className="table-wrap">
            <table className="matrix-table">
              <thead>
                <tr>
                  <th>Type</th><th>Location</th><th>Parameter</th>
                  {scanners.map(s => <th key={s.scan.id} className="text-center matrix-header"><ScannerHeader s={s} /></th>)}
                  <th className="text-center">Flagged</th>
                </tr>
              </thead>
              <tbody>
                {fp_matrix.map((row, i) => (
                  <tr key={i}>
                    <td className="text-error">{row.vuln_type}</td>
                    <td className="font-mono text-sm">{row.location || '-'}</td>
                    <td className="font-mono">{row.parameter || '-'}</td>
                    {row.flagged_by.map((f, j) => (
                      <td key={j} className={`text-center ${f ? 'matrix-hit' : 'matrix-miss'}`}>{f ? '✓' : '✗'}</td>
                    ))}
                    <td className="text-center font-mono text-error">{row.flagged_count}/{scanners.length}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      <div className="mt-2">
        <Link to={`/apps/${appId}/compare`} className="btn btn-outline">Change Selection</Link>
      </div>
    </>
  );
}
