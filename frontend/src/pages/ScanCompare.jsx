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
      if (next.has(id)) next.delete(id); else next.add(id);
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
      <h3 className="card-title mb-2">Select scans to compare</h3>
      {scans.length > 0 ? (
        <>
          <div className="table-wrap">
            <table>
              <thead><tr><th style={{ width: 40 }}></th><th>Scanner</th><th>Date</th><th>Submitted by</th></tr></thead>
              <tbody>
                {scans.map(s => (
                  <tr key={s.id}>
                    <td><input type="checkbox" checked={selected.has(s.id)} onChange={() => onToggle(s.id)} style={{ accentColor: 'var(--accent)', width: 16, height: 16, cursor: 'pointer' }} /></td>
                    <td><strong>{s.scanner_name}</strong></td>
                    <td>{s.scan_date}</td>
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
  const { scanners, matrix, fp_matrix } = data;
  const ALL_SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'];
  const [sevFilter, setSevFilter] = useState(new Set(ALL_SEVERITIES));

  const toggleSev = (sev) => {
    setSevFilter(prev => {
      const next = new Set(prev);
      if (next.has(sev)) { if (next.size > 1) next.delete(sev); }
      else next.add(sev);
      return next;
    });
  };

  const filteredMatrix = matrix.filter(row => sevFilter.has(row.vuln.severity));

  const computeMetrics = (scannerIdx) => {
    const s = scanners[scannerIdx];
    const tp = filteredMatrix.filter(row => row.detections[scannerIdx]).length;
    const fn = filteredMatrix.filter(row => !row.detections[scannerIdx]).length;
    const fp = s.metrics.fp;
    const precision = (tp + fp) > 0 ? tp / (tp + fp) : 0;
    const recall = (tp + fn) > 0 ? tp / (tp + fn) : 0;
    const f1 = (precision + recall) > 0 ? 2 * precision * recall / (precision + recall) : 0;
    return { tp, fn, fp, pending: s.metrics.pending, precision, recall, f1 };
  };

  const filteredMetrics = scanners.map((_, i) => computeMetrics(i));
  const filteredVulnCount = filteredMatrix.length;
  const isFiltered = sevFilter.size < ALL_SEVERITIES.length;

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

  const METRIC_TOOLTIPS = {
    tp: 'Known vulnerabilities detected by the scanner (unique matched vulns)',
    fp: 'Findings that don\'t correspond to any known vulnerability',
    fn: 'Known vulnerabilities the scanner failed to detect',
    pending: 'Findings not yet mapped to a known vulnerability',
    precision: 'TP / (TP + FP) — How many of the scanner\'s findings are real vulnerabilities',
    recall: 'TP / (TP + FN) — How many of the known vulnerabilities were found',
    f1: 'Harmonic mean of Precision and Recall — Overall scanner accuracy',
  };

  const MetricLabel = ({ k }) => {
    const names = { tp: 'True Positives', fp: 'False Positives', fn: 'False Negatives', pending: 'Pending', precision: 'Precision', recall: 'Recall', f1: 'F1 Score' };
    const tip = METRIC_TOOLTIPS[k];
    return (
      <>{names[k]}{tip && <span className="text-muted text-xs" style={{ marginLeft: 4, cursor: 'help' }} title={tip}>ⓘ</span>}</>
    );
  };

  return (
    <>
      <div className="flex gap-1 items-center mb-2" style={{ flexWrap: 'wrap' }}>
        <span className="text-muted text-sm" style={{ marginRight: '0.25rem' }}>Severity:</span>
        {ALL_SEVERITIES.map(sev => (
          <button key={sev} onClick={() => toggleSev(sev)}
            className={`badge badge-${sev}`}
            style={{ cursor: 'pointer', opacity: sevFilter.has(sev) ? 1 : 0.3, transition: 'opacity 0.15s' }}>
            {sev}
          </button>
        ))}
        {isFiltered && <span className="text-muted text-xs" style={{ marginLeft: '0.25rem' }}>({filteredVulnCount} of {matrix.length} vulns)</span>}
      </div>

      <div className="card mb-2">
        <h3 className="card-title mb-2">Metrics Comparison{isFiltered ? <span className="text-muted text-sm"> (filtered)</span> : ''}</h3>
        <div className="compare-scroll">
          <table>
            <thead>
              <tr>
                <th className="sticky-col">Metric</th>
                {scanners.map(s => <th key={s.scan.id} className="text-center"><ScannerHeader s={s} /></th>)}
              </tr>
            </thead>
            <tbody>
              {['tp', 'fp', 'fn', 'pending'].map(k => (
                <tr key={k}>
                  <td className="detail-label sticky-col"><MetricLabel k={k} /></td>
                  {filteredMetrics.map((m, i) => (
                    <td key={scanners[i].scan.id} className={`text-center font-mono ${k === 'tp' ? 'text-success' : k === 'fp' || k === 'fn' ? 'text-error' : 'text-warning'}`}>{m[k]}</td>
                  ))}
                </tr>
              ))}
              {['precision', 'recall', 'f1'].map(k => (
                <tr key={k}>
                  <td className="detail-label sticky-col"><MetricLabel k={k} /></td>
                  {filteredMetrics.map((m, i) => (
                    <td key={scanners[i].scan.id} className={`text-center font-mono ${pctColor(m[k])}`}>{(m[k] * 100).toFixed(1)}%</td>
                  ))}
                </tr>
              ))}
              <tr>
                <td className="detail-label sticky-col">Detection Rate</td>
                {filteredMetrics.map((m, i) => {
                  const rate = filteredVulnCount > 0 ? m.tp / filteredVulnCount : 0;
                  return <td key={scanners[i].scan.id} className="text-center font-mono text-accent">{(rate * 100).toFixed(1)}% ({m.tp}/{filteredVulnCount})</td>;
                })}
              </tr>
              {scanners.some(s => s.scan.duration != null) && (
                <tr>
                  <td className="detail-label sticky-col">Duration</td>
                  {scanners.map(s => (
                    <td key={s.scan.id} className="text-center font-mono text-secondary">
                      {s.scan.duration != null ? (s.scan.duration >= 60 ? `${Math.floor(s.scan.duration / 60)}m ${s.scan.duration % 60}s` : `${s.scan.duration}s`) : '-'}
                    </td>
                  ))}
                </tr>
              )}
              {scanners.some(s => s.scan.tokens != null) && (
                <tr>
                  <td className="detail-label sticky-col">Tokens</td>
                  {scanners.map(s => (
                    <td key={s.scan.id} className="text-center font-mono text-secondary">{s.scan.tokens != null ? s.scan.tokens.toLocaleString() : '-'}</td>
                  ))}
                </tr>
              )}
              {scanners.some(s => s.scan.cost != null) && (
                <tr>
                  <td className="detail-label sticky-col">Cost</td>
                  {scanners.map(s => (
                    <td key={s.scan.id} className="text-center font-mono text-secondary">{s.scan.cost != null ? `$${s.scan.cost.toFixed(4)}` : '-'}</td>
                  ))}
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      <div className="card mb-2">
        <h3 className="card-title mb-2">Detection Matrix{isFiltered ? <span className="text-muted text-sm"> (filtered)</span> : ''}</h3>
        <div className="compare-scroll">
          <table className="matrix-table">
            <thead>
              <tr>
                <th className="sticky-col" style={{ left: 0, minWidth: 70 }}>ID</th>
                <th className="sticky-col" style={{ left: 70, minWidth: 200 }}>Vulnerability</th>
                <th>Severity</th>
                {scanners.map(s => <th key={s.scan.id} className="text-center matrix-header"><ScannerHeader s={s} /></th>)}
                <th className="text-center">Found</th>
              </tr>
            </thead>
            <tbody>
              {filteredMatrix.map((row, i) => (
                <tr key={i}>
                  <td className="font-mono text-sm sticky-col" style={{ left: 0 }}>{row.vuln.vuln_id}</td>
                  <td className="sticky-col" style={{ left: 70 }}>{row.vuln.title}</td>
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
          <div className="compare-scroll">
            <table className="matrix-table">
              <thead>
                <tr>
                  <th className="sticky-col" style={{ left: 0, minWidth: 120 }}>Type</th>
                  <th>Location</th>
                  <th>Parameter</th>
                  {scanners.map(s => <th key={s.scan.id} className="text-center matrix-header"><ScannerHeader s={s} /></th>)}
                  <th className="text-center">Flagged</th>
                </tr>
              </thead>
              <tbody>
                {fp_matrix.map((row, i) => (
                  <tr key={i}>
                    <td className="text-error sticky-col" style={{ left: 0 }}>{row.vuln_type}</td>
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
