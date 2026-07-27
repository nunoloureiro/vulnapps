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

  // F1 winner — the scanner with the highest F1 (only if it's strictly better
  // than the runner-up; on ties we don't crown anyone).
  const winnerIdx = (() => {
    if (filteredMetrics.length < 2) return -1;
    let bestIdx = 0;
    let bestF1 = filteredMetrics[0].f1;
    let tie = false;
    for (let i = 1; i < filteredMetrics.length; i++) {
      const f1 = filteredMetrics[i].f1;
      if (f1 > bestF1) { bestF1 = f1; bestIdx = i; tie = false; }
      else if (f1 === bestF1) { tie = true; }
    }
    return bestF1 > 0 && !tie ? bestIdx : -1;
  })();

  const ScannerHeader = ({ s, isWinner }) => (
    <>
      {isWinner && (
        <div title="Highest F1" style={{ fontSize: '1rem', lineHeight: 1, marginBottom: '0.15rem' }}>🏆</div>
      )}
      <Link to={`/scans/${s.scan.id}`}>{s.scan.scanner_name}</Link>
      {s.scan.scanner_version && <span className="text-muted text-xs"> v{s.scan.scanner_version}</span>}
      <br />
      <span className="text-muted text-xs">{s.short_date}</span>
      {s.labels && s.labels.length > 0 && (
        <div
          className="scan-labels-cell"
          style={{
            justifyContent: 'center',
            marginTop: '0.25rem',
            maxWidth: 240,
            marginLeft: 'auto',
            marginRight: 'auto',
          }}
        >
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
      <>
        {names[k]}
        {tip && (
          <span className="tooltip-wrap text-muted text-xs" style={{ marginLeft: 4 }}>
            ⓘ
            <span className="tooltip-text">{tip}</span>
          </span>
        )}
      </>
    );
  };

  const WINNER_BG = 'rgba(249, 115, 22, 0.08)';
  const winnerStyle = (i) => (i === winnerIdx ? { background: WINNER_BG } : undefined);

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
                {scanners.map((s, i) => (
                  <th
                    key={s.scan.id}
                    className="text-center"
                    style={winnerStyle(i)}
                  >
                    <ScannerHeader s={s} isWinner={i === winnerIdx} />
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {['tp', 'fp', 'fn', 'pending'].map(k => (
                <tr key={k}>
                  <td className="detail-label sticky-col"><MetricLabel k={k} /></td>
                  {filteredMetrics.map((m, i) => (
                    <td
                      key={scanners[i].scan.id}
                      className={`text-center font-mono ${k === 'tp' ? 'text-success' : k === 'fp' || k === 'fn' ? 'text-error' : 'text-warning'}`}
                      style={winnerStyle(i)}
                    >
                      {m[k]}
                    </td>
                  ))}
                </tr>
              ))}
              {['precision', 'recall', 'f1'].map(k => (
                <tr key={k}>
                  <td className="detail-label sticky-col"><MetricLabel k={k} /></td>
                  {filteredMetrics.map((m, i) => {
                    const isWinnerF1 = k === 'f1' && i === winnerIdx;
                    const baseStyle = winnerStyle(i);
                    const style = isWinnerF1 ? { ...baseStyle, fontWeight: 700 } : baseStyle;
                    return (
                      <td
                        key={scanners[i].scan.id}
                        className={`text-center font-mono ${pctColor(m[k])}`}
                        style={style}
                      >
                        {(m[k] * 100).toFixed(1)}%
                      </td>
                    );
                  })}
                </tr>
              ))}
              {scanners.some(s => s.scan.duration != null) && (
                <tr>
                  <td className="detail-label sticky-col">Duration</td>
                  {scanners.map((s, i) => (
                    <td key={s.scan.id} className="text-center font-mono text-secondary" style={winnerStyle(i)}>
                      {s.scan.duration != null ? (s.scan.duration >= 60 ? `${Math.floor(s.scan.duration / 60)}m ${s.scan.duration % 60}s` : `${s.scan.duration}s`) : '-'}
                    </td>
                  ))}
                </tr>
              )}
              {scanners.some(s => s.scan.tokens != null) && (
                <tr>
                  <td className="detail-label sticky-col">Tokens</td>
                  {scanners.map((s, i) => (
                    <td key={s.scan.id} className="text-center font-mono text-secondary" style={winnerStyle(i)}>{s.scan.tokens != null ? s.scan.tokens.toLocaleString() : '-'}</td>
                  ))}
                </tr>
              )}
              {scanners.some(s => s.scan.cost != null) && (
                <tr>
                  <td className="detail-label sticky-col">Cost</td>
                  {scanners.map((s, i) => (
                    <td key={s.scan.id} className="text-center font-mono text-secondary" style={winnerStyle(i)}>{s.scan.cost != null ? `$${s.scan.cost.toFixed(4)}` : '-'}</td>
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

      <F1TimelineChart scanners={scanners} metrics={filteredMetrics} isFiltered={isFiltered} />

      <div className="mt-2">
        <Link to={`/apps/${appId}/compare`} className="btn btn-outline">Change Selection</Link>
      </div>
    </>
  );
}

// F1-vs-date scatter shown above the metrics table. Single series (all points
// are scans of this app), so one accent hue + direct labels carry identity —
// no legend, no rank-based coloring. F1 comes from the severity-filtered
// metrics, so the chart recomputes live with the filter. Honest 0–100% y-axis.
function F1TimelineChart({ scanners, metrics, isFiltered }) {
  const [hover, setHover] = useState(null);

  const pts = scanners.map((s, i) => {
    const raw = String(s.scan.scan_date || '');
    const t = Date.parse(raw.replace(' ', 'T'));
    return {
      i,
      name: s.scan.scanner_name || 'scan',
      version: s.scan.scanner_version,
      dateLabel: s.short_date || raw,
      t: Number.isFinite(t) ? t : null,
      f1: metrics[i].f1,
    };
  });
  if (pts.length < 2) return null;

  const W = 820, H = 340;
  const M = { top: 24, right: 128, bottom: 40, left: 46 };
  const plotW = W - M.left - M.right;
  const plotH = H - M.top - M.bottom;
  const XPAD = 0.06;

  const times = pts.map(p => p.t).filter(v => v != null);
  const tMin = times.length ? Math.min(...times) : 0;
  const tMax = times.length ? Math.max(...times) : 1;
  const tSpan = tMax - tMin;

  const xOf = (p, idx) => {
    let frac;
    if (tSpan > 0 && p.t != null) frac = (p.t - tMin) / tSpan;
    else frac = pts.length > 1 ? idx / (pts.length - 1) : 0.5; // all same/unknown date → even spread
    return M.left + plotW * (XPAD + frac * (1 - 2 * XPAD));
  };
  const yOf = f1 => M.top + plotH * (1 - Math.max(0, Math.min(1, f1)));

  const yTicks = [0, 0.2, 0.4, 0.6, 0.8, 1.0];
  const trunc = n => (n.length > 22 ? n.slice(0, 21) + '…' : n);

  // YY-MM-DD from an epoch-ms (UTC so it matches the stored date string).
  const pad = v => String(v).padStart(2, '0');
  const fmtYMD = ms => {
    const d = new Date(ms);
    return `${pad(d.getUTCFullYear() % 100)}-${pad(d.getUTCMonth() + 1)}-${pad(d.getUTCDate())}`;
  };

  // X-axis ticks: a handful of evenly-spaced dates across the range (or a
  // single centered date when every scan shares one date).
  const N_TICKS = Math.min(6, Math.max(2, pts.length));
  const xTicks = tSpan > 0
    ? Array.from({ length: N_TICKS }, (_, k) => {
        const ms = tMin + (tSpan * k) / (N_TICKS - 1);
        return { x: M.left + plotW * (XPAD + (k / (N_TICKS - 1)) * (1 - 2 * XPAD)), label: fmtYMD(ms) };
      })
    : [{ x: M.left + plotW / 2, label: pts.find(p => p.t != null) ? fmtYMD(pts.find(p => p.t != null).t) : pts[0].dateLabel }];

  // Least-squares trend line over the plotted points (best fit, not a
  // point-to-point connector). Fit f1 = a + b*x in pixel-x; draw across the
  // plot and clip to the box so an extrapolated end can't escape the axes.
  const xs = pts.map((p, idx) => xOf(p, idx));
  const ys = pts.map(p => p.f1);
  const n = xs.length;
  const sx = xs.reduce((a, v) => a + v, 0);
  const sy = ys.reduce((a, v) => a + v, 0);
  const sxx = xs.reduce((a, v) => a + v * v, 0);
  const sxy = xs.reduce((a, v, i) => a + v * ys[i], 0);
  const denom = n * sxx - sx * sx;
  const b = denom !== 0 ? (n * sxy - sx * sy) / denom : 0;
  const a = (sy - b * sx) / n;
  const yRaw = f1 => M.top + plotH * (1 - f1); // unclamped (trend line is clipped instead)
  const trendX0 = M.left, trendX1 = W - M.right;
  const trendY0 = yRaw(a + b * trendX0), trendY1 = yRaw(a + b * trendX1);

  // Vertical de-collision for the point labels: two labels only clash when
  // their points are close in x (labels sit to the right), so push the later
  // one down until it clears any already-placed label within a label-width.
  const LABEL_W = 132, LABEL_H = 13;
  const labelY = {};
  const placed = [];
  pts.map((p, idx) => ({ idx, x: xOf(p, idx), y: yOf(p.f1) }))
    .sort((q, r) => q.x - r.x || q.y - r.y)
    .forEach(o => {
      let ly = o.y + 3.5;
      let guard = 0;
      while (guard++ < 40 && placed.some(q => Math.abs(q.x - o.x) < LABEL_W && Math.abs(q.ly - ly) < LABEL_H)) ly += LABEL_H;
      if (ly > M.top + plotH - 2) ly = o.y + 3.5 - LABEL_H; // pushed off the bottom → flip above
      placed.push({ x: o.x, ly });
      labelY[o.idx] = ly;
    });

  const ACCENT = 'var(--accent)', GRID = 'var(--border)', MUTED = 'var(--text-muted)';
  const SECN = 'var(--text-secondary)', SURF = 'var(--bg-panel)';
  const clipId = 'f1plot';

  return (
    <div className="card mb-2">
      <h3 className="card-title mb-2">F1 Score over Time{isFiltered ? <span className="text-muted text-sm"> (filtered)</span> : ''}</h3>
      <svg viewBox={`0 0 ${W} ${H}`} width="100%" style={{ display: 'block', maxHeight: 380 }}
        role="img" aria-label="F1 score of each scan plotted against its scan date, with a linear trend line">
        <defs>
          <clipPath id={clipId}><rect x={M.left} y={M.top} width={plotW} height={plotH} /></clipPath>
        </defs>
        {yTicks.map(t => {
          const y = yOf(t);
          return (
            <g key={t}>
              <line x1={M.left} y1={y} x2={W - M.right} y2={y} stroke={GRID} strokeWidth="1" />
              <text x={M.left - 8} y={y + 3.5} textAnchor="end" fontSize="11" fill={MUTED}>{Math.round(t * 100)}%</text>
            </g>
          );
        })}
        <line x1={M.left} y1={M.top + plotH} x2={W - M.right} y2={M.top + plotH} stroke={GRID} strokeWidth="1" />

        {/* X-axis ticks + YY-MM-DD labels */}
        {xTicks.map((tk, k) => (
          <g key={k}>
            <line x1={tk.x} y1={M.top + plotH} x2={tk.x} y2={M.top + plotH + 5} stroke={GRID} strokeWidth="1" />
            <text x={tk.x} y={M.top + plotH + 20} textAnchor="middle" fontSize="11" fill={MUTED} className="font-mono">{tk.label}</text>
          </g>
        ))}

        {/* linear trend line (clipped to the plot box) */}
        <line x1={trendX0} y1={trendY0} x2={trendX1} y2={trendY1} clipPath={`url(#${clipId})`}
          stroke={ACCENT} strokeWidth="2" strokeDasharray="6 4" opacity="0.55" />

        {pts.map((p, idx) => {
          const x = xOf(p, idx), y = yOf(p.f1);
          const ly = labelY[idx];
          const offset = Math.abs(ly - (y + 3.5)) > 2;
          return (
            <g key={p.i}>
              {offset && <line x1={x} y1={y} x2={x + 8} y2={ly - 3.5} stroke={GRID} strokeWidth="1" opacity="0.7" />}
              <circle cx={x} cy={y} r={hover === idx ? 7 : 5.5} fill={ACCENT} stroke={SURF} strokeWidth="2"
                style={{ cursor: 'pointer' }}
                onMouseEnter={() => setHover(idx)} onMouseLeave={() => setHover(null)} />
              <text x={x + 10} y={ly} fontSize="11" fill={SECN}>{trunc(p.name)}</text>
            </g>
          );
        })}

        {hover != null && (() => {
          const p = pts[hover], x = xOf(p, hover), y = yOf(p.f1);
          const label = `${p.name}${p.version ? ' v' + p.version : ''} · ${p.t != null ? fmtYMD(p.t) : p.dateLabel} · F1 ${(p.f1 * 100).toFixed(1)}%`;
          const w = Math.min(360, 14 + label.length * 6.1);
          const tx = Math.min(Math.max(x - w / 2, 4), W - w - 4);
          const ty = y - 34 < M.top ? y + 14 : y - 34;
          return (
            <g pointerEvents="none">
              <rect x={tx} y={ty} width={w} height="24" rx="4" fill="var(--bg)" stroke={GRID} strokeWidth="1" />
              <text x={tx + w / 2} y={ty + 16} textAnchor="middle" fontSize="11" fill="var(--text)">{label}</text>
            </g>
          );
        })()}
      </svg>
    </div>
  );
}
