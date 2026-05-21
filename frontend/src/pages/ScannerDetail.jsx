import { useState, useEffect } from 'react';
import { useParams, Link, useSearchParams } from 'react-router-dom';
import { api } from '../api/client';
import { LabelBadge } from '../components/LabelBadge';
import { MultiSelect } from '../components/MultiSelect';

const pctColor = (v) => (v >= 0.7 ? 'text-success' : v >= 0.4 ? 'text-warning' : 'text-error');
const fmt = (v) => (v * 100).toFixed(1) + '%';
const fmtCost = (v) => (v != null ? `$${v.toFixed(4)}` : '-');
const fmtDuration = (s) => {
  if (s == null) return '-';
  if (s >= 60) return `${Math.floor(s / 60)}m ${s % 60}s`;
  return `${s}s`;
};

const COLORS = {
  precision: '#3b82f6',
  recall: '#22c55e',
  f1: 'var(--accent)',
  tp: '#22c55e',
  fp: '#ef4444',
  fn: '#eab308',
  cost: 'var(--accent)',
  duration: '#3b82f6',
  tokens: '#8b5cf6',
};

const fmtValue = (v) => (v != null ? v.toFixed(2) : '—');

// Mirrors app/services/dashboard.py:_label_family. Keep in sync.
function labelFamily(name) {
  const n = (name || '').toLowerCase();
  if (n === 'blackbox' || n === 'greybox') return 'methodology';
  if (n.startsWith('judge-')) return 'judge';
  if (n.startsWith('claude-') || n.startsWith('gpt-')) return 'model';
  if (n.startsWith('thinking-')) return 'thinking';
  if (n.startsWith('used-')) return 'tools';
  return null;
}

const FAMILY_LABELS = {
  methodology: 'Methodology',
  model: 'Model',
  judge: 'Judge',
  thinking: 'Thinking budget',
  tools: 'Tools used',
};

export default function ScannerDetail() {
  const { name } = useParams();
  const [searchParams, setSearchParams] = useSearchParams();
  const [data, setData] = useState(null);
  const [error, setError] = useState(null);

  const appParam = searchParams.get('app') || '';
  const selectedAppIds = appParam.split(',').filter(Boolean).map((v) => parseInt(v, 10));

  useEffect(() => {
    const qs = appParam ? '?app=' + encodeURIComponent(appParam) : '';
    api.get('/scanners/' + encodeURIComponent(name) + qs)
      .then(setData)
      .catch((err) => setError(err.message || 'Failed to load scanner'));
  }, [name, appParam]);

  const updateAppFilter = (ids) => {
    const next = new URLSearchParams(searchParams);
    if (ids.length === 0) next.delete('app');
    else next.set('app', ids.join(','));
    setSearchParams(next, { replace: true });
  };

  if (error) {
    return (
      <div className="container">
        <div className="page-header"><h1 className="page-title">{name}</h1></div>
        <div className="alert alert-error">{error}</div>
      </div>
    );
  }

  if (!data) {
    return (
      <div className="container">
        <div className="page-header"><h1 className="page-title">{name}</h1></div>
        <div className="empty-state"><p>Loading...</p></div>
      </div>
    );
  }

  const { summary, time_series: rawTs, labels, available_apps: availableApps = [] } = data;
  const isFiltered = selectedAppIds.length > 0;
  const ts = buildXLabels(rawTs);
  const m = summary.metrics;
  const hasCost = ts.some((s) => s.cost != null);
  const hasTokens = ts.some((s) => s.tokens != null);
  const hasDuration = ts.some((s) => s.duration != null);

  return (
    <div className="container">
      <div className="page-header">
        <h1 className="page-title">{summary.name}</h1>
        <Link to="/scanners" className="btn btn-outline">Back to scanners</Link>
      </div>

      {availableApps.length > 1 && (
        <div className="filter-bar mb-2" style={{ flexWrap: 'wrap' }}>
          <span className="text-muted text-sm" style={{ marginRight: '0.25rem' }}>App:</span>
          <MultiSelect
            options={availableApps.map((a) => ({ value: String(a.id), label: a.name }))}
            selected={selectedAppIds.map(String)}
            onChange={(vals) => updateAppFilter(vals.map((v) => parseInt(v, 10)))}
            allLabel="All apps"
            minWidth={180}
          />
          {isFiltered && (
            <span className="text-muted text-xs">
              (filtered to {selectedAppIds.length === 1 ? '1 app' : `${selectedAppIds.length} apps`})
            </span>
          )}
        </div>
      )}

      {/* Overall metrics */}
      <div className="card mb-2">
        <h3 className="card-title mb-2">
          Overall{isFiltered ? <span className="text-muted text-sm"> (filtered)</span> : ''}
        </h3>
        <div className="detail-grid">
          <span className="detail-label">Apps</span>
          <span className="detail-value font-mono">{summary.app_count}</span>
          <span className="detail-label">Scans</span>
          <span className="detail-value font-mono">{summary.scan_count}</span>
          <span className="detail-label">True Positives</span>
          <span className="detail-value font-mono text-success">{m.tp}</span>
          <span className="detail-label">False Positives</span>
          <span className="detail-value font-mono text-error">{m.fp}</span>
          <span className="detail-label">False Negatives</span>
          <span className="detail-value font-mono text-error">{m.fn}</span>
          <span className="detail-label">Precision</span>
          <span className={`detail-value font-mono ${pctColor(m.precision)}`}>{fmt(m.precision)}</span>
          <span className="detail-label">Recall</span>
          <span className={`detail-value font-mono ${pctColor(m.recall)}`}>{fmt(m.recall)}</span>
          <span className="detail-label">F1</span>
          <span className={`detail-value font-mono ${pctColor(m.f1)}`}>{fmt(m.f1)}</span>
          {summary.avg_cost != null && (
            <>
              <span className="detail-label">Avg Cost</span>
              <span className="detail-value font-mono">{fmtCost(summary.avg_cost)}</span>
            </>
          )}
          {summary.avg_tokens != null && (
            <>
              <span className="detail-label">Avg Tokens</span>
              <span className="detail-value font-mono">{summary.avg_tokens.toLocaleString()}</span>
            </>
          )}
          {summary.avg_duration != null && (
            <>
              <span className="detail-label">Avg Duration</span>
              <span className="detail-value font-mono">{fmtDuration(summary.avg_duration)}</span>
            </>
          )}
        </div>
      </div>

      {ts.length > 0 && (
        <>
          <LineChart
            title="Precision / Recall / F1 over time"
            data={ts}
            series={[
              { key: 'precision', label: 'Precision', color: COLORS.precision },
              { key: 'recall', label: 'Recall', color: COLORS.recall },
              { key: 'f1', label: 'F1', color: COLORS.f1 },
            ]}
            yMax={1}
            formatY={(v) => (v * 100).toFixed(0) + '%'}
          />

          <StackedBarChart
            title="Findings per scan (TP / FP / FN)"
            data={ts}
            series={[
              { key: 'tp', label: 'TP', color: COLORS.tp },
              { key: 'fp', label: 'FP', color: COLORS.fp },
              { key: 'fn', label: 'FN', color: COLORS.fn },
            ]}
          />

          {(hasCost || hasTokens || hasDuration) && (
            <LineChart
              title="Cost / tokens / duration over time"
              data={ts}
              series={[
                hasCost && { key: 'cost', label: 'Cost ($)', color: COLORS.cost, scale: 'cost' },
                hasTokens && { key: 'tokens', label: 'Tokens', color: COLORS.tokens, scale: 'tokens' },
                hasDuration && { key: 'duration', label: 'Duration (s)', color: COLORS.duration, scale: 'duration' },
              ].filter(Boolean)}
              autoscalePerSeries
            />
          )}
        </>
      )}

      {/* Per-app breakdown */}
      {summary.by_app?.length > 0 && (
        <div className="card mt-2">
          <h3 className="card-title mb-2">Per-app breakdown <span className="text-muted text-sm">(latest scan per app)</span></h3>
          <div className="compare-scroll">
            <table>
              <thead>
                <tr>
                  <th className="sticky-col">App</th>
                  <th className="text-center">TP</th>
                  <th className="text-center">FP</th>
                  <th className="text-center">FN</th>
                  <th className="text-center">Precision</th>
                  <th className="text-center">Recall</th>
                  <th className="text-center">F1</th>
                </tr>
              </thead>
              <tbody>
                {summary.by_app.map((a) => (
                  <tr key={a.app_id}>
                    <td className="sticky-col" style={{ fontWeight: 600 }}>
                      <Link to={'/apps/' + a.app_id}>{a.app_name}</Link>
                    </td>
                    <td className="text-center font-mono text-success">{a.tp}</td>
                    <td className="text-center font-mono text-error">{a.fp}</td>
                    <td className="text-center font-mono text-error">{a.fn}</td>
                    <td className={`text-center font-mono ${pctColor(a.precision)}`}>{fmt(a.precision)}</td>
                    <td className={`text-center font-mono ${pctColor(a.recall)}`}>{fmt(a.recall)}</td>
                    <td className={`text-center font-mono ${pctColor(a.f1)}`}>{fmt(a.f1)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      <ByMode scannerName={name} labels={labels || []} />

      {labels?.length > 0 && (
        <div className="card mt-2">
          <h3 className="card-title mb-2">Labels</h3>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
            {labels.map((l) => (
              <span key={l.id} style={{ display: 'inline-flex', alignItems: 'center', gap: 4 }}>
                <LabelBadge label={l} />
                <span className="text-muted text-xs">×{l.count}</span>
              </span>
            ))}
          </div>
        </div>
      )}

      {/* All scans for this scanner */}
      <div className="card mt-2">
        <h3 className="card-title mb-2">Scans <span className="text-muted text-sm">({ts.length})</span></h3>
        <div className="compare-scroll">
          <table>
            <thead>
              <tr>
                <th>Date</th>
                <th>App</th>
                <th className="text-center">TP</th>
                <th className="text-center">FP</th>
                <th className="text-center">FN</th>
                <th className="text-center">F1</th>
                <th className="text-center">Cost</th>
                <th className="text-center">Duration</th>
              </tr>
            </thead>
            <tbody>
              {[...ts].reverse().map((s) => (
                <tr key={s.scan_id}>
                  <td className="font-mono text-sm">
                    <Link to={'/scans/' + s.scan_id}>{s.scan_date}</Link>
                  </td>
                  <td><Link to={'/apps/' + s.app_id}>{s.app_name}</Link></td>
                  <td className="text-center font-mono text-success">{s.tp}</td>
                  <td className="text-center font-mono text-error">{s.fp}</td>
                  <td className="text-center font-mono text-error">{s.fn}</td>
                  <td className={`text-center font-mono ${pctColor(s.f1)}`}>{fmt(s.f1)}</td>
                  <td className="text-center font-mono">{fmtCost(s.cost)}</td>
                  <td className="text-center font-mono">{fmtDuration(s.duration)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}

/* ---------- By Mode (label-family breakdown for this scanner) ---------- */

function ByMode({ scannerName, labels }) {
  // Which families have at least one label in this scanner's history?
  const availableFamilies = new Set();
  for (const l of labels) {
    const fam = labelFamily(l.name);
    if (fam) availableFamilies.add(fam);
  }
  const familyOptions = Object.keys(FAMILY_LABELS).filter((f) => availableFamilies.has(f));

  const [family, setFamily] = useState('');
  const [rows, setRows] = useState(null);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    if (!family) { setRows(null); return; }
    setLoading(true);
    const qs = new URLSearchParams({ scanner: scannerName, group_by: family });
    api.get('/dashboard?' + qs.toString())
      .then((d) => setRows(d.scanners || []))
      .catch(() => setRows([]))
      .finally(() => setLoading(false));
  }, [scannerName, family]);

  if (familyOptions.length === 0) return null;

  const hasCost = (rows || []).some((r) => r.avg_cost != null && r.avg_cost > 0);

  return (
    <div className="card mt-2">
      <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 8 }}>
        <h3 className="card-title" style={{ margin: 0 }}>By Mode</h3>
        <select
          className="form-select"
          value={family}
          onChange={(e) => setFamily(e.target.value)}
        >
          <option value="">— pick a family —</option>
          {familyOptions.map((f) => (
            <option key={f} value={f}>{FAMILY_LABELS[f]}</option>
          ))}
        </select>
      </div>
      {!family && (
        <p className="text-muted text-sm">Pick a label family to break this scanner down by mode (e.g. blackbox vs greybox, model A vs model B).</p>
      )}
      {family && loading && <p className="text-muted text-sm">Loading…</p>}
      {family && !loading && rows && rows.length === 0 && (
        <p className="text-muted text-sm">No scans in this family for this scanner.</p>
      )}
      {family && !loading && rows && rows.length > 0 && (
        <>
          {hasCost && (
            <p className="text-muted text-xs mb-2">
              <strong>F1 / $1k</strong> = F1 score per $1,000 of average scan cost. Higher = better value for money.
            </p>
          )}
          <div className="compare-scroll">
            <table>
              <thead>
                <tr>
                  <th>Mode</th>
                  <th className="text-center">Apps</th>
                  <th className="text-center">Scans</th>
                  <th className="text-center">TP</th>
                  <th className="text-center">FP</th>
                  <th className="text-center">FN</th>
                  <th className="text-center">Precision</th>
                  <th className="text-center">Recall</th>
                  <th className="text-center">F1</th>
                  {hasCost && <th className="text-center">Avg Cost</th>}
                  {hasCost && <th className="text-center" title="F1 score per $1,000 of avg scan cost. Higher = better value.">F1 / $1k</th>}
                </tr>
              </thead>
              <tbody>
                {rows.map((r) => {
                  const m = r.metrics;
                  return (
                    <tr key={r.mode || r.name}>
                      <td style={{ fontWeight: 600 }}>{r.mode || '—'}</td>
                      <td className="text-center font-mono">{r.app_count}</td>
                      <td className="text-center font-mono">{r.scan_count}</td>
                      <td className="text-center font-mono text-success">{m.tp}</td>
                      <td className="text-center font-mono text-error">{m.fp}</td>
                      <td className="text-center font-mono text-error">{m.fn}</td>
                      <td className={`text-center font-mono ${pctColor(m.precision)}`}>{fmt(m.precision)}</td>
                      <td className={`text-center font-mono ${pctColor(m.recall)}`}>{fmt(m.recall)}</td>
                      <td className={`text-center font-mono ${pctColor(m.f1)}`}>{fmt(m.f1)}</td>
                      {hasCost && <td className="text-center font-mono">{fmtCost(r.avg_cost)}</td>}
                      {hasCost && <td className="text-center font-mono">{fmtValue(r.value)}</td>}
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </>
      )}
    </div>
  );
}

/* Disambiguate x-axis labels: when multiple scans share a date, suffix each
 * with #N in chronological order. (The point's tooltip still surfaces the
 * app name, so #N is enough — the user can hover for context.) */
function buildXLabels(ts) {
  if (!Array.isArray(ts) || ts.length === 0) return [];
  const datePart = (s) => String(s.scan_date || '').slice(0, 10);
  const dateCounts = {};
  for (const s of ts) {
    const d = datePart(s);
    dateCounts[d] = (dateCounts[d] || 0) + 1;
  }
  const perDateIdx = {};
  return ts.map((s) => {
    const d = datePart(s);
    if (dateCounts[d] <= 1) return { ...s, x_label: d };
    perDateIdx[d] = (perDateIdx[d] || 0) + 1;
    return { ...s, x_label: `${d} #${perDateIdx[d]}` };
  });
}

/* ---------- Tiny SVG charts ---------- */

const CHART_W = 800;
const CHART_H = 220;
const PADDING = { top: 16, right: 24, bottom: 36, left: 48 };

function chartX(i, n) {
  if (n <= 1) return PADDING.left + (CHART_W - PADDING.left - PADDING.right) / 2;
  const w = CHART_W - PADDING.left - PADDING.right;
  return PADDING.left + (i / (n - 1)) * w;
}
function chartY(v, max) {
  const h = CHART_H - PADDING.top - PADDING.bottom;
  if (max <= 0) return PADDING.top + h;
  return PADDING.top + (1 - v / max) * h;
}

function LineChart({ title, data, series, yMax, formatY, autoscalePerSeries }) {
  if (data.length === 0) return null;

  // Per-series scaling so cost ($0.01) doesn't get crushed by tokens (10000)
  const seriesMax = {};
  for (const s of series) {
    const vals = data.map((d) => d[s.key]).filter((v) => v != null);
    seriesMax[s.key] = vals.length ? Math.max(...vals) : 0;
  }
  const sharedMax = yMax != null
    ? yMax
    : Math.max(...Object.values(seriesMax), 1);

  return (
    <div className="card mt-2">
      <h3 className="card-title mb-2">{title}</h3>
      <Legend series={series} />
      <div style={{ overflowX: 'auto' }}>
        <svg width={CHART_W} height={CHART_H} style={{ display: 'block' }}>
          {/* Y axis grid */}
          {[0, 0.25, 0.5, 0.75, 1].map((p) => {
            const max = autoscalePerSeries ? 1 : sharedMax;
            const y = chartY(p * max, max);
            return (
              <g key={p}>
                <line x1={PADDING.left} y1={y} x2={CHART_W - PADDING.right} y2={y} stroke="var(--border)" strokeWidth="0.5" />
                <text x={PADDING.left - 6} y={y + 3} textAnchor="end" fontSize="10" fill="var(--text-muted)">
                  {formatY ? formatY(p * max) : (p * max).toFixed(0)}
                </text>
              </g>
            );
          })}

          {/* Series lines */}
          {series.map((s) => {
            const max = autoscalePerSeries ? Math.max(seriesMax[s.key] || 1, 1) : sharedMax;
            const points = data.map((d, i) => {
              const v = d[s.key];
              if (v == null) return null;
              return `${chartX(i, data.length)},${chartY(v, max)}`;
            }).filter(Boolean);
            return (
              <g key={s.key}>
                <polyline
                  fill="none"
                  stroke={s.color}
                  strokeWidth="2"
                  points={points.join(' ')}
                />
                {data.map((d, i) => {
                  const v = d[s.key];
                  if (v == null) return null;
                  return (
                    <circle
                      key={i}
                      cx={chartX(i, data.length)}
                      cy={chartY(v, max)}
                      r="3"
                      fill={s.color}
                    >
                      <title>{`${d.x_label} (${d.app_name}) — ${s.label}: ${formatY ? formatY(v) : v}`}</title>
                    </circle>
                  );
                })}
              </g>
            );
          })}

          {/* X labels: show first, last, and ~3 in middle */}
          {data.map((d, i) => {
            const n = data.length;
            const showLabels = n <= 8 || i === 0 || i === n - 1 || i % Math.max(1, Math.floor(n / 5)) === 0;
            if (!showLabels) return null;
            return (
              <text
                key={i}
                x={chartX(i, n)}
                y={CHART_H - PADDING.bottom + 14}
                textAnchor="middle"
                fontSize="10"
                fill="var(--text-muted)"
              >
                {d.x_label}
              </text>
            );
          })}
        </svg>
      </div>
    </div>
  );
}

function StackedBarChart({ title, data, series }) {
  if (data.length === 0) return null;

  const totals = data.map((d) => series.reduce((acc, s) => acc + (d[s.key] || 0), 0));
  const max = Math.max(...totals, 1);

  const innerW = CHART_W - PADDING.left - PADDING.right;
  const barW = Math.max(Math.min(innerW / data.length * 0.7, 30), 6);

  return (
    <div className="card mt-2">
      <h3 className="card-title mb-2">{title}</h3>
      <Legend series={series} />
      <div style={{ overflowX: 'auto' }}>
        <svg width={CHART_W} height={CHART_H} style={{ display: 'block' }}>
          {/* Y axis grid */}
          {[0, 0.25, 0.5, 0.75, 1].map((p) => {
            const y = chartY(p * max, max);
            return (
              <g key={p}>
                <line x1={PADDING.left} y1={y} x2={CHART_W - PADDING.right} y2={y} stroke="var(--border)" strokeWidth="0.5" />
                <text x={PADDING.left - 6} y={y + 3} textAnchor="end" fontSize="10" fill="var(--text-muted)">
                  {Math.round(p * max)}
                </text>
              </g>
            );
          })}

          {/* Bars */}
          {data.map((d, i) => {
            const x = chartX(i, data.length) - barW / 2;
            let yOffset = 0;
            return (
              <g key={i}>
                {series.map((s) => {
                  const v = d[s.key] || 0;
                  if (v === 0) return null;
                  const h = (CHART_H - PADDING.top - PADDING.bottom) * (v / max);
                  const y = chartY(0, max) - yOffset - h;
                  yOffset += h;
                  return (
                    <rect
                      key={s.key}
                      x={x}
                      y={y}
                      width={barW}
                      height={h}
                      fill={s.color}
                    >
                      <title>{`${d.x_label} (${d.app_name}) — ${s.label}: ${v}`}</title>
                    </rect>
                  );
                })}
              </g>
            );
          })}

          {/* X labels */}
          {data.map((d, i) => {
            const n = data.length;
            const showLabels = n <= 8 || i === 0 || i === n - 1 || i % Math.max(1, Math.floor(n / 5)) === 0;
            if (!showLabels) return null;
            return (
              <text
                key={i}
                x={chartX(i, n)}
                y={CHART_H - PADDING.bottom + 14}
                textAnchor="middle"
                fontSize="10"
                fill="var(--text-muted)"
              >
                {d.x_label}
              </text>
            );
          })}
        </svg>
      </div>
    </div>
  );
}

function Legend({ series }) {
  return (
    <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.75rem', marginBottom: '0.5rem' }}>
      {series.map((s) => (
        <div key={s.key} style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
          <span style={{ width: 12, height: 12, background: s.color, borderRadius: 2 }} />
          <span className="text-xs text-muted">{s.label}</span>
        </div>
      ))}
    </div>
  );
}
