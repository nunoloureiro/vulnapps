import { useState, useEffect, useMemo, useCallback } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import { api } from '../api/client';
import { Badge } from '../components/Badge';
import { MultiSelect } from '../components/MultiSelect';

const ALL_SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'];

const SEV_COLORS = {
  critical: '#ef4444',
  high: '#f97316',
  medium: '#eab308',
  low: '#22c55e',
  info: '#3b82f6',
};

const pctColor = (v) => (v >= 0.7 ? 'text-success' : v >= 0.4 ? 'text-warning' : 'text-error');

const pctBarColor = (v) => (v >= 0.7 ? 'var(--success)' : v >= 0.4 ? 'var(--warning)' : 'var(--error)');

const fmt = (v) => (v * 100).toFixed(1) + '%';

const fmtCost = (c) => (c != null ? `$${c.toFixed(4)}` : '-');

const fmtValue = (v) => (v != null ? v.toFixed(2) : '—');

const GROUP_BY_OPTIONS = [
  { value: '', label: 'No grouping' },
  { value: 'methodology', label: 'Methodology' },
  { value: 'model', label: 'Model' },
  { value: 'judge', label: 'Judge' },
  { value: 'thinking', label: 'Thinking budget' },
  { value: 'tools', label: 'Tools used' },
];

const rowKey = (s) => (s.mode ? `${s.name}|${s.mode}` : s.name);
const rowLabel = (s) => (s.mode ? `${s.name} · ${s.mode}` : s.name);

/* Pareto frontier on (cost asc, F1 desc): a point is on the frontier if no
 * other point has BOTH lower cost AND higher F1. Sort by cost asc and keep
 * points whose F1 strictly exceeds the max F1 seen so far. */
function paretoFrontier(points) {
  const valid = points.filter(p => p.cost != null && p.cost > 0 && p.f1 != null);
  const sorted = [...valid].sort((a, b) => a.cost - b.cost || b.f1 - a.f1);
  const frontier = [];
  let bestF1 = -Infinity;
  for (const p of sorted) {
    if (p.f1 > bestF1) { frontier.push(p); bestF1 = p.f1; }
  }
  return frontier;
}

function computeFilteredMetrics(scanner, selectedSeverities) {
  let tp = 0;
  let fn = 0;
  for (const [sev, data] of Object.entries(scanner.by_severity || {})) {
    if (selectedSeverities.has(sev)) {
      tp += data.detected;
      fn += data.total - data.detected;
    }
  }
  const fp = scanner.metrics.fp;
  const precision = tp + fp > 0 ? tp / (tp + fp) : 0;
  const recall = tp + fn > 0 ? tp / (tp + fn) : 0;
  const f1 = precision + recall > 0 ? (2 * precision * recall) / (precision + recall) : 0;
  const total = tp + fn;
  return { tp, fp, fn, precision, recall, f1, total };
}

export default function Dashboard() {
  const { user } = useAuth();
  const [searchParams, setSearchParams] = useSearchParams();

  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [sevFilter, setSevFilter] = useState(new Set(ALL_SEVERITIES));
  const [teams, setTeams] = useState([]);

  const scanner = searchParams.get('scanner') || '';
  const label = searchParams.get('label') || '';
  const tech = searchParams.get('tech') || '';
  const auth = searchParams.get('auth') || '';
  const appFilter = searchParams.get('app') || '';
  const teamFilter = searchParams.get('team') || '';
  const groupBy = searchParams.get('group_by') || '';

  const fetchData = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const params = new URLSearchParams();
      if (scanner) params.set('scanner', scanner);
      if (label) params.set('label', label);
      if (tech) params.set('tech', tech);
      if (auth) params.set('auth', auth);
      if (appFilter) params.set('app', appFilter);
      if (teamFilter) params.set('team', teamFilter);
      if (groupBy) params.set('group_by', groupBy);
      const qs = params.toString();
      const result = await api.get('/dashboard' + (qs ? '?' + qs : ''));
      setData(result);
    } catch (err) {
      setError(err.message || 'Failed to load dashboard data');
    } finally {
      setLoading(false);
    }
  }, [scanner, label, tech, auth, appFilter, teamFilter, groupBy]);

  useEffect(() => {
    fetchData();
  }, [fetchData]);

  useEffect(() => {
    api.get('/teams').catch(() => ({ teams: [] })).then((res) => {
      setTeams(res.teams || []);
    });
  }, []);

  const toggleSev = (sev) => {
    setSevFilter((prev) => {
      const next = new Set(prev);
      if (next.has(sev)) {
        if (next.size > 1) next.delete(sev);
      } else {
        next.add(sev);
      }
      return next;
    });
  };

  const updateFilter = (key, value) => {
    const next = new URLSearchParams(searchParams);
    if (value) next.set(key, value);
    else next.delete(key);
    setSearchParams(next, { replace: true });
  };

  const filteredScanners = useMemo(() => {
    if (!data?.scanners) return [];
    return data.scanners.map((s) => ({
      ...s,
      filtered: computeFilteredMetrics(s, sevFilter),
    }));
  }, [data, sevFilter]);

  const isFiltered = sevFilter.size < ALL_SEVERITIES.length;

  if (loading) {
    return (
      <div className="container">
        <div className="page-header">
          <h1 className="page-title">Dashboard</h1>
        </div>
        <div className="empty-state">
          <p>Loading...</p>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="container">
        <div className="page-header">
          <h1 className="page-title">Dashboard</h1>
        </div>
        <div className="alert alert-error">{error}</div>
      </div>
    );
  }

  if (!data?.scanners?.length) {
    return (
      <div className="container">
        <div className="page-header">
          <h1 className="page-title">Dashboard</h1>
        </div>
        <FilterBar
          filters={data?.filters}
          searchParams={searchParams}
          sevFilter={sevFilter}
          onToggleSev={toggleSev}
          onUpdateFilter={updateFilter}
          isFiltered={isFiltered}
          teams={teams}
        />
        <div className="empty-state">
          <h3>No scan data</h3>
          <p>Submit scans to see cross-app scanner benchmarks here.</p>
        </div>
      </div>
    );
  }

  const hasCostData = filteredScanners.some((s) => s.avg_cost != null && s.avg_cost > 0);

  return (
    <div className="container">
      <div className="page-header">
        <h1 className="page-title">Dashboard</h1>
      </div>

      <FilterBar
        filters={data.filters}
        searchParams={searchParams}
        sevFilter={sevFilter}
        onToggleSev={toggleSev}
        onUpdateFilter={updateFilter}
        isFiltered={isFiltered}
        teams={teams}
      />

      <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
        <SummaryTable scanners={filteredScanners} isFiltered={isFiltered} grouped={!!groupBy} hasCostData={hasCostData} />
        <ScannerComparisonBars scanners={filteredScanners} isFiltered={isFiltered} />
        <SeverityBreakdown scanners={data.scanners} sevFilter={sevFilter} />
        <ScannerAppHeatmap scanners={data.scanners} sevFilter={sevFilter} />
        {hasCostData && <CostEfficiency scanners={filteredScanners} grouped={!!groupBy} />}
      </div>
    </div>
  );
}

/* ---------- Filter Bar ---------- */

function FilterBar({ filters, searchParams, sevFilter, onToggleSev, onUpdateFilter, isFiltered, teams }) {
  return (
    <div className="filter-bar mb-2" style={{ flexWrap: 'wrap' }}>
      <span className="text-muted text-sm" style={{ marginRight: '0.25rem' }}>
        Severity:
      </span>
      {ALL_SEVERITIES.map((sev) => (
        <button
          key={sev}
          onClick={() => onToggleSev(sev)}
          className={`badge badge-${sev}`}
          style={{
            cursor: 'pointer',
            opacity: sevFilter.has(sev) ? 1 : 0.3,
            transition: 'opacity 0.15s',
            border: 'none',
          }}
        >
          {sev}
        </button>
      ))}
      {isFiltered && (
        <span className="text-muted text-xs" style={{ marginLeft: '0.25rem' }}>(filtered)</span>
      )}

      <span style={{ width: '1px', height: '20px', background: 'var(--border)', margin: '0 0.25rem' }} />

      {filters?.scanners?.length > 0 && (
        <MultiSelect
          options={filters.scanners}
          selected={(searchParams.get('scanner') || '').split(',').filter(Boolean)}
          onChange={(values) => onUpdateFilter('scanner', values.join(','))}
          allLabel="All scanners"
        />
      )}

      {filters?.labels?.length > 0 && (
        <select
          className="form-select"
          value={searchParams.get('label') || ''}
          onChange={(e) => onUpdateFilter('label', e.target.value)}
        >
          <option value="">All labels</option>
          {filters.labels.map((l) => (
            <option key={l} value={l}>{l}</option>
          ))}
        </select>
      )}

      {filters?.techs?.length > 0 && (
        <select
          className="form-select"
          value={searchParams.get('tech') || ''}
          onChange={(e) => onUpdateFilter('tech', e.target.value)}
        >
          <option value="">All techs</option>
          {filters.techs.map((t) => (
            <option key={t} value={t}>{t}</option>
          ))}
        </select>
      )}

      {filters?.apps?.length > 0 && (
        <select
          className="form-select"
          value={searchParams.get('app') || ''}
          onChange={(e) => onUpdateFilter('app', e.target.value)}
        >
          <option value="">All apps</option>
          {filters.apps.map((a) => (
            <option key={a.id} value={a.id}>{a.name}</option>
          ))}
        </select>
      )}

      {teams?.length > 0 && (
        <select
          className="form-select"
          value={searchParams.get('team') || ''}
          onChange={(e) => onUpdateFilter('team', e.target.value)}
        >
          <option value="">All teams</option>
          {teams.map((t) => (
            <option key={t.id} value={t.id}>{t.name}</option>
          ))}
        </select>
      )}

      <span style={{ width: '1px', height: '20px', background: 'var(--border)', margin: '0 0.25rem' }} />

      <span className="text-muted text-sm" style={{ marginRight: '0.25rem' }}>Group by:</span>
      <select
        className="form-select"
        value={searchParams.get('group_by') || ''}
        onChange={(e) => onUpdateFilter('group_by', e.target.value)}
        title="Compare scanners across modes (label families)"
      >
        {GROUP_BY_OPTIONS.map((o) => (
          <option key={o.value} value={o.value}>{o.label}</option>
        ))}
      </select>
    </div>
  );
}

/* ---------- Scanner Comparison Bars (vertical, grouped by metric) ---------- */

function ScannerComparisonBars({ scanners, isFiltered }) {
  const metrics = [
    { key: 'precision', label: 'Precision' },
    { key: 'recall', label: 'Recall' },
    { key: 'f1', label: 'F1 Score' },
  ];

  const BAR_HEIGHT = 120;

  return (
    <div className="card">
      <h3 className="card-title mb-2">
        Scanner Comparison{isFiltered ? <span className="text-muted text-sm"> (filtered)</span> : ''}
      </h3>
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '1.5rem' }}>
        {metrics.map((m) => (
          <div key={m.key}>
            <div className="text-sm" style={{ fontWeight: 600, marginBottom: '0.75rem', textAlign: 'center' }}>
              {m.label}
            </div>
            <div style={{ display: 'flex', alignItems: 'flex-end', justifyContent: 'center', gap: '8px', height: BAR_HEIGHT }}>
              {scanners.map((s) => {
                const value = s.filtered[m.key];
                const barH = Math.max(value * BAR_HEIGHT, 2);
                const color = pctBarColor(value);
                return (
                  <div key={rowKey(s)} style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '4px' }}>
                    <span className="font-mono" style={{ fontSize: '0.625rem', color }}>{fmt(value)}</span>
                    <div
                      style={{
                        width: 40,
                        height: barH,
                        background: color,
                        borderRadius: '4px 4px 0 0',
                        transition: 'height 0.3s ease',
                      }}
                      title={`${rowLabel(s)}: ${fmt(value)}`}
                    />
                  </div>
                );
              })}
            </div>
            <div style={{ display: 'flex', justifyContent: 'center', gap: '8px', marginTop: '4px' }}>
              {scanners.map((s) => (
                <span
                  key={rowKey(s)}
                  className="text-muted"
                  style={{
                    width: 40,
                    fontSize: '0.575rem',
                    textAlign: 'center',
                    overflow: 'hidden',
                    textOverflow: 'ellipsis',
                    whiteSpace: 'nowrap',
                  }}
                  title={rowLabel(s)}
                >
                  {rowLabel(s)}
                </span>
              ))}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

/* ---------- Severity Breakdown (vertical, grouped by severity) ---------- */

const SCANNER_COLORS = ['var(--accent)', '#3b82f6', '#22c55e', '#8b5cf6', '#06b6d4', '#f97316', '#ec4899'];

function SeverityBreakdown({ scanners, sevFilter }) {
  const activeSeverities = ALL_SEVERITIES.filter((s) => sevFilter.has(s));
  const BAR_HEIGHT = 120;

  return (
    <div className="card">
      <h3 className="card-title mb-2">Severity Breakdown</h3>
      {/* Scanner legend */}
      <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.75rem', marginBottom: '1rem' }}>
        {scanners.map((s, i) => (
          <div key={rowKey(s)} style={{ display: 'flex', alignItems: 'center', gap: '4px' }}>
            <span style={{ width: 10, height: 10, borderRadius: 2, background: SCANNER_COLORS[i % SCANNER_COLORS.length], flexShrink: 0 }} />
            <span className="text-xs text-muted">{rowLabel(s)}</span>
          </div>
        ))}
      </div>
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(160px, 1fr))', gap: '1.5rem' }}>
        {activeSeverities.map((sev) => {
          // Check if any scanner has data for this severity
          const hasData = scanners.some((s) => s.by_severity?.[sev]?.total > 0);
          if (!hasData) return null;
          return (
            <div key={sev}>
              <div
                className="text-sm"
                style={{
                  fontWeight: 600,
                  marginBottom: '0.75rem',
                  textAlign: 'center',
                  color: SEV_COLORS[sev],
                  textTransform: 'capitalize',
                }}
              >
                {sev}
              </div>
              <div style={{ display: 'flex', alignItems: 'flex-end', justifyContent: 'center', gap: '8px', height: BAR_HEIGHT }}>
                {scanners.map((s, i) => {
                  const sevData = s.by_severity?.[sev];
                  const recall = sevData?.recall ?? 0;
                  const barH = Math.max(recall * BAR_HEIGHT, 2);
                  const color = SCANNER_COLORS[i % SCANNER_COLORS.length];
                  return (
                    <div key={rowKey(s)} style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '4px' }}>
                      <span className="font-mono" style={{ fontSize: '0.625rem', color }}>
                        {sevData ? fmt(recall) : '-'}
                      </span>
                      <div
                        style={{
                          width: 40,
                          height: sevData ? barH : 2,
                          background: sevData ? color : 'var(--border)',
                          borderRadius: '4px 4px 0 0',
                          transition: 'height 0.3s ease',
                          opacity: sevData ? 1 : 0.3,
                        }}
                        title={sevData ? `${rowLabel(s)}: ${fmt(recall)} (${sevData.detected}/${sevData.total})` : `${rowLabel(s)}: no data`}
                      />
                    </div>
                  );
                })}
              </div>
              <div style={{ display: 'flex', justifyContent: 'center', gap: '8px', marginTop: '4px' }}>
                {scanners.map((s) => (
                  <span
                    key={rowKey(s)}
                    className="text-muted"
                    style={{
                      width: 40,
                      fontSize: '0.575rem',
                      textAlign: 'center',
                      overflow: 'hidden',
                      textOverflow: 'ellipsis',
                      whiteSpace: 'nowrap',
                    }}
                    title={rowLabel(s)}
                  >
                    {rowLabel(s)}
                  </span>
                ))}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}

/* ---------- Scanner x App Heatmap ---------- */

function ScannerAppHeatmap({ scanners, sevFilter }) {
  const allApps = useMemo(() => {
    const appMap = new Map();
    for (const s of scanners) {
      for (const a of s.by_app || []) {
        if (!appMap.has(a.app_id)) {
          appMap.set(a.app_id, { id: a.app_id, name: a.app_name });
        }
      }
    }
    return Array.from(appMap.values());
  }, [scanners]);

  const getAppRecall = useCallback(
    (scanner, appId) => {
      const appData = (scanner.by_app || []).find((a) => a.app_id === appId);
      if (!appData) return null;
      return appData.recall ?? 0;
    },
    []
  );

  const cellBg = (recall) => {
    if (recall === null) return 'transparent';
    // Green for high recall, red for low
    const r = Math.round(239 * (1 - recall) + 34 * recall);
    const g = Math.round(68 * (1 - recall) + 197 * recall);
    const b = Math.round(68 * (1 - recall) + 94 * recall);
    return `rgba(${r}, ${g}, ${b}, 0.25)`;
  };

  if (allApps.length === 0) return null;

  return (
    <div className="card">
      <h3 className="card-title mb-2">Scanner x App Heatmap</h3>
      <div className="compare-scroll">
        <table>
          <thead>
            <tr>
              <th className="sticky-col">App</th>
              {scanners.map((s) => (
                <th key={rowKey(s)} className="text-center">{rowLabel(s)}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {allApps.map((app) => (
              <tr key={app.id}>
                <td className="sticky-col">
                  <Link to={`/apps/${app.id}`}>{app.name}</Link>
                </td>
                {scanners.map((s) => {
                  const recall = getAppRecall(s, app.id);
                  return (
                    <td
                      key={rowKey(s)}
                      className="text-center font-mono text-sm"
                      style={{
                        background: cellBg(recall),
                        color: recall === null ? 'var(--text-muted)' : undefined,
                      }}
                    >
                      {recall !== null ? (
                        <span className={pctColor(recall)}>{fmt(recall)}</span>
                      ) : (
                        '-'
                      )}
                    </td>
                  );
                })}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

/* ---------- Cost Efficiency ---------- */

function CostEfficiency({ scanners, grouped }) {
  const withCost = scanners.filter((s) => s.avg_cost != null && s.avg_cost > 0);
  if (withCost.length === 0) return null;

  const maxCost = Math.max(...withCost.map((s) => s.avg_cost));
  const minCost = Math.min(...withCost.map((s) => s.avg_cost));
  const costRange = maxCost - minCost || maxCost || 1;

  const frontier = paretoFrontier(
    withCost.map((s) => ({ key: rowKey(s), cost: s.avg_cost, f1: s.filtered.f1 }))
  );
  const frontierKeys = new Set(frontier.map((p) => p.key));

  const projectX = (cost) => (withCost.length === 1
    ? 50
    : ((cost - minCost) / costRange) * 80 + 10);

  const DOT_COLORS = [
    'var(--accent)',
    'var(--success)',
    '#3b82f6',
    '#a855f7',
    '#ec4899',
    '#14b8a6',
    '#eab308',
  ];

  const chartH = 240;
  const chartW = '100%';
  const padL = 48;
  const padB = 36;
  const padR = 16;
  const padT = 16;

  return (
    <div className="card">
      <h3 className="card-title mb-2">Cost Efficiency</h3>
      <p className="text-muted text-xs mb-2">
        Lower cost + higher F1 = top-left is best.{' '}
        <span style={{ color: 'var(--accent)' }}>★</span> = Pareto-optimal (no other point has both lower cost and higher F1).
      </p>
      <div
        style={{
          position: 'relative',
          height: chartH + padT + padB,
          width: chartW,
        }}
      >
        {/* Y axis label */}
        <span
          className="text-muted text-xs"
          style={{
            position: 'absolute',
            left: 0,
            top: padT + chartH / 2,
            transform: 'rotate(-90deg) translateX(50%)',
            transformOrigin: '0 0',
          }}
        >
          F1 Score
        </span>
        {/* X axis label */}
        <span
          className="text-muted text-xs"
          style={{
            position: 'absolute',
            bottom: 0,
            left: '50%',
            transform: 'translateX(-50%)',
          }}
        >
          Avg Cost ($)
        </span>

        {/* Grid lines */}
        <svg
          style={{
            position: 'absolute',
            left: padL,
            top: padT,
            width: `calc(100% - ${padL + padR}px)`,
            height: chartH,
          }}
          viewBox={`0 0 100 100`}
          preserveAspectRatio="none"
        >
          {[0, 25, 50, 75, 100].map((v) => (
            <line
              key={`h-${v}`}
              x1="0" y1={100 - v} x2="100" y2={100 - v}
              stroke="var(--border)" strokeWidth="0.5" vectorEffect="non-scaling-stroke"
            />
          ))}
          {[0, 25, 50, 75, 100].map((v) => (
            <line
              key={`v-${v}`}
              x1={v} y1="0" x2={v} y2="100"
              stroke="var(--border)" strokeWidth="0.5" vectorEffect="non-scaling-stroke"
            />
          ))}
          {/* Pareto frontier line */}
          {frontier.length > 1 && (
            <polyline
              fill="none"
              stroke="var(--accent)"
              strokeWidth="1.2"
              strokeDasharray="3,3"
              vectorEffect="non-scaling-stroke"
              points={frontier.map((p) => `${projectX(p.cost)},${100 - p.f1 * 100}`).join(' ')}
            />
          )}
        </svg>

        {/* Y axis ticks */}
        {[0, 0.25, 0.5, 0.75, 1.0].map((v) => (
          <span
            key={v}
            className="text-muted font-mono"
            style={{
              position: 'absolute',
              left: padL - 4,
              top: padT + chartH * (1 - v) - 6,
              fontSize: '0.625rem',
              textAlign: 'right',
              transform: 'translateX(-100%)',
            }}
          >
            {fmt(v)}
          </span>
        ))}

        {/* Dots */}
        {withCost.map((s, i) => {
          const xPct = projectX(s.avg_cost);
          const yPct = s.filtered.f1 * 100;
          const color = DOT_COLORS[i % DOT_COLORS.length];
          const isOptimal = frontierKeys.has(rowKey(s));
          const filteredValue = s.filtered.f1 / (s.avg_cost / 1000);

          return (
            <div
              key={rowKey(s)}
              style={{
                position: 'absolute',
                left: `calc(${padL}px + (100% - ${padL + padR}px) * ${xPct / 100})`,
                bottom: padB + (chartH * yPct) / 100,
                transform: 'translate(-50%, 50%)',
              }}
            >
              <div
                style={{
                  width: isOptimal ? 14 : 12,
                  height: isOptimal ? 14 : 12,
                  borderRadius: '50%',
                  background: color,
                  border: isOptimal ? '2px solid var(--accent)' : '2px solid var(--bg-panel)',
                  boxShadow: `0 0 0 1px ${color}`,
                }}
                title={`${rowLabel(s)}: F1=${fmt(s.filtered.f1)}, Cost=${fmtCost(s.avg_cost)}, F1/$1k=${fmtValue(filteredValue)}${isOptimal ? ' (Pareto-optimal)' : ''}`}
              />
              <span
                className="text-xs"
                style={{
                  position: 'absolute',
                  left: 16,
                  top: '50%',
                  transform: 'translateY(-50%)',
                  whiteSpace: 'nowrap',
                  color,
                }}
              >
                {isOptimal && <span style={{ color: 'var(--accent)', marginRight: 2 }}>★</span>}{rowLabel(s)}
              </span>
            </div>
          );
        })}
      </div>
    </div>
  );
}

/* ---------- Summary Table ---------- */

function SummaryTable({ scanners, isFiltered, grouped, hasCostData }) {
  return (
    <div className="card">
      <h3 className="card-title mb-2">
        Summary{isFiltered ? <span className="text-muted text-sm"> (filtered)</span> : ''}
      </h3>
      {hasCostData && (
        <p className="text-muted text-xs mb-2">
          <strong>F1 / $1k</strong> = F1 score per $1,000 of average scan cost. Higher = better value for money
          (e.g. F1 = 0.90 at $0.50 → 1,800).
        </p>
      )}
      <div className="compare-scroll">
        <table>
          <thead>
            <tr>
              <th className="sticky-col">Scanner</th>
              {grouped && <th>Mode</th>}
              <th className="text-center">Apps</th>
              <th className="text-center">Scans</th>
              <th className="text-center">TP</th>
              <th className="text-center">FP</th>
              <th className="text-center">FN</th>
              <th className="text-center">Precision</th>
              <th className="text-center">Recall</th>
              <th className="text-center">F1</th>
              {hasCostData && <th className="text-center" title="F1 score per $1,000 of avg scan cost. Higher = better value.">F1 / $1k</th>}
            </tr>
          </thead>
          <tbody>
            {scanners.map((s) => {
              const m = s.filtered;
              // Value column tracks the filtered F1 so it stays consistent
              // when the user toggles severity buttons. Derives from avg_cost
              // (backend) and the per-row filtered F1 (client).
              const filteredValue = (s.avg_cost && s.avg_cost > 0)
                ? m.f1 / (s.avg_cost / 1000)
                : null;
              return (
                <tr key={rowKey(s)}>
                  <td className="sticky-col" style={{ fontWeight: 600 }}>
                    <Link to={'/scanners/' + encodeURIComponent(s.name)}>{s.name}</Link>
                  </td>
                  {grouped && <td className="text-muted text-sm">{s.mode || '—'}</td>}
                  <td className="text-center font-mono">{s.app_count}</td>
                  <td className="text-center font-mono">{s.scan_count}</td>
                  <td className="text-center font-mono text-success">{m.tp}</td>
                  <td className="text-center font-mono text-error">{m.fp}</td>
                  <td className="text-center font-mono text-error">{m.fn}</td>
                  <td className={`text-center font-mono ${pctColor(m.precision)}`}>{fmt(m.precision)}</td>
                  <td className={`text-center font-mono ${pctColor(m.recall)}`}>{fmt(m.recall)}</td>
                  <td className={`text-center font-mono ${pctColor(m.f1)}`}>{fmt(m.f1)}</td>
                  {hasCostData && (
                    <td className="text-center font-mono" title={filteredValue != null ? `F1 ${m.f1.toFixed(3)} per $1k of avg scan cost ($${s.avg_cost?.toFixed(4)})` : 'No cost data'}>
                      {fmtValue(filteredValue)}
                    </td>
                  )}
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
}
