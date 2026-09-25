import { Fragment, useState, useEffect, useMemo, useRef, useReducer } from 'react';
import { Link, useSearchParams, useNavigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import { api } from '../api/client';
import { SearchableFilter } from '../components/SearchableFilter';
import { groupScans, scanGroupOptions } from '../utils/scanGroups';
import { initialScanRequest, scanRequestReducer, scanResultForKey } from '../utils/scanRequest';
import { scanStatistics, scanQuality, canonicalScanCounts } from '../utils/scanStatistics';
import { LabelBadge } from '../components/LabelBadge';

// Ordering for which labels survive when the cell can only show a few.
// Lower rank = higher priority (kept). judge-* and thinking-* are dropped first.
function labelRank(name) {
  const n = (name || '').toLowerCase();
  if (n.startsWith('judge') || n.startsWith('thinking')) return 90;
  if (['blackbox', 'greybox', 'graybox', 'whitebox'].includes(n)) return 0; // assessment type
  if (/(claude|gpt|gemini|llama|opus|sonnet|haiku|mistral|qwen|deepseek|grok|o\d)/.test(n)) return 10; // model
  if (n.startsWith('used-')) return 20;
  return 30; // other uncategorised labels
}

function prioritiseLabels(labels) {
  return labels
    .map((l, i) => ({ l, i }))
    .sort((a, b) => labelRank(a.l.name) - labelRank(b.l.name) || a.i - b.i)
    .map(({ l }) => l);
}

const MAX_VISIBLE_LABELS = 3;

export default function ScansList() {
  const { user } = useAuth();
  const navigate = useNavigate();
  const [searchParams, setSearchParams] = useSearchParams();
  const [request, dispatchRequest] = useReducer(scanRequestReducer, initialScanRequest);
  const data = request.data;
  const [selected, setSelected] = useState(new Set());
  const requestId = useRef(0);
  const [metricView, setMetricView] = useState('quality');
  const weighting = searchParams.get('weighting') === 'unweighted' ? 'unweighted' : 'weighted';
  const metricColumns = metricView === 'quality'
    ? weighting === 'weighted'
      ? [['weighted_rate', 'Weighted detection'], ['weighted_found', 'Points found'], ['weighted_total', 'Points available']]
      : [['precision', 'Unweighted precision'], ['recall', 'Unweighted recall'], ['f1', 'Unweighted F1']]
    : [['tp_count', 'TP'], ['fp_count', 'FP'], ['pending_count', 'Pending'], ['fn_count', 'FN']];
  const [expanded, setExpanded] = useState(new Set());
  const groupBy = Object.hasOwn(scanGroupOptions, searchParams.get('group_by')) ? searchParams.get('group_by') : '';
  const [teams, setTeams] = useState([]);
  const [bulkLabel, setBulkLabel] = useState('');
  const [sortKey, setSortKey] = useState('date');
  const [sortDir, setSortDir] = useState('desc');

  const params = {
    app_id: searchParams.get('app_id') || '',
    scanner: searchParams.get('scanner') || '',
    latest: searchParams.get('latest') || '',
    q: searchParams.get('q') || '',
    filter: searchParams.get('filter') || '',
  };

  const labelValues = [...new Set(searchParams.getAll('label').filter(Boolean))];
  const labelMatch = searchParams.get('label_match') === 'any' ? 'any' : 'all';
  const queryParams = new URLSearchParams(Object.entries(params).filter(([, value]) => value));
  labelValues.forEach(label => queryParams.append('label', label));
  if (labelValues.length) queryParams.set('label_match', labelMatch);
  if (groupBy) queryParams.set('include_metrics', 'true');
  const query = queryParams.toString();
  const requestKey = JSON.stringify([query, user?.id ?? null]);
  const { loading, data: resultData, error } = scanResultForKey(request, requestKey);
  const fetchScans = () => {
    const id = ++requestId.current;
    dispatchRequest({ type: 'start', key: requestKey, id });
    return api.get(`/scans?${query}`).then(d => {
      if (id === requestId.current) dispatchRequest({ type: 'success', key: requestKey, id, data: d });
    }).catch(err => {
      if (id === requestId.current) dispatchRequest({ type: 'failure', key: requestKey, id, error: err.message });
    });
  };
  useEffect(() => {
    setSelected(new Set());
    fetchScans();
    return () => { requestId.current += 1; };
  }, [requestKey]);
  useEffect(() => setExpanded(new Set()), [query, groupBy]);

  useEffect(() => {
    if (user) api.get('/teams').then(d => setTeams(d.teams || [])).catch(() => {});
  }, [user]);

  const setFilter = (key, val) => {
    const p = new URLSearchParams(searchParams);
    p.delete(key);
    if (Array.isArray(val)) val.forEach(value => p.append(key, value));
    else if (val) p.set(key, val);
    setSearchParams(p);
  };

  const hasFilters = labelValues.length > 0 || Object.values(params).some(v => v);
  const rawScans = useMemo(() => (resultData?.scans || []).map(canonicalScanCounts), [resultData]);
  const labelsMap = resultData?.scan_labels_map || {};

  const appId = params.app_id;

  const scans = useMemo(() => {
    const getVal = (s) => {
      switch (sortKey) {
        case 'scanner': return `${(s.scanner_name || '').toLowerCase()} ${s.scanner_version || ''}`;
        case 'app': return `${(s.app_name || '').toLowerCase()} ${s.app_version || ''}`;
        case 'tp': return s.tp_count ?? -1;
        case 'fp': return s.fp_count ?? -1;
        case 'pending': return s.pending_count ?? -1;
        case 'fn': return s.fn_count ?? -1;
        case 'date':
        default: return s.scan_date || '';
      }
    };
    const sorted = [...rawScans].sort((a, b) => {
      const av = getVal(a); const bv = getVal(b);
      if (av < bv) return -1;
      if (av > bv) return 1;
      return 0;
    });
    if (sortDir === 'desc') sorted.reverse();
    return sorted;
  }, [rawScans, sortKey, sortDir]);

  const groups = useMemo(() => groupScans(scans, labelsMap, groupBy), [scans, groupBy, labelsMap]);
  const toggleGroup = key => setExpanded(previous => {
    const next = new Set(previous);
    if (next.has(key)) next.delete(key); else next.add(key);
    return next;
  });

  const totals = useMemo(() => scans.reduce(
    (acc, s) => ({
      tp: acc.tp + (s.tp_count ?? 0),
      fp: acc.fp + (s.fp_count ?? 0),
      pending: acc.pending + (s.pending_count ?? 0),
      fn: acc.fn + (s.fn_count ?? 0),
      critical: acc.critical + (s.sev_critical ?? 0),
      high: acc.high + (s.sev_high ?? 0),
      medium: acc.medium + (s.sev_medium ?? 0),
      low: acc.low + (s.sev_low ?? 0),
    }),
    { tp: 0, fp: 0, pending: 0, fn: 0, critical: 0, high: 0, medium: 0, low: 0 },
  ), [scans]);

  const SeverityCells = ({ s }) => (
    <>
      {['critical','high','medium','low'].map(sev => {
        const n = s?.[`sev_${sev}`] ?? s?.[sev] ?? 0;
        return (
          <span key={sev}
            className={`sev-pill sev-pill-${sev}${n === 0 ? ' sev-pill-zero' : ''}`}
            title={`${sev}: ${n}`}>
            <span className="sev-pill-count">{n}</span>
            <span className="sev-pill-letter">{sev[0].toUpperCase()}</span>
          </span>
        );
      })}
    </>
  );

  const toggleSort = (key) => {
    if (sortKey === key) {
      setSortDir(d => d === 'asc' ? 'desc' : 'asc');
    } else {
      setSortKey(key);
      setSortDir(['date','tp','fp','pending','fn'].includes(key) ? 'desc' : 'asc');
    }
  };
  const sortArrow = (key) => sortKey === key ? (sortDir === 'asc' ? ' ▲' : ' ▼') : '';
  const sortableTh = (key, label, extraProps = {}) => (
    <th {...extraProps} onClick={() => toggleSort(key)} style={{ cursor: 'pointer', userSelect: 'none', ...(extraProps.style || {}) }}>
      {label}{sortArrow(key)}
    </th>
  );
  const toggleSelect = (id) => {
    setSelected(prev => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id); else next.add(id);
      return next;
    });
  };
  const compareSelected = () => {
    if (selected.size >= 2 && appId) {
      navigate(`/apps/${appId}/compare?scans=${Array.from(selected).join(',')}`);
    }
  };

  const deleteScan = async (id) => {
    if (!confirm('Delete this scan and all its findings?')) return;
    await api.del(`/scans/${id}`);
    setSelected(previous => { const next = new Set(previous); next.delete(id); return next; });
    await fetchScans();
  };

  const bulkDelete = async () => {
    if (!confirm(`Delete ${selected.size} scan(s) and all their findings?`)) return;
    for (const id of selected) await api.del(`/scans/${id}`);
    setSelected(new Set());
    fetchScans();
  };

  const bulkAddLabel = async () => {
    if (!bulkLabel.trim()) return;
    for (const id of selected) await api.post(`/scans/${id}/labels`, { name: bulkLabel.trim() });
    setBulkLabel('');
    setSelected(new Set());
    fetchScans();
  };

  const renderScanTable = scanRows => (
        <div className="card">
          <div className="table-wrap">
            <table className="cards-on-mobile">
              <thead>
                <tr>
                  {user && <th style={{ width: 36 }}>
                    <input type="checkbox"
                      aria-label="Select all scans" checked={scanRows.length > 0 && scanRows.every(s => selected.has(s.id))}
                      onChange={() => {
                        setSelected(previous => {
                          const next = new Set(previous);
                          const remove = scanRows.every(scan => previous.has(scan.id));
                          scanRows.forEach(scan => remove ? next.delete(scan.id) : next.add(scan.id));
                          return next;
                        });
                      }}
                      style={{ accentColor: 'var(--accent)', width: 16, height: 16, cursor: 'pointer' }} />
                  </th>}
                  {sortableTh('scanner', 'Scanner')}
                  {!appId && sortableTh('app', 'App')}
                  {sortableTh('date', 'Date')}
                  {sortableTh('tp', 'TP')}
                  {sortableTh('fp', 'FP')}
                  {sortableTh('pending', 'Pending')}
                  {sortableTh('fn', 'FN')}
                  <th>Severity</th>
                  <th>Labels</th>
                  {user && <th style={{ width: 40 }}></th>}
                </tr>
              </thead>
              <tbody>
                {scanRows.map(scan => {
                  const labels = prioritiseLabels(labelsMap[scan.id] || []);
                  const hiddenLabels = labels.slice(MAX_VISIBLE_LABELS);
                  return (
                    <tr key={scan.id}>
                      {user && (
                        <td data-label="">
                          <input type="checkbox" aria-label={`Select ${scan.scanner_name} scan ${scan.id}`} checked={selected.has(scan.id)}
                            onChange={() => toggleSelect(scan.id)}
                            style={{ accentColor: 'var(--accent)', width: 16, height: 16, cursor: 'pointer' }} />
                        </td>
                      )}
                      <td data-label="Scanner">
                        <Link to={`/scans/${scan.id}`}>{scan.scanner_name}</Link>
                        {scan.scanner_version && <span className="text-muted text-sm"> v{scan.scanner_version}</span>}
                      </td>
                      {!appId && (
                        <td data-label="App">
                          <Link to={`/apps/${scan.app_id}`}>{scan.app_name}</Link>
                          {scan.app_version && <span className="text-muted text-sm"> v{scan.app_version}</span>}
                        </td>
                      )}
                      <td data-label="Date">{scan.scan_date}</td>
                      <td data-label="TP" className="text-success">{scan.tp_count ?? '-'}</td>
                      <td data-label="FP" className="text-error">{scan.fp_count ?? '-'}</td>
                      <td data-label="Pending" className="text-muted">{scan.pending_count ?? '-'}</td>
                      <td data-label="FN" className="text-warn">{scan.fn_count ?? '-'}</td>
                      <td data-label="Severity"><span className="sev-pill-group"><SeverityCells s={scan} /></span></td>
                      <td data-label="Labels">
                        {labels.length > 0 && (
                          <div className="scan-labels-cell">
                            {labels.slice(0, MAX_VISIBLE_LABELS).map(l => <LabelBadge key={l.id} label={l} />)}
                            {hiddenLabels.length > 0 && (
                              <span className="label-overflow-wrap" tabIndex={0}>
                                <span className="label-badge label-overflow">+{hiddenLabels.length}</span>
                                <span className="label-overflow-pop">
                                  {hiddenLabels.map(l => <LabelBadge key={l.id} label={l} />)}
                                </span>
                              </span>
                            )}
                          </div>
                        )}
                      </td>
                      {user && (
                        <td data-label="">
                          {(user.role === 'admin' || scan.submitted_by == user.id) && (
                            <button className="btn-icon btn-icon-danger" title="Delete" onClick={() => deleteScan(scan.id)}>
                              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M3 6h18"/><path d="M19 6v14c0 1-1 2-2 2H7c-1 0-2-1-2-2V6"/><path d="M8 6V4c0-1 1-2 2-2h4c1 0 2 1 2 2v2"/></svg>
                            </button>
                          )}
                        </td>
                      )}
                    </tr>
                  );
                })}
              </tbody>
              {!groupBy && <tfoot>
                <tr className="scans-totals-row">
                  {user && <td></td>}
                  <td className="text-muted" data-label="">Total</td>
                  {!appId && <td></td>}
                  <td></td>
                  <td className="text-success" data-label="TP">{totals.tp}</td>
                  <td className="text-error" data-label="FP">{totals.fp}</td>
                  <td className="text-muted" data-label="Pending">{totals.pending}</td>
                  <td className="text-warn" data-label="FN">{totals.fn}</td>
                  <td data-label="Severity"><span className="sev-pill-group"><SeverityCells s={{
                    sev_critical: totals.critical,
                    sev_high: totals.high,
                    sev_medium: totals.medium,
                    sev_low: totals.low,
                  }} /></span></td>
                  <td></td>
                  {user && <td></td>}
                </tr>
              </tfoot>}
            </table>
          </div>
        </div>
  );

  return (
    <>
      <div className="page-header">
        <h1 className="page-title">Scans</h1>
      </div>

      {user && (
        <section className="scan-filters mb-2" aria-label="Filter scans">
          <div className="scan-filter-heading"><span>Filter scans</span>
            {hasFilters && <button className="scan-text-button" onClick={() => setSearchParams({ ...(groupBy ? { group_by: groupBy } : {}), ...(weighting === 'unweighted' ? { weighting } : {}) })}>Reset filters</button>}
          </div>
          <div className="scan-filter-primary">
            <SearchableFilter label="App" placeholder="All apps" value={params.app_id}
              options={(data?.apps_list || []).map(a => ({ value: String(a.id), label: `${a.name}${a.version ? ` v${a.version}` : ''}` }))}
              onChange={value => setFilter('app_id', value)} />
            <SearchableFilter label="Scanner" placeholder="All scanners" value={params.scanner}
              options={(data?.scanners || []).map(value => ({ value, label: value }))}
              onChange={value => setFilter('scanner', value)} />
            <label className="scan-filter-field">Search
              <input className="form-input" aria-label="Search scans" placeholder="App, scanner or submitter…" value={params.q} onChange={e => setFilter('q', e.target.value)} />
            </label>
          </div>
          <div className="scan-filter-secondary">
            <div className="scan-label-filter">
              <SearchableFilter multiple label="Labels" allLabel="All labels" placeholder="Search and select labels…" value={labelValues}
                options={(data?.all_labels || []).map(value => ({ value, label: value }))}
                onChange={value => setFilter('label', value)} />
              {labelValues.length > 1 && <div className="scan-label-matching"><span>Include scans matching</span>
                <div className="scan-segmented" role="group" aria-label="Match labels">
                  <button aria-pressed={labelMatch === 'all'} onClick={() => setFilter('label_match', 'all')}>All labels</button>
                  <button aria-pressed={labelMatch === 'any'} onClick={() => setFilter('label_match', 'any')}>Any label</button>
                </div>
              </div>}
            </div>
            <label className="scan-filter-field">History
              <select aria-label="Scan history" className="form-select" value={params.latest} onChange={e => setFilter('latest', e.target.value)}>
                <option value="">All scans</option><option value="1">Latest per scanner</option>
              </select>
            </label>
            {teams.length > 0 && <SearchableFilter label="Team" placeholder="All teams" value={params.filter}
              options={teams.map(t => ({ value: `team:${t.id}`, label: t.name }))}
              onChange={value => setFilter('filter', value)} />}
          </div>
        </section>
      )}

      <div className="scan-view-bar mb-2">
        <div className="scan-segmented" role="group" aria-label="Results view">
          <button aria-pressed={!groupBy} onClick={() => setFilter('group_by', '')}>Individual scans</button>
          <button aria-pressed={!!groupBy} onClick={() => { if (!groupBy) setFilter('group_by', 'scanner'); }}>Grouped summary</button>
        </div>
        {groupBy && <label className="scan-group-control">Group by
          <select aria-label="Group by" className="form-select" value={groupBy} onChange={e => setFilter('group_by', e.target.value)}>
            {Object.entries(scanGroupOptions).map(([value, label]) => <option key={value} value={value}>{label}</option>)}
          </select>
        </label>}
        <span className="scan-result-count text-muted text-sm" role="status">{loading ? 'Loading scans…' : error ? 'Scans unavailable' : `${scans.length} ${scans.length === 1 ? 'scan' : 'scans'}${groupBy ? ` in ${groups.length} groups` : ''}`}</span>
      </div>

      {error && <p role="alert" className="text-error">Could not load scans: {error} <button className="btn btn-outline btn-sm" onClick={fetchScans}>Retry</button></p>}

      {!loading && !error && user && selected.size > 0 && (
        <div className="flex gap-1 items-center mb-2">
          <span className="text-muted text-sm">{selected.size} selected</span>
          {appId && selected.size >= 2 && (
            <button className="btn btn-primary btn-sm" onClick={compareSelected}>Compare {selected.size} Scans</button>
          )}
          <button className="btn btn-danger btn-sm" onClick={bulkDelete}>Delete Selected</button>
          <input className="form-input" placeholder="Add label..." value={bulkLabel} onChange={e => setBulkLabel(e.target.value)} style={{ width: 150 }} />
          <button className="btn btn-primary btn-sm" onClick={bulkAddLabel}>Add Label</button>
          <button className="btn btn-outline btn-sm" onClick={() => setSelected(new Set())}>Clear</button>
        </div>
      )}

      {loading ? <p role="status" className="text-muted">{groupBy ? 'Loading scored scans…' : 'Loading scans…'}</p> : error ? null : scans.length > 0 ? (
        groupBy ? <div className="card scan-summary-card">
          <div className="scan-summary-heading">
            <div><h2>Scan performance</h2><p>Mean <span className="text-muted">± standard deviation</span><span className="scan-legend-divider">·</span>Min–max beneath</p></div>
            <div className="scan-summary-actions"><div className="scan-segmented" role="group" aria-label="Summary metrics">
              <button aria-pressed={metricView === 'quality'} onClick={() => setMetricView('quality')}>Quality</button>
              <button aria-pressed={metricView === 'counts'} onClick={() => setMetricView('counts')}>Counts</button>
            </div><button className="scan-text-button" onClick={() => setExpanded(expanded.size === groups.length ? new Set() : new Set(groups.map(g => g.key)))}>
              {expanded.size === groups.length ? 'Hide all scans' : 'Show all scans'}
            </button></div>
          </div>
          {metricView === 'quality' && <div className="scan-weighting-control">
            <span>Scoring</span><div className="scan-segmented" role="group" aria-label="Scoring weights">
              <button aria-pressed={weighting === 'weighted'} onClick={() => setFilter('weighting', '')}>Weighted</button>
              <button aria-pressed={weighting === 'unweighted'} onClick={() => setFilter('weighting', 'unweighted')}>Unweighted</button>
            </div>
          </div>}
          <p className="scan-summary-note">{groupBy === 'configuration'
            ? 'Groups share an app, scanner version and exact label set. Unrecorded settings may still differ.'
            : groupBy === 'scanner' ? 'Scanner groups can mix versions and settings. Group by app + scanner version + labels for narrower comparisons.'
            : groupBy === 'scanner_version' ? 'Scanner versions may still span different apps and label sets.' : 'Groups may include different scanners and settings.'} Small samples are descriptive.</p>
          {groupBy === 'label' && <p className="scan-summary-note">A scan can belong to multiple label groups. The overall scan count counts each scan once.</p>}
          {metricView === 'quality' && <p className="scan-summary-note">{weighting === 'weighted' ? 'Impact-weighted detection, including chain credit. Current benchmark revision; each scan has equal weight in the summary.' : 'Count-based scores; each scan has equal weight.'} {scans.some(scan => (scan.pending_count ?? 0) > 0) && 'Pending findings excluded; scores are provisional.'}</p>}
          <div className="table-wrap">
          <table className="scan-aggregation">
            <thead><tr><th>{scanGroupOptions[groupBy]}</th><th>Scans</th>
              {metricColumns.map(([field, label]) => <th key={field}>{label}</th>)}</tr></thead>
            <tbody>{groups.map(group => <Fragment key={group.key}>
              <tr>
                <td data-label="Group"><button className="scan-group-toggle" aria-expanded={expanded.has(group.key)} onClick={() => toggleGroup(group.key)}>
                  <span aria-hidden="true">{expanded.has(group.key) ? '▾' : '▸'}</span><span>{group.name}{group.detail && <span className="scan-group-description">{group.detail}</span>}</span>
                </button></td>
                <td data-label="Scans">{group.scans.length}</td>
                {metricColumns.map(([field, label]) => {
                  const stats = scanStatistics(metricView === 'quality' ? group.scans.map(scanQuality) : group.scans, field);
                  const percent = ['weighted_rate', 'precision', 'recall', 'f1'].includes(field);
                  const format = value => value === null ? '—' : percent ? `${(value * 100).toFixed(1)}%` : value.toFixed(1);
                  return <td key={field} data-label={label}>
                    <div className="scan-statistics">
                      <div className="scan-stat-primary" aria-label={`Mean ${stats.mean === null ? 'unavailable' : format(stats.mean)}, standard deviation ${stats.std === null ? 'unavailable' : format(stats.std)}`}>
                        <strong>{stats.mean === null ? '—' : format(stats.mean)}</strong>
                        <span className="scan-stat-spread"> ± {stats.std === null ? '—' : format(stats.std)}</span>
                      </div>
                      <div className="text-muted text-xs">{stats.n ? `${format(stats.min)}–${format(stats.max)}` : 'No data'}
                        <span className="scan-stat-missing"> · n={stats.n}/{group.scans.length}</span>
                      </div>
                    </div>
                  </td>;

                })}
              </tr>
              {expanded.has(group.key) && <tr className="scan-group-detail"><td colSpan={metricColumns.length + 2}>{renderScanTable(group.scans)}</td></tr>}
            </Fragment>)}</tbody>
          </table>
        </div>
          <details className="scan-stat-help"><summary>How these statistics are calculated</summary>
            <p>Weighted detection uses the same current-revision scorer as scan detail: credited vulnerability and chain impact points / available impact points. Weighted precision and weighted F1 are not defined here. Unweighted metrics use vulnerability counts and clustered false positives from that scorer. Each scan has equal weight; scores are calculated per scan before averaging (macro average). Precision = TP/(TP+FP), recall = TP/(TP+FN), F1 = 2TP/(2TP+FP+FN). Pending findings are excluded, so quality scores remain provisional while findings are pending. Undefined ratios are excluded, not counted as zero. Percentage standard deviations describe percentage-point spread. We show the arithmetic mean, sample standard deviation (n−1), and minimum–maximum. Missing values are excluded; n shows the measured/total scans for each metric. Small samples describe observed variation, not evidence of a performance difference. Standard deviation is unavailable for a single scan. Counts are per scan, not distinct findings across scans. Comparisons are most meaningful within the same app version and benchmark corpus; mixed groups are descriptive summaries, not controlled model evaluations.</p>
          </details>
        </div> : renderScanTable(scans)
      ) : (
        <div className="empty-state"><h3>No scans found</h3><p>{hasFilters ? 'No scans match the current filters.' : 'No scan results have been submitted yet.'}</p></div>
      )}
    </>
  );
}
