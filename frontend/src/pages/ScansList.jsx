import { useState, useEffect, useMemo } from 'react';
import { Link, useSearchParams, useNavigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import { api } from '../api/client';
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
  const [data, setData] = useState(null);
  const [selected, setSelected] = useState(new Set());
  const [loading, setLoading] = useState(true);
  const [teams, setTeams] = useState([]);
  const [bulkLabel, setBulkLabel] = useState('');
  const [sortKey, setSortKey] = useState('date');
  const [sortDir, setSortDir] = useState('desc');

  const params = {
    app_id: searchParams.get('app_id') || '',
    scanner: searchParams.get('scanner') || '',
    latest: searchParams.get('latest') || '',
    q: searchParams.get('q') || '',
    label: searchParams.get('label') || '',
    filter: searchParams.get('filter') || '',
  };

  const fetchScans = () => {
    const qs = new URLSearchParams();
    Object.entries(params).forEach(([k, v]) => { if (v) qs.set(k, v); });
    return api.get(`/scans?${qs}`).then(d => { setData(d); setLoading(false); });
  };

  useEffect(() => { fetchScans(); }, [searchParams.toString()]);

  useEffect(() => {
    if (user) api.get('/teams').then(d => setTeams(d.teams || [])).catch(() => {});
  }, [user]);

  const setFilter = (key, val) => {
    const p = new URLSearchParams(searchParams);
    if (val) p.set(key, val); else p.delete(key);
    setSearchParams(p);
  };

  const hasFilters = Object.values(params).some(v => v);
  const rawScans = data?.scans || [];
  const labelsMap = data?.scan_labels_map || {};

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
    setData(d => ({ ...d, scans: d.scans.filter(s => s.id !== id) }));
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

  if (loading) return <p className="text-muted">Loading...</p>;

  return (
    <>
      <div className="page-header">
        <h1 className="page-title">Scans</h1>
      </div>

      {user && (
        <div className="filter-bar mb-2">
          <select className="form-select" value={params.latest} onChange={e => setFilter('latest', e.target.value)}>
            <option value="">All scans</option>
            <option value="1">Latest per scanner</option>
          </select>
          <select className="form-select" value={params.scanner} onChange={e => setFilter('scanner', e.target.value)}>
            <option value="">All scanners</option>
            {(data?.scanners || []).map(s => <option key={s} value={s}>{s}</option>)}
          </select>
          <select className="form-select" value={params.label} onChange={e => setFilter('label', e.target.value)}>
            <option value="">All labels</option>
            {(data?.all_labels || []).map(l => <option key={l} value={l}>{l}</option>)}
          </select>
          {teams.length > 0 && (
            <select className="form-select" value={params.filter} onChange={e => setFilter('filter', e.target.value)}>
              <option value="">All teams</option>
              {teams.map(t => <option key={t.id} value={`team:${t.id}`}>{t.name}</option>)}
            </select>
          )}
          <select className="form-select" value={params.app_id} onChange={e => setFilter('app_id', e.target.value)}>
            <option value="">All apps</option>
            {(data?.apps_list || []).map(a => <option key={a.id} value={a.id}>{a.name}{a.version ? ` v${a.version}` : ''}</option>)}
          </select>
          <input className="form-input" placeholder="Search..." value={params.q} onChange={e => setFilter('q', e.target.value)} style={{ width: 140 }} />
          {hasFilters && <Link to="/scans" className="btn btn-outline btn-sm">Clear</Link>}
        </div>
      )}

      {user && selected.size > 0 && (
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

      {scans.length > 0 ? (
        <div className="card">
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  {user && <th style={{ width: 36 }}>
                    <input type="checkbox"
                      checked={selected.size > 0 && selected.size === scans.length}
                      onChange={() => {
                        if (selected.size === scans.length) setSelected(new Set());
                        else setSelected(new Set(scans.map(s => s.id)));
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
                {scans.map(scan => {
                  const labels = prioritiseLabels(labelsMap[scan.id] || []);
                  const hiddenLabels = labels.slice(MAX_VISIBLE_LABELS);
                  return (
                    <tr key={scan.id}>
                      {user && (
                        <td>
                          <input type="checkbox" checked={selected.has(scan.id)}
                            onChange={() => toggleSelect(scan.id)}
                            style={{ accentColor: 'var(--accent)', width: 16, height: 16, cursor: 'pointer' }} />
                        </td>
                      )}
                      <td>
                        <Link to={`/scans/${scan.id}`}>{scan.scanner_name}</Link>
                        {scan.scanner_version && <span className="text-muted text-sm"> v{scan.scanner_version}</span>}
                      </td>
                      {!appId && (
                        <td>
                          <Link to={`/apps/${scan.app_id}`}>{scan.app_name}</Link>
                          {scan.app_version && <span className="text-muted text-sm"> v{scan.app_version}</span>}
                        </td>
                      )}
                      <td>{scan.scan_date}</td>
                      <td className="text-success">{scan.tp_count ?? '-'}</td>
                      <td className="text-error">{scan.fp_count ?? '-'}</td>
                      <td className="text-muted">{scan.pending_count ?? '-'}</td>
                      <td className="text-warn">{scan.fn_count ?? '-'}</td>
                      <td><span className="sev-pill-group"><SeverityCells s={scan} /></span></td>
                      <td>
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
                        <td>
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
              <tfoot>
                <tr className="scans-totals-row">
                  {user && <td></td>}
                  <td className="text-muted">Total</td>
                  {!appId && <td></td>}
                  <td></td>
                  <td className="text-success">{totals.tp}</td>
                  <td className="text-error">{totals.fp}</td>
                  <td className="text-muted">{totals.pending}</td>
                  <td className="text-warn">{totals.fn}</td>
                  <td><span className="sev-pill-group"><SeverityCells s={{
                    sev_critical: totals.critical,
                    sev_high: totals.high,
                    sev_medium: totals.medium,
                    sev_low: totals.low,
                  }} /></span></td>
                  <td></td>
                  {user && <td></td>}
                </tr>
              </tfoot>
            </table>
          </div>
        </div>
      ) : (
        <div className="empty-state"><h3>No scans found</h3><p>{hasFilters ? 'No scans match the current filters.' : 'No scan results have been submitted yet.'}</p></div>
      )}
    </>
  );
}
