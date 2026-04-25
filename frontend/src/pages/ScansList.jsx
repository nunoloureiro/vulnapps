import { useState, useEffect } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import { api } from '../api/client';
import { LabelBadge } from '../components/LabelBadge';

export default function ScansList() {
  const { user } = useAuth();
  const [searchParams, setSearchParams] = useSearchParams();
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);

  const params = {
    app_id: searchParams.get('app_id') || '',
    scanner: searchParams.get('scanner') || '',
    latest: searchParams.get('latest') || '',
    q: searchParams.get('q') || '',
    authenticated: searchParams.get('authenticated') || '',
    label: searchParams.get('label') || '',
    filter: searchParams.get('filter') || '',
  };

  useEffect(() => {
    const qs = new URLSearchParams();
    Object.entries(params).forEach(([k, v]) => { if (v) qs.set(k, v); });
    api.get(`/scans?${qs}`).then(d => { setData(d); setLoading(false); });
  }, [searchParams.toString()]);

  const setFilter = (key, val) => {
    const p = new URLSearchParams(searchParams);
    if (val) p.set(key, val); else p.delete(key);
    setSearchParams(p);
  };

  const hasFilters = Object.values(params).some(v => v);
  const scans = data?.scans || [];
  const labelsMap = data?.scan_labels_map || {};

  const deleteScan = async (id) => {
    if (!confirm('Delete this scan and all its findings?')) return;
    await api.del(`/scans/${id}`);
    setData(d => ({ ...d, scans: d.scans.filter(s => s.id !== id) }));
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
          <select className="form-select" value={params.authenticated} onChange={e => setFilter('authenticated', e.target.value)}>
            <option value="">All auth</option>
            <option value="1">Authenticated</option>
            <option value="0">Unauthenticated</option>
          </select>
          <select className="form-select" value={params.label} onChange={e => setFilter('label', e.target.value)}>
            <option value="">All labels</option>
            {(data?.all_labels || []).map(l => <option key={l} value={l}>{l}</option>)}
          </select>
          <select className="form-select" value={params.app_id} onChange={e => setFilter('app_id', e.target.value)}>
            <option value="">All apps</option>
            {(data?.apps_list || []).map(a => <option key={a.id} value={a.id}>{a.name}{a.version ? ` v${a.version}` : ''}</option>)}
          </select>
          <input className="form-input" placeholder="Search..." value={params.q} onChange={e => setFilter('q', e.target.value)} style={{ width: 140 }} />
          {hasFilters && <Link to="/scans" className="btn btn-outline btn-sm">Clear</Link>}
        </div>
      )}

      {scans.length > 0 ? (
        <div className="card">
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Scanner</th>
                  <th>App</th>
                  <th>Date</th>
                  <th>Auth</th>
                  <th>TP</th>
                  <th>FP</th>
                  <th>Labels</th>
                  {user && <th style={{ width: 40 }}></th>}
                </tr>
              </thead>
              <tbody>
                {scans.map(scan => {
                  const labels = labelsMap[scan.id] || [];
                  return (
                    <tr key={scan.id}>
                      <td><Link to={`/scans/${scan.id}`}>{scan.scanner_name}</Link></td>
                      <td>
                        <Link to={`/apps/${scan.app_id}`}>{scan.app_name}</Link>
                        {scan.app_version && <span className="text-muted text-sm"> v{scan.app_version}</span>}
                      </td>
                      <td>{scan.scan_date}</td>
                      <td>{scan.authenticated ? 'Yes' : 'No'}</td>
                      <td className="text-success">{scan.tp_count ?? '-'}</td>
                      <td className="text-error">{scan.fp_count ?? '-'}</td>
                      <td>
                        {labels.length > 0 && (
                          <div className="scan-labels-cell">
                            {labels.slice(0, 3).map(l => <LabelBadge key={l.id} label={l} />)}
                            {labels.length > 3 && <span className="label-badge label-overflow" title={labels.slice(3).map(l => l.name).join(', ')}>+{labels.length - 3}</span>}
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
            </table>
          </div>
        </div>
      ) : (
        <div className="empty-state"><h3>No scans found</h3><p>{hasFilters ? 'No scans match the current filters.' : 'No scan results have been submitted yet.'}</p></div>
      )}
    </>
  );
}
