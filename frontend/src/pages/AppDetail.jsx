import { useState, useEffect, useCallback, useRef } from 'react';
import { useParams, Link } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import { api } from '../api/client';

const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'];

export default function AppDetail() {
  const { id } = useParams();
  const { user } = useAuth();

  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [importOpen, setImportOpen] = useState(false);
  const [importMsg, setImportMsg] = useState(null);
  const [editingCell, setEditingCell] = useState(null);
  const fileInputRef = useRef(null);

  const fetchApp = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const result = await api.get('/apps/' + id);
      setData(result);
    } catch (err) {
      setError(err.message || 'Failed to load app');
    } finally {
      setLoading(false);
    }
  }, [id]);

  useEffect(() => { fetchApp(); }, [fetchApp]);

  async function handleDeleteVuln(vulnId) {
    if (!window.confirm('Delete this vulnerability?')) return;
    try {
      await api.del('/apps/' + id + '/vulns/' + vulnId);
      fetchApp();
    } catch (err) {
      setError(err.message || 'Failed to delete vulnerability');
    }
  }

  async function handleImport(e) {
    e.preventDefault();
    const file = fileInputRef.current?.files?.[0];
    if (!file) return;
    setImportMsg(null);
    try {
      const formData = new FormData();
      formData.append('file', file);
      const resp = await fetch('/api/apps/' + id + '/vulns/import', {
        method: 'POST',
        body: formData,
      });
      const result = await resp.json();
      if (!resp.ok) throw new Error(result.detail || 'Import failed');
      setImportMsg('Imported ' + result.imported + ' vulnerabilities');
      fileInputRef.current.value = '';
      fetchApp();
    } catch (err) {
      setImportMsg('Error: ' + (err.message || 'Import failed'));
    }
  }

  function startEdit(vulnId, field, currentValue) {
    setEditingCell({ vulnId, field, value: currentValue });
  }

  function cancelEdit() {
    setEditingCell(null);
  }

  async function saveEdit(vuln) {
    if (!editingCell) return;
    const { field, value } = editingCell;
    if (value === vuln[field]) {
      cancelEdit();
      return;
    }
    try {
      const body = {};
      // Send all required fields for full PUT update
      const fields = [
        'vuln_id', 'title', 'severity', 'vuln_type', 'http_method',
        'url', 'parameter', 'filename', 'line_number', 'description',
        'code_location', 'poc', 'remediation',
      ];
      for (const f of fields) {
        body[f] = vuln[f] || '';
      }
      body[field] = value;
      await api.put('/apps/' + id + '/vulns/' + vuln.id, body);
      cancelEdit();
      fetchApp();
    } catch (err) {
      setError(err.message || 'Failed to update');
      cancelEdit();
    }
  }

  if (loading) {
    return <div className="container"><div className="empty-state"><p>Loading...</p></div></div>;
  }

  if (error && !data) {
    return <div className="container"><div className="alert alert-error">{error}</div></div>;
  }

  if (!data) return null;

  const { app, vulns = [], tech_stack = [], scan_count = 0, severity_counts = {}, can_edit, can_submit_scan } = data;

  function renderLocation(v) {
    if (v.url) return v.url;
    if (v.filename) return v.filename + (v.line_number ? ':' + v.line_number : '');
    return '';
  }

  function renderEditInput(vuln, field) {
    if (field === 'severity') {
      return (
        <select
          className="inline-input"
          value={editingCell.value}
          onChange={e => setEditingCell({ ...editingCell, value: e.target.value })}
          onBlur={() => saveEdit(vuln)}
          onKeyDown={e => { if (e.key === 'Escape') cancelEdit(); }}
          autoFocus
        >
          {SEVERITIES.map(s => (
            <option key={s} value={s}>{s}</option>
          ))}
        </select>
      );
    }
    return (
      <input
        className="inline-input"
        type="text"
        value={editingCell.value}
        onChange={e => setEditingCell({ ...editingCell, value: e.target.value })}
        onBlur={() => saveEdit(vuln)}
        onKeyDown={e => {
          if (e.key === 'Enter') { e.preventDefault(); saveEdit(vuln); }
          if (e.key === 'Escape') cancelEdit();
        }}
        autoFocus
      />
    );
  }

  function renderCell(vuln, field) {
    const isEditing = editingCell && editingCell.vulnId === vuln.id && editingCell.field === field;

    if (field === 'vuln_id') {
      return (
        <td
          className={can_edit ? 'cell-editable font-mono text-sm' : 'font-mono text-sm'}
          onClick={can_edit && !isEditing ? () => startEdit(vuln.id, 'vuln_id', vuln.vuln_id) : undefined}
        >
          {isEditing ? renderEditInput(vuln, field) : vuln.vuln_id}
        </td>
      );
    }
    if (field === 'title') {
      return (
        <td
          className={can_edit ? 'cell-editable' : ''}
          onClick={can_edit && !isEditing ? (e) => { if (e.target.tagName !== 'A') startEdit(vuln.id, 'title', vuln.title); } : undefined}
        >
          {isEditing ? renderEditInput(vuln, field) : <Link to={'/apps/' + id + '/vulns/' + vuln.id}>{vuln.title}</Link>}
        </td>
      );
    }
    if (field === 'severity') {
      return (
        <td
          className={can_edit ? 'cell-editable' : ''}
          onClick={can_edit && !isEditing ? () => startEdit(vuln.id, 'severity', vuln.severity) : undefined}
        >
          {isEditing ? renderEditInput(vuln, field) : <span className={'badge badge-' + vuln.severity}>{vuln.severity}</span>}
        </td>
      );
    }
    if (field === 'vuln_type') {
      return (
        <td
          className={can_edit ? 'cell-editable' : ''}
          onClick={can_edit && !isEditing ? () => startEdit(vuln.id, 'vuln_type', vuln.vuln_type || '') : undefined}
        >
          {isEditing ? renderEditInput(vuln, field) : (vuln.vuln_type || '')}
        </td>
      );
    }
    return null;
  }

  return (
    <div className="container">
      {error && <div className="alert alert-error">{error}</div>}

      <div className="page-header">
        <h1 className="page-title">
          {app.name}
          {app.version && <span className="text-muted text-sm"> v{app.version}</span>}
        </h1>
        <div className="flex items-center gap-1">
          {can_edit && (
            <>
              <Link to={'/apps/' + id + '/edit'} className="btn btn-outline">Edit App</Link>
              <Link to={'/apps/' + id + '/vulns/new'} className="btn btn-primary">Add Vulnerability</Link>
              <button
                type="button"
                className="btn btn-outline"
                onClick={() => setImportOpen(!importOpen)}
              >
                Import Vulns
              </button>
            </>
          )}
          {can_submit_scan && (
            <Link to={'/apps/' + id + '/scans/new'} className="btn btn-outline">Submit Scan</Link>
          )}
          {user && (
            <Link to={'/apps/new?clone_from=' + id} className="btn btn-outline">Clone</Link>
          )}
          {scan_count >= 2 && (
            <Link to={'/apps/' + id + '/compare'} className="btn btn-outline">Compare Scans</Link>
          )}
        </div>
      </div>

      {can_edit && importOpen && (
        <div className="card mb-2">
          <h3 className="card-title mb-2">Import Vulnerabilities</h3>
          <p className="text-sm text-secondary mb-2">Upload a JSON or CSV file with vulnerabilities.</p>
          {importMsg && (
            <div className={'alert ' + (importMsg.startsWith('Error') ? 'alert-error' : 'alert-success')}>{importMsg}</div>
          )}
          <form onSubmit={handleImport}>
            <div className="flex items-center gap-1">
              <input type="file" ref={fileInputRef} accept=".json,.csv" className="form-input" style={{ maxWidth: '400px' }} required />
              <button type="submit" className="btn btn-primary">Upload</button>
            </div>
          </form>
        </div>
      )}

      <div className="card mb-2">
        <div className="detail-grid">
          <div className="detail-label">Description</div>
          <div className="detail-value">{app.description || 'No description provided.'}</div>

          <div className="detail-label">URL</div>
          <div className="detail-value">
            {app.url ? <a href={app.url}>{app.url}</a> : <span className="text-muted">N/A</span>}
          </div>

          <div className="detail-label">Tech Stack</div>
          <div className="detail-value">
            {tech_stack.length > 0
              ? tech_stack.map(t => <span className="badge badge-info" key={t} style={{ marginRight: '0.25rem' }}>{t}</span>)
              : <span className="text-muted">N/A</span>
            }
          </div>

          <div className="detail-label">Created by</div>
          <div className="detail-value">{app.creator_name || app.created_by}</div>

          <div className="detail-label">Visibility</div>
          <div className="detail-value">
            <span className={'badge badge-' + (app.visibility === 'public' ? 'info' : app.visibility === 'team' ? 'medium' : 'low')}>
              {app.visibility}
            </span>
          </div>

          <div className="detail-label">Scans</div>
          <div className="detail-value">
            <Link to={'/scans?app_id=' + id}>{scan_count} scan{scan_count === 1 ? '' : 's'}</Link>
          </div>
        </div>
      </div>

      <div className="page-header">
        <h2 className="page-title">Vulnerabilities <span className="text-muted text-sm">({vulns.length})</span></h2>
      </div>

      {vulns.length > 0 && (
        <div className="metrics-grid mb-2">
          {SEVERITIES.map(sev => {
            const count = severity_counts[sev] || 0;
            if (count === 0) return null;
            return (
              <div className="metric-card" key={sev}>
                <div className="metric-value">
                  <span className={'badge badge-' + sev} style={{ fontSize: '1.25rem', padding: '0.25rem 0.75rem' }}>{count}</span>
                </div>
                <div className="metric-label">{sev}</div>
              </div>
            );
          })}
        </div>
      )}

      {vulns.length > 0 ? (
        <div className="card">
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>ID</th>
                  <th>Title</th>
                  <th>Severity</th>
                  <th>Type</th>
                  <th>Location</th>
                  {can_edit && <th style={{ width: '70px' }}></th>}
                </tr>
              </thead>
              <tbody>
                {vulns.map(vuln => (
                  <tr className="vuln-row" key={vuln.id}>
                    {renderCell(vuln, 'vuln_id')}
                    {renderCell(vuln, 'title')}
                    {renderCell(vuln, 'severity')}
                    {renderCell(vuln, 'vuln_type')}
                    <td className="font-mono text-sm">{renderLocation(vuln)}</td>
                    {can_edit && (
                      <td>
                        <div className="flex gap-1">
                          <Link to={'/apps/' + id + '/vulns/' + vuln.id + '/edit'} className="btn-icon" title="Edit all fields">
                            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M17 3a2.85 2.85 0 114 4L7.5 20.5 2 22l1.5-5.5Z"/></svg>
                          </Link>
                          <button
                            type="button"
                            className="btn-icon btn-icon-danger"
                            title="Delete"
                            onClick={() => handleDeleteVuln(vuln.id)}
                          >
                            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M3 6h18"/><path d="M19 6v14c0 1-1 2-2 2H7c-1 0-2-1-2-2V6"/><path d="M8 6V4c0-1 1-2 2-2h4c1 0 2 1 2 2v2"/></svg>
                          </button>
                        </div>
                      </td>
                    )}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      ) : (
        <div className="empty-state">
          <p>No vulnerabilities documented yet.</p>
        </div>
      )}
    </div>
  );
}
