import { useState, useEffect } from 'react';
import { useParams, useNavigate, Link } from 'react-router-dom';
import { api } from '../api/client';

export default function ScanSubmit() {
  const { id: appId } = useParams();
  const navigate = useNavigate();
  const [app, setApp] = useState(null);
  const [form, setForm] = useState({ scanner_name: '', scan_date: '', authenticated: false, is_public: false, notes: '', labels: '', cost: '' });
  const [file, setFile] = useState(null);
  const [findings, setFindings] = useState([{ vuln_type: '', http_method: '', url: '', parameter: '', filename: '' }]);
  const [error, setError] = useState('');

  useEffect(() => {
    api.get(`/apps/${appId}`).then(d => setApp(d.app));
  }, [appId]);

  const set = (k, v) => setForm(f => ({ ...f, [k]: v }));

  const addFinding = () => setFindings(f => [...f, { vuln_type: '', http_method: '', url: '', parameter: '', filename: '' }]);
  const removeFinding = (i) => setFindings(f => f.filter((_, j) => j !== i));
  const setFinding = (i, k, v) => setFindings(f => f.map((r, j) => j === i ? { ...r, [k]: v } : r));

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    try {
      let findingsData = [];
      if (file) {
        const text = await file.text();
        if (file.name.endsWith('.json')) {
          const parsed = JSON.parse(text);
          findingsData = (parsed.findings || []).filter(f => f.vuln_type);
        } else if (file.name.endsWith('.csv')) {
          const lines = text.trim().split('\n');
          const headers = lines[0].split(',').map(h => h.trim());
          for (let i = 1; i < lines.length; i++) {
            const vals = lines[i].split(',').map(v => v.trim());
            const row = {};
            headers.forEach((h, j) => { row[h] = vals[j] || ''; });
            if (row.vuln_type) findingsData.push(row);
          }
        }
      } else {
        findingsData = findings.filter(f => f.vuln_type);
      }

      const body = {
        scanner_name: form.scanner_name,
        scan_date: form.scan_date,
        authenticated: form.authenticated,
        is_public: form.is_public,
        notes: form.notes,
        findings: findingsData,
        labels: form.labels ? form.labels.split(',').map(l => l.trim()).filter(Boolean) : [],
      };
      if (form.cost) body.cost = parseFloat(form.cost);

      const result = await api.post(`/apps/${appId}/scans`, body);
      navigate(`/scans/${result.scan_id}`);
    } catch (err) {
      setError(err.message);
    }
  };

  if (!app) return <p className="text-muted">Loading...</p>;

  return (
    <>
      <div className="page-header">
        <h1 className="page-title">Submit Scan for {app.name}</h1>
        <Link to={`/apps/${appId}`} className="btn btn-outline">Cancel</Link>
      </div>
      {error && <div className="alert alert-error mb-2">{error}</div>}
      <div className="card">
        <form onSubmit={handleSubmit}>
          <div className="form-row">
            <div className="form-group">
              <label className="form-label">Scanner Name</label>
              <input className="form-input" value={form.scanner_name} onChange={e => set('scanner_name', e.target.value)} required />
            </div>
            <div className="form-group">
              <label className="form-label">Scan Date</label>
              <input type="date" className="form-input" value={form.scan_date} onChange={e => set('scan_date', e.target.value)} required />
            </div>
          </div>
          <div className="form-row">
            <div className="form-group">
              <div className="form-check mt-2">
                <input type="checkbox" checked={form.authenticated} onChange={e => set('authenticated', e.target.checked)} />
                <label className="form-label" style={{ marginBottom: 0 }}>Authenticated Scan</label>
              </div>
            </div>
            {app.visibility === 'public' && (
              <div className="form-group">
                <div className="form-check mt-2">
                  <input type="checkbox" checked={form.is_public} onChange={e => set('is_public', e.target.checked)} />
                  <label className="form-label" style={{ marginBottom: 0 }}>Public</label>
                </div>
              </div>
            )}
          </div>
          <div className="form-group">
            <label className="form-label">Notes</label>
            <textarea className="form-textarea" value={form.notes} onChange={e => set('notes', e.target.value)} />
          </div>
          <div className="form-group">
            <label className="form-label">Labels <span className="text-muted text-xs">(optional, comma-separated)</span></label>
            <input className="form-input" value={form.labels} onChange={e => set('labels', e.target.value)} placeholder="e.g. baseline, quarterly" />
          </div>
          <div className="form-group">
            <label className="form-label">Cost <span className="text-muted text-xs">(optional, private)</span></label>
            <input type="number" step="0.0001" min="0" className="form-input" value={form.cost} onChange={e => set('cost', e.target.value)} placeholder="e.g. 0.0432" />
          </div>

          <h3 className="card-title mt-3 mb-2">Upload Findings File</h3>
          <div className="form-group">
            <input type="file" accept=".json,.csv" className="form-input" onChange={e => setFile(e.target.files[0] || null)} />
            <p className="text-sm text-muted mt-1">JSON or CSV file with findings. If uploaded, manual findings below are ignored.</p>
          </div>

          <h3 className="card-title mt-3 mb-2">Or Add Findings Manually</h3>
          {findings.map((f, i) => (
            <div key={i} className="card mb-2" style={{ padding: '1rem' }}>
              <div className="form-row">
                <div className="form-group">
                  <label className="form-label">Vulnerability Type</label>
                  <input className="form-input" value={f.vuln_type} onChange={e => setFinding(i, 'vuln_type', e.target.value)} placeholder="e.g. XSS, SQLi" />
                </div>
                <div className="form-group">
                  <label className="form-label">HTTP Method</label>
                  <select className="form-select" value={f.http_method} onChange={e => setFinding(i, 'http_method', e.target.value)}>
                    <option value="">Select</option>
                    {['GET', 'POST', 'PUT', 'DELETE', 'PATCH'].map(m => <option key={m}>{m}</option>)}
                  </select>
                </div>
              </div>
              <div className="form-row">
                <div className="form-group">
                  <label className="form-label">URL <span className="text-muted text-xs">(DAST)</span></label>
                  <input className="form-input" value={f.url} onChange={e => setFinding(i, 'url', e.target.value)} />
                </div>
                <div className="form-group">
                  <label className="form-label">Parameter</label>
                  <input className="form-input" value={f.parameter} onChange={e => setFinding(i, 'parameter', e.target.value)} />
                </div>
              </div>
              <div className="form-group">
                <label className="form-label">Filename <span className="text-muted text-xs">(SAST)</span></label>
                <input className="form-input" value={f.filename} onChange={e => setFinding(i, 'filename', e.target.value)} />
              </div>
              {findings.length > 1 && <button type="button" className="btn btn-danger btn-sm" onClick={() => removeFinding(i)}>Remove</button>}
            </div>
          ))}
          <button type="button" className="btn btn-outline mb-2" onClick={addFinding}>Add Finding</button>
          <div className="mt-3">
            <button type="submit" className="btn btn-primary">Submit Scan</button>
          </div>
        </form>
      </div>
    </>
  );
}
