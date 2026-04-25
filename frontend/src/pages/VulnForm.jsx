import { useState, useEffect } from 'react';
import { useParams, useNavigate, useSearchParams } from 'react-router-dom';
import { api } from '../api/client';

const HTTP_METHODS = ['', 'GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'];
const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'];

export default function VulnForm() {
  const { appId, id } = useParams();
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();

  const isEdit = Boolean(id);

  const [form, setForm] = useState({
    vuln_id: '',
    title: '',
    severity: '',
    vuln_type: '',
    http_method: '',
    url: '',
    parameter: '',
    filename: '',
    line_number: '',
    code_location: '',
    description: '',
    poc: '',
    remediation: '',
  });
  const [appName, setAppName] = useState('');
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [submitting, setSubmitting] = useState(false);

  useEffect(() => {
    async function load() {
      setLoading(true);
      setError(null);
      try {
        if (isEdit) {
          const data = await api.get('/api/apps/' + appId + '/vulns/' + id);
          const v = data.vuln;
          setAppName(data.app?.name || '');
          setForm({
            vuln_id: v.vuln_id || '',
            title: v.title || '',
            severity: v.severity || '',
            vuln_type: v.vuln_type || '',
            http_method: v.http_method || '',
            url: v.url || '',
            parameter: v.parameter || '',
            filename: v.filename || '',
            line_number: v.line_number ? String(v.line_number) : '',
            code_location: v.code_location || '',
            description: v.description || '',
            poc: v.poc || '',
            remediation: v.remediation || '',
          });
        } else {
          // Fetch app name for the header
          try {
            const appData = await api.get('/api/apps/' + appId);
            setAppName(appData.app?.name || '');
          } catch {
            // Non-critical
          }

          // Check for prefill query params (from "new from FP" flow)
          const prefill = {};
          for (const key of ['vuln_type', 'http_method', 'url', 'parameter', 'filename']) {
            const val = searchParams.get(key);
            if (val) prefill[key] = val;
          }
          if (Object.keys(prefill).length > 0) {
            setForm(prev => ({ ...prev, ...prefill }));
          }
        }
      } catch (err) {
        setError(err.message || 'Failed to load');
      } finally {
        setLoading(false);
      }
    }
    load();
  }, [appId, id, isEdit, searchParams]);

  function handleChange(e) {
    const { name, value } = e.target;
    setForm(prev => ({ ...prev, [name]: value }));
  }

  async function handleSubmit(e) {
    e.preventDefault();
    setSubmitting(true);
    setError(null);

    const body = {
      vuln_id: form.vuln_id,
      title: form.title,
      severity: form.severity,
      vuln_type: form.vuln_type,
      http_method: form.http_method || null,
      url: form.url || null,
      parameter: form.parameter || null,
      filename: form.filename || null,
      line_number: form.line_number ? parseInt(form.line_number, 10) : null,
      code_location: form.code_location || null,
      description: form.description || null,
      poc: form.poc || null,
      remediation: form.remediation || null,
    };

    try {
      let result;
      if (isEdit) {
        result = await api.put('/api/apps/' + appId + '/vulns/' + id, body);
        navigate('/apps/' + appId + '/vulns/' + id);
      } else {
        result = await api.post('/api/apps/' + appId + '/vulns', body);
        const newId = result.vulnerability?.id;
        navigate(newId ? '/apps/' + appId + '/vulns/' + newId : '/apps/' + appId);
      }
    } catch (err) {
      setError(err.message || 'Failed to save vulnerability');
    } finally {
      setSubmitting(false);
    }
  }

  if (loading) {
    return <div className="container"><div className="empty-state"><p>Loading...</p></div></div>;
  }

  return (
    <div className="container">
      <div className="page-header">
        <h1 className="page-title">{isEdit ? 'Edit Vulnerability' : 'Add Vulnerability'}</h1>
        <Link to={'/apps/' + appId} className="btn btn-outline">Cancel</Link>
      </div>

      {error && <div className="alert alert-error">{error}</div>}

      <div className="card">
        <form onSubmit={handleSubmit}>
          <div className="form-row">
            <div className="form-group">
              <label className="form-label" htmlFor="vuln_id">Vuln ID</label>
              <input
                type="text"
                id="vuln_id"
                name="vuln_id"
                className="form-input"
                value={form.vuln_id}
                onChange={handleChange}
                required
              />
            </div>
            <div className="form-group">
              <label className="form-label" htmlFor="title">Title</label>
              <input
                type="text"
                id="title"
                name="title"
                className="form-input"
                value={form.title}
                onChange={handleChange}
                required
              />
            </div>
          </div>

          <div className="form-row">
            <div className="form-group">
              <label className="form-label" htmlFor="severity">Severity</label>
              <select
                id="severity"
                name="severity"
                className="form-select"
                value={form.severity}
                onChange={handleChange}
                required
              >
                <option value="">Select severity</option>
                {SEVERITIES.map(s => (
                  <option key={s} value={s}>{s.charAt(0).toUpperCase() + s.slice(1)}</option>
                ))}
              </select>
            </div>
            <div className="form-group">
              <label className="form-label" htmlFor="vuln_type">Vulnerability Type</label>
              <input
                type="text"
                id="vuln_type"
                name="vuln_type"
                className="form-input"
                value={form.vuln_type}
                onChange={handleChange}
                required
              />
            </div>
          </div>

          <div className="form-row">
            <div className="form-group">
              <label className="form-label" htmlFor="http_method">HTTP Method</label>
              <select
                id="http_method"
                name="http_method"
                className="form-select"
                value={form.http_method}
                onChange={handleChange}
              >
                {HTTP_METHODS.map(m => (
                  <option key={m} value={m}>{m || 'Select method'}</option>
                ))}
              </select>
            </div>
            <div className="form-group">
              <label className="form-label" htmlFor="url">URL</label>
              <input
                type="text"
                id="url"
                name="url"
                className="form-input"
                value={form.url}
                onChange={handleChange}
              />
            </div>
          </div>

          <div className="form-row">
            <div className="form-group">
              <label className="form-label" htmlFor="parameter">
                Parameter <span className="text-muted text-xs">(DAST)</span>
              </label>
              <input
                type="text"
                id="parameter"
                name="parameter"
                className="form-input"
                value={form.parameter}
                onChange={handleChange}
              />
            </div>
            <div className="form-group">
              <label className="form-label" htmlFor="filename">
                Filename <span className="text-muted text-xs">(SAST)</span>
              </label>
              <input
                type="text"
                id="filename"
                name="filename"
                className="form-input"
                value={form.filename}
                onChange={handleChange}
                placeholder="src/path/to/file.py"
              />
            </div>
          </div>

          <div className="form-group">
            <label className="form-label" htmlFor="line_number">Line Number</label>
            <input
              type="number"
              id="line_number"
              name="line_number"
              className="form-input"
              value={form.line_number}
              onChange={handleChange}
              style={{ maxWidth: '150px' }}
            />
          </div>

          <div className="form-group">
            <label className="form-label" htmlFor="description">Description</label>
            <textarea
              id="description"
              name="description"
              className="form-textarea"
              value={form.description}
              onChange={handleChange}
            />
          </div>

          <div className="form-group">
            <label className="form-label" htmlFor="code_location">Code Location</label>
            <input
              type="text"
              id="code_location"
              name="code_location"
              className="form-input"
              value={form.code_location}
              onChange={handleChange}
            />
          </div>

          <div className="form-group">
            <label className="form-label" htmlFor="poc">Proof of Concept</label>
            <textarea
              id="poc"
              name="poc"
              className="form-textarea"
              value={form.poc}
              onChange={handleChange}
            />
          </div>

          <div className="form-group">
            <label className="form-label" htmlFor="remediation">Remediation</label>
            <textarea
              id="remediation"
              name="remediation"
              className="form-textarea"
              value={form.remediation}
              onChange={handleChange}
            />
          </div>

          <button type="submit" className="btn btn-primary" disabled={submitting}>
            {submitting ? 'Saving...' : (isEdit ? 'Update Vulnerability' : 'Add Vulnerability')}
          </button>
        </form>
      </div>
    </div>
  );
}
