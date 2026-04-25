import { useState, useEffect } from 'react';
import { api } from '../api/client';
import { LabelBadge } from '../components/LabelBadge';

const COLORS = ['#ef4444', '#f97316', '#eab308', '#22c55e', '#06b6d4', '#3b82f6', '#8b5cf6', '#ec4899', '#a1a1aa', '#f59e0b'];

export default function AdminLabels() {
  const [labels, setLabels] = useState([]);
  const [name, setName] = useState('');
  const [color, setColor] = useState(COLORS[0]);
  const [loading, setLoading] = useState(true);

  const load = () => api.get('/admin/labels').then(d => { setLabels(d.labels || []); setLoading(false); });
  useEffect(load, []);

  const create = async (e) => {
    e.preventDefault();
    if (!name.trim()) return;
    await api.post('/admin/labels', { name: name.trim(), color });
    setName('');
    load();
  };

  const updateLabel = async (id, updates) => {
    await api.put(`/admin/labels/${id}`, updates);
    load();
  };

  const deleteLabel = async (label) => {
    if (!confirm(`Delete label "${label.name}"? It will be removed from ${label.scan_count} scan(s).`)) return;
    await api.del(`/admin/labels/${label.id}`);
    load();
  };

  if (loading) return <p className="text-muted">Loading...</p>;

  return (
    <>
      <h1 className="page-title mb-2">Label Management</h1>

      <div className="card mb-2">
        <h3 className="card-title mb-2">Create Label</h3>
        <form onSubmit={create}>
          <div className="flex gap-1 items-center mb-1">
            <input className="form-input" placeholder="Label name" value={name} onChange={e => setName(e.target.value)} required style={{ width: 200 }} />
            <button type="submit" className="btn btn-primary btn-sm">Create</button>
          </div>
          <div className="flex gap-1 items-center">
            <span className="text-muted text-sm" style={{ marginRight: '0.25rem' }}>Color:</span>
            <div className="color-picker-row" style={{ marginTop: 0 }}>
              {COLORS.map(c => (
                <span key={c} className={`color-swatch${color === c ? ' selected' : ''}`} style={{ background: c }} onClick={() => setColor(c)} />
              ))}
            </div>
          </div>
        </form>
      </div>

      {labels.length > 0 ? (
        <div className="card">
          <div className="table-wrap">
            <table>
              <thead><tr><th>Color</th><th>Name</th><th>Preview</th><th>Scans</th><th style={{ width: 80 }}></th></tr></thead>
              <tbody>
                {labels.map(l => (
                  <tr key={l.id}>
                    <td>
                      <div className="color-picker-row">
                        {COLORS.map(c => (
                          <span key={c} className={`color-swatch${l.color === c ? ' selected' : ''}`} style={{ background: c }}
                            onClick={() => updateLabel(l.id, { color: c })} />
                        ))}
                      </div>
                    </td>
                    <td>{l.name}</td>
                    <td><LabelBadge label={l} /></td>
                    <td className="text-muted">{l.scan_count}</td>
                    <td>
                      <button className="btn-icon btn-icon-danger" onClick={() => deleteLabel(l)} title="Delete label">
                        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M3 6h18"/><path d="M19 6v14c0 1-1 2-2 2H7c-1 0-2-1-2-2V6"/><path d="M8 6V4c0-1 1-2 2-2h4c1 0 2 1 2 2v2"/></svg>
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      ) : <div className="empty-state"><h3>No labels</h3><p>Create your first label above.</p></div>}
    </>
  );
}
