import { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import { api } from '../api/client';
import { Badge } from '../components/Badge';

export default function TeamsList() {
  const [teams, setTeams] = useState([]);
  const [loading, setLoading] = useState(true);
  const [editingId, setEditingId] = useState(null);
  const [draft, setDraft] = useState('');

  const load = () => api.get('/teams').then(d => { setTeams(d.teams || []); setLoading(false); });

  useEffect(() => { load(); }, []);

  const startEdit = (team) => { setDraft(team.name); setEditingId(team.id); };
  const cancelEdit = () => { setEditingId(null); setDraft(''); };
  const saveEdit = async (team) => {
    const newName = draft.trim();
    if (!newName || newName === team.name) { cancelEdit(); return; }
    await api.put(`/teams/${team.id}`, { name: newName });
    cancelEdit();
    load();
  };

  if (loading) return <p className="text-muted">Loading...</p>;

  return (
    <>
      <div className="page-header">
        <h1 className="page-title">Teams</h1>
        <Link to="/teams/new" className="btn btn-primary">New Team</Link>
      </div>
      {teams.length > 0 ? (
        <div className="card">
          <div className="table-wrap">
            <table className="cards-on-mobile">
              <thead><tr><th>Name</th><th>Members</th><th>My Role</th></tr></thead>
              <tbody>
                {teams.map(t => (
                  <tr key={t.id}>
                    <td data-label="Name">
                      {editingId === t.id ? (
                        <div style={{ display: 'flex', gap: 4, alignItems: 'center' }}>
                          <input
                            className="form-input"
                            value={draft}
                            onChange={e => setDraft(e.target.value)}
                            autoFocus
                            onKeyDown={e => { if (e.key === 'Enter') saveEdit(t); if (e.key === 'Escape') cancelEdit(); }}
                            style={{ padding: '2px 6px', fontSize: '0.9rem', width: 'auto', minWidth: 180 }}
                          />
                          <button className="btn btn-primary btn-sm" onClick={() => saveEdit(t)} style={{ height: 24, padding: '0 0.4rem', fontSize: '0.7rem' }}>Save</button>
                          <button className="btn btn-outline btn-sm" onClick={cancelEdit} style={{ height: 24, padding: '0 0.4rem', fontSize: '0.7rem' }}>Cancel</button>
                        </div>
                      ) : (
                        <>
                          <Link to={`/teams/${t.id}`}>{t.name}</Link>
                          {t.my_role === 'admin' && (
                            <span
                              className="editable-field"
                              style={{ marginLeft: 8 }}
                              title="Rename team"
                              onClick={() => startEdit(t)}
                            >
                              <svg className="edit-icon" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="var(--text-muted)" strokeWidth="2"><path d="M17 3a2.85 2.85 0 1 1 4 4L7.5 20.5 2 22l1.5-5.5Z"/><path d="m15 5 4 4"/></svg>
                            </span>
                          )}
                        </>
                      )}
                    </td>
                    <td data-label="Members">{t.member_count}</td>
                    <td data-label="My Role">{t.my_role && <Badge severity={t.my_role === 'admin' ? 'critical' : t.my_role === 'contributor' ? 'high' : 'info'}>{t.my_role}</Badge>}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      ) : <div className="empty-state"><h3>No teams</h3><p>Create your first team to collaborate with others.</p></div>}
    </>
  );
}
