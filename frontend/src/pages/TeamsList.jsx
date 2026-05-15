import { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import { api } from '../api/client';
import { Badge } from '../components/Badge';

export default function TeamsList() {
  const [teams, setTeams] = useState([]);
  const [loading, setLoading] = useState(true);

  const load = () => api.get('/teams').then(d => { setTeams(d.teams || []); setLoading(false); });

  useEffect(() => { load(); }, []);

  const rename = (team) => {
    const newName = prompt('Rename team:', team.name);
    if (newName && newName.trim() && newName.trim() !== team.name) {
      api.put(`/teams/${team.id}`, { name: newName.trim() }).then(load);
    }
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
            <table>
              <thead><tr><th>Name</th><th>Members</th><th>My Role</th></tr></thead>
              <tbody>
                {teams.map(t => (
                  <tr key={t.id}>
                    <td>
                      <Link to={`/teams/${t.id}`}>{t.name}</Link>
                      {t.my_role === 'admin' && (
                        <span
                          className="editable-field"
                          style={{ marginLeft: 8 }}
                          title="Rename team"
                          onClick={() => rename(t)}
                        >
                          <svg className="edit-icon" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="var(--text-muted)" strokeWidth="2"><path d="M17 3a2.85 2.85 0 1 1 4 4L7.5 20.5 2 22l1.5-5.5Z"/><path d="m15 5 4 4"/></svg>
                        </span>
                      )}
                    </td>
                    <td>{t.member_count}</td>
                    <td>{t.my_role && <Badge severity={t.my_role === 'admin' ? 'critical' : t.my_role === 'contributor' ? 'high' : 'info'}>{t.my_role}</Badge>}</td>
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
