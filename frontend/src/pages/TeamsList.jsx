import { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import { api } from '../api/client';
import { Badge } from '../components/Badge';

export default function TeamsList() {
  const [teams, setTeams] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    api.get('/teams').then(d => { setTeams(d.teams || []); setLoading(false); });
  }, []);

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
                    <td><Link to={`/teams/${t.id}`}>{t.name}</Link></td>
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
