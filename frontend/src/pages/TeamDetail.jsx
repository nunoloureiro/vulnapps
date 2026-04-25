import { useState, useEffect } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { api } from '../api/client';
import { Badge } from '../components/Badge';

export default function TeamDetail() {
  const { id } = useParams();
  const navigate = useNavigate();
  const [data, setData] = useState(null);
  const [email, setEmail] = useState('');
  const [role, setRole] = useState('view');
  const [error, setError] = useState('');

  const load = () => api.get(`/teams/${id}`).then(setData);
  useEffect(() => { load(); }, [id]);

  const addMember = async (e) => {
    e.preventDefault();
    try {
      await api.post(`/teams/${id}/members`, { email, role });
      setEmail(''); load();
    } catch (err) { setError(err.message); }
  };

  const removeMember = async (uid) => {
    if (!confirm('Remove this member?')) return;
    await api.del(`/teams/${id}/members/${uid}`);
    load();
  };

  const changeRole = async (uid, newRole) => {
    await api.put(`/teams/${id}/members/${uid}`, { role: newRole });
    load();
  };

  const deleteTeam = async () => {
    if (!confirm('Delete this team? This cannot be undone.')) return;
    await api.del(`/teams/${id}`);
    navigate('/teams');
  };

  if (!data) return <p className="text-muted">Loading...</p>;
  const { team, members, is_team_admin } = data;

  return (
    <>
      <div className="page-header">
        <h1 className="page-title">{team.name}</h1>
        {is_team_admin && <button className="btn btn-danger btn-sm" onClick={deleteTeam}>Delete Team</button>}
      </div>

      {error && <div className="alert alert-error mb-2">{error}</div>}

      {is_team_admin && (
        <div className="card mb-2">
          <h3 className="card-title mb-2">Add Member</h3>
          <form onSubmit={addMember} className="flex gap-1 items-center">
            <input className="form-input" placeholder="Email address" value={email} onChange={e => setEmail(e.target.value)} required style={{ width: 250 }} />
            <select className="form-select" value={role} onChange={e => setRole(e.target.value)} style={{ width: 'auto' }}>
              <option value="view">Viewer</option>
              <option value="contributor">Contributor</option>
              <option value="admin">Admin</option>
            </select>
            <button type="submit" className="btn btn-primary btn-sm">Add</button>
          </form>
        </div>
      )}

      <div className="card">
        <h3 className="card-title mb-2">Members</h3>
        <div className="table-wrap">
          <table>
            <thead><tr><th>Name</th><th>Email</th><th>Role</th>{is_team_admin && <th></th>}</tr></thead>
            <tbody>
              {members.map(m => (
                <tr key={m.id}>
                  <td>{m.name}</td>
                  <td className="text-secondary">{m.email}</td>
                  <td>
                    {is_team_admin ? (
                      <select className="form-select" value={m.team_role} onChange={e => changeRole(m.id, e.target.value)} style={{ width: 'auto', padding: '2px 6px', fontSize: '0.85rem' }}>
                        <option value="view">view</option>
                        <option value="contributor">contributor</option>
                        <option value="admin">admin</option>
                      </select>
                    ) : (
                      <Badge severity={m.team_role === 'admin' ? 'critical' : m.team_role === 'contributor' ? 'high' : 'info'}>{m.team_role}</Badge>
                    )}
                  </td>
                  {is_team_admin && (
                    <td><button className="btn btn-outline btn-sm" onClick={() => removeMember(m.id)}>Remove</button></td>
                  )}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </>
  );
}
