import { useState, useEffect } from 'react';
import { api } from '../api/client';
import { Badge } from '../components/Badge';

export default function AdminUsers() {
  const [users, setUsers] = useState([]);
  const [loading, setLoading] = useState(true);

  const load = () => api.get('/admin/users').then(d => { setUsers(d.users || []); setLoading(false); });
  useEffect(load, []);

  const updateField = async (userId, field, value) => {
    await api.put(`/admin/users/${userId}`, { [field]: value });
    load();
  };

  const deleteUser = async (userId, name) => {
    if (!confirm(`Delete user ${name}?`)) return;
    await api.del(`/admin/users/${userId}`);
    load();
  };

  if (loading) return <p className="text-muted">Loading...</p>;

  return (
    <>
      <h1 className="page-title mb-2">User Management</h1>
      <div className="card">
        <div className="table-wrap">
          <table>
            <thead><tr><th>Name</th><th>Email</th><th>Role</th><th>Created</th><th>Last Login</th><th style={{ width: 120 }}></th></tr></thead>
            <tbody>
              {users.map(u => (
                <tr key={u.id}>
                  <td>{u.name}</td>
                  <td className="text-secondary">{u.email}</td>
                  <td><Badge severity={u.role === 'admin' ? 'critical' : 'info'}>{u.role}</Badge></td>
                  <td className="text-muted text-sm">{u.created_at?.slice(0, 10)}</td>
                  <td className="text-muted text-sm">{u.last_login ? u.last_login.slice(0, 16).replace('T', ' ') : 'Never'}</td>
                  <td>
                    {u.role !== 'admin' && (
                      <div className="flex gap-1">
                        <button className="btn btn-outline btn-sm" onClick={() => { if (confirm(`Make ${u.name} an admin?`)) updateField(u.id, 'role', 'admin'); }}>Make Admin</button>
                        <button className="btn-icon btn-icon-danger" onClick={() => deleteUser(u.id, u.name)} title="Delete">
                          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M3 6h18"/><path d="M19 6v14c0 1-1 2-2 2H7c-1 0-2-1-2-2V6"/><path d="M8 6V4c0-1 1-2 2-2h4c1 0 2 1 2 2v2"/></svg>
                        </button>
                      </div>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </>
  );
}
