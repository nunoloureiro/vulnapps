import { useState, useEffect } from 'react';
import { useAuth } from '../context/AuthContext';
import { api } from '../api/client';

export default function Account() {
  const { user } = useAuth();
  const [account, setAccount] = useState(null);
  const [apiKeys, setApiKeys] = useState([]);
  const [name, setName] = useState('');
  const [curPw, setCurPw] = useState('');
  const [newPw, setNewPw] = useState('');
  const [keyName, setKeyName] = useState('');
  const [keyScope, setKeyScope] = useState('read');
  const [newKey, setNewKey] = useState(null);
  const [msg, setMsg] = useState('');
  const [error, setError] = useState('');

  useEffect(() => {
    api.get('/account').then(data => {
      setAccount(data.account);
      setName(data.account.name);
      setApiKeys(data.api_keys || []);
    });
  }, []);

  const saveName = async () => {
    try {
      const data = await api.put('/account/name', { name });
      if (data.token) api.setToken(data.token);
      setMsg('Name updated');
    } catch (e) { setError(e.message); }
  };

  const changePw = async (e) => {
    e.preventDefault();
    try {
      await api.put('/account/password', { current_password: curPw, new_password: newPw });
      setCurPw(''); setNewPw('');
      setMsg('Password changed');
    } catch (e) { setError(e.message); }
  };

  const createKey = async () => {
    try {
      const data = await api.post('/account/api-keys', { name: keyName || 'default', scope: keyScope });
      setNewKey(data.key);
      setApiKeys(prev => [...prev, { id: Date.now(), key_prefix: data.prefix, name: data.name, scope: data.scope, created_at: new Date().toISOString() }]);
      setKeyName('');
    } catch (e) { setError(e.message); }
  };

  const revokeKey = async (id) => {
    if (!confirm('Revoke this API key?')) return;
    await api.del(`/account/api-keys/${id}`);
    setApiKeys(prev => prev.filter(k => k.id !== id));
  };

  if (!account) return <p className="text-muted">Loading...</p>;

  return (
    <>
      <h1 className="page-title mb-2">Account Settings</h1>
      {msg && <div className="alert alert-success mb-2" onClick={() => setMsg('')}>{msg}</div>}
      {error && <div className="alert alert-error mb-2" onClick={() => setError('')}>{error}</div>}

      <div style={{ maxWidth: 600 }}>
        <div className="card mb-2">
          <h3 className="card-title mb-2">Name</h3>
          <div className="flex gap-1 items-center">
            <input className="form-input" value={name} onChange={e => setName(e.target.value)} style={{ flex: 1 }} />
            <button className="btn btn-primary btn-sm" onClick={saveName}>Save</button>
          </div>
        </div>

        <div className="card mb-2">
          <h3 className="card-title mb-2">Password</h3>
          <form onSubmit={changePw}>
            <div className="form-group">
              <input type="password" className="form-input" placeholder="Current password" value={curPw} onChange={e => setCurPw(e.target.value)} required />
            </div>
            <div className="form-group">
              <input type="password" className="form-input" placeholder="New password" value={newPw} onChange={e => setNewPw(e.target.value)} required minLength={4} />
            </div>
            <button type="submit" className="btn btn-primary btn-sm">Change Password</button>
          </form>
        </div>

        <div className="card">
          <h3 className="card-title mb-2">API Keys</h3>
          <div className="flex gap-1 items-center mb-2">
            <input className="form-input" placeholder="Key name" value={keyName} onChange={e => setKeyName(e.target.value)} style={{ width: 150 }} />
            <select className="form-select" value={keyScope} onChange={e => setKeyScope(e.target.value)} style={{ width: 'auto' }}>
              <option value="read">read</option>
              <option value="vuln-mapper">vuln-mapper</option>
              <option value="full">full</option>
            </select>
            <button className="btn btn-primary btn-sm" onClick={createKey}>Generate</button>
          </div>

          {newKey && (
            <div className="alert alert-success mb-2" style={{ wordBreak: 'break-all' }}>
              <strong>Copy this key now — it won't be shown again:</strong><br />
              <code className="font-mono">{newKey}</code>
              <button className="btn btn-outline btn-sm" style={{ marginLeft: 8 }} onClick={() => { navigator.clipboard.writeText(newKey); }}>Copy</button>
            </div>
          )}

          {apiKeys.length > 0 ? (
            <div className="table-wrap">
              <table>
                <thead><tr><th>Prefix</th><th>Name</th><th>Scope</th><th>Created</th><th></th></tr></thead>
                <tbody>
                  {apiKeys.map(k => (
                    <tr key={k.id}>
                      <td className="font-mono text-sm">{k.key_prefix}...</td>
                      <td>{k.name}</td>
                      <td><span className={`badge badge-${k.scope === 'full' ? 'critical' : k.scope === 'vuln-mapper' ? 'high' : 'info'}`}>{k.scope}</span></td>
                      <td className="text-muted text-sm">{k.created_at?.slice(0, 10)}</td>
                      <td><button className="btn btn-outline btn-sm" onClick={() => revokeKey(k.id)}>Revoke</button></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : <p className="text-muted text-sm">No API keys yet.</p>}
        </div>
      </div>
    </>
  );
}
