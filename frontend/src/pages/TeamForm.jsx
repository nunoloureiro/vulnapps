import { useState } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { api } from '../api/client';

export default function TeamForm() {
  const [name, setName] = useState('');
  const [error, setError] = useState('');
  const navigate = useNavigate();

  const handleSubmit = async (e) => {
    e.preventDefault();
    try {
      const data = await api.post('/teams', { name });
      navigate(`/teams/${data.team.id}`);
    } catch (err) { setError(err.message); }
  };

  return (
    <div style={{ maxWidth: 500, margin: '2rem auto' }}>
      <h1 className="page-title mb-2">New Team</h1>
      {error && <div className="alert alert-error mb-2">{error}</div>}
      <div className="card">
        <form onSubmit={handleSubmit}>
          <div className="form-group">
            <label className="form-label">Team Name</label>
            <input className="form-input" value={name} onChange={e => setName(e.target.value)} required />
          </div>
          <div className="flex gap-1 mt-2">
            <button type="submit" className="btn btn-primary">Create Team</button>
            <Link to="/teams" className="btn btn-outline">Cancel</Link>
          </div>
        </form>
      </div>
    </div>
  );
}
