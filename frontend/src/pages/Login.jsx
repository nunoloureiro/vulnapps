import { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';

export default function Login() {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const { login } = useAuth();
  const navigate = useNavigate();

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    try {
      await login(email, password);
      navigate('/');
    } catch (err) {
      setError(err.message || 'Invalid credentials');
    }
  };

  return (
    <div style={{ maxWidth: 400, margin: '3rem auto' }}>
      <h1 className="page-title mb-2">Login</h1>
      {error && <div className="alert alert-error mb-2">{error}</div>}
      <div className="card">
        <form onSubmit={handleSubmit}>
          <div className="form-group">
            <label className="form-label">Email</label>
            <input type="email" className="form-input" value={email} onChange={e => setEmail(e.target.value)} required />
          </div>
          <div className="form-group">
            <label className="form-label">Password</label>
            <input type="password" className="form-input" value={password} onChange={e => setPassword(e.target.value)} required />
          </div>
          <button type="submit" className="btn btn-primary mt-1" style={{ width: '100%' }}>Login</button>
        </form>
        <p className="text-muted text-sm mt-2">Don't have an account? <Link to="/register">Register</Link></p>
      </div>
    </div>
  );
}
