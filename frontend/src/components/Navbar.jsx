import { useState, useEffect } from 'react';
import { Link, useNavigate, useLocation } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';

export default function Navbar() {
  const { user, logout } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();
  const [menuOpen, setMenuOpen] = useState(false);
  const [adminOpen, setAdminOpen] = useState(false);

  // Close the mobile menu whenever the route changes (covers link taps too).
  useEffect(() => {
    setMenuOpen(false);
    setAdminOpen(false);
  }, [location.pathname]);

  const handleLogout = () => {
    logout();
    navigate('/');
  };

  return (
    <nav className="navbar">
      <div className="container">
        <Link to="/" className="navbar-brand">
          <img src="/static/logo.svg" alt="" className="navbar-logo" />
          vulnapps
        </Link>
        <button
          className="navbar-toggle"
          aria-label="Toggle navigation menu"
          aria-expanded={menuOpen}
          onClick={() => setMenuOpen(o => !o)}
        >
          <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round">
            {menuOpen
              ? <><path d="M18 6 6 18" /><path d="m6 6 12 12" /></>
              : <><path d="M3 12h18" /><path d="M3 6h18" /><path d="M3 18h18" /></>}
          </svg>
        </button>
        <ul className={`navbar-nav${menuOpen ? ' open' : ''}`}>
          {user && <li><Link to="/dashboard">Dashboard</Link></li>}
          <li><Link to="/apps">Apps</Link></li>
          {user && (
            <>
              <li><Link to="/scans">Scans</Link></li>
              <li><Link to="/teams">Teams</Link></li>
              <li><Link to="/account">Account</Link></li>
              {user.role === 'admin' && (
                <li className={`nav-dropdown${adminOpen ? ' open' : ''}`}>
                  <a href="#" className="nav-dropdown-toggle" onClick={e => { e.preventDefault(); setAdminOpen(o => !o); }}>
                    Admin <span className="nav-arrow">&#9662;</span>
                  </a>
                  <ul className="nav-dropdown-menu">
                    <li><Link to="/admin/users">Users</Link></li>
                    <li><Link to="/admin/labels">Labels</Link></li>
                  </ul>
                </li>
              )}
              <li>
                <button onClick={handleLogout} className="btn btn-outline btn-sm">Logout</button>
              </li>
            </>
          )}
          {!user && (
            <>
              <li><Link to="/login" className="btn btn-outline btn-sm">Login</Link></li>
              <li><Link to="/register" className="btn btn-primary btn-sm">Register</Link></li>
            </>
          )}
        </ul>
      </div>
    </nav>
  );
}
