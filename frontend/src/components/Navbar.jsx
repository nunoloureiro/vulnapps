import { Link, useNavigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';

export default function Navbar() {
  const { user, logout } = useAuth();
  const navigate = useNavigate();

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
        <ul className="navbar-nav">
          <li><Link to="/apps">Apps</Link></li>
          {user && (
            <>
              <li><Link to="/scans">Scans</Link></li>
              <li><Link to="/teams">Teams</Link></li>
              <li><Link to="/account">Account</Link></li>
              {user.role === 'admin' && (
                <li className="nav-dropdown">
                  <a href="#" className="nav-dropdown-toggle" onClick={e => e.preventDefault()}>
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
