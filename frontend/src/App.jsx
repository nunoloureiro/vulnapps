import { BrowserRouter, Routes, Route } from 'react-router-dom';
import { AuthProvider } from './context/AuthContext';
import Navbar from './components/Navbar';
import Home from './pages/Home';
import Login from './pages/Login';
import Register from './pages/Register';
import Account from './pages/Account';
import AppsList from './pages/AppsList';
import AppDetail from './pages/AppDetail';
import AppForm from './pages/AppForm';
import VulnDetail from './pages/VulnDetail';
import VulnForm from './pages/VulnForm';
import ScansList from './pages/ScansList';
import ScanDetail from './pages/ScanDetail';
import ScanSubmit from './pages/ScanSubmit';
import ScanCompare from './pages/ScanCompare';
import TeamsList from './pages/TeamsList';
import TeamDetail from './pages/TeamDetail';
import TeamForm from './pages/TeamForm';
import AdminUsers from './pages/AdminUsers';
import AdminLabels from './pages/AdminLabels';

export default function App() {
  return (
    <BrowserRouter>
      <AuthProvider>
        <Navbar />
        <main className="container">
          <Routes>
            <Route path="/" element={<Home />} />
            <Route path="/login" element={<Login />} />
            <Route path="/register" element={<Register />} />
            <Route path="/account" element={<Account />} />
            <Route path="/apps" element={<AppsList />} />
            <Route path="/apps/new" element={<AppForm />} />
            <Route path="/apps/:id" element={<AppDetail />} />
            <Route path="/apps/:id/edit" element={<AppForm />} />
            <Route path="/apps/:appId/vulns/new" element={<VulnForm />} />
            <Route path="/apps/:appId/vulns/:id" element={<VulnDetail />} />
            <Route path="/apps/:appId/vulns/:id/edit" element={<VulnForm />} />
            <Route path="/apps/:id/scans/new" element={<ScanSubmit />} />
            <Route path="/apps/:id/compare" element={<ScanCompare />} />
            <Route path="/scans" element={<ScansList />} />
            <Route path="/scans/:id" element={<ScanDetail />} />
            <Route path="/teams" element={<TeamsList />} />
            <Route path="/teams/new" element={<TeamForm />} />
            <Route path="/teams/:id" element={<TeamDetail />} />
            <Route path="/admin/users" element={<AdminUsers />} />
            <Route path="/admin/labels" element={<AdminLabels />} />
          </Routes>
        </main>
      </AuthProvider>
    </BrowserRouter>
  );
}
