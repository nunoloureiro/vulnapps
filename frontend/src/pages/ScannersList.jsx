import { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import { api } from '../api/client';

const pctColor = (v) => (v >= 0.7 ? 'text-success' : v >= 0.4 ? 'text-warning' : 'text-error');
const fmt = (v) => (v * 100).toFixed(1) + '%';

function detRate(metrics) {
  const total = metrics.tp + metrics.fn;
  return total > 0 ? metrics.tp / total : 0;
}

export default function ScannersList() {
  const [scanners, setScanners] = useState(null);
  const [error, setError] = useState(null);

  useEffect(() => {
    api.get('/scanners')
      .then((res) => setScanners(res.scanners || []))
      .catch((err) => setError(err.message || 'Failed to load scanners'));
  }, []);

  if (error) {
    return (
      <div className="container">
        <div className="page-header"><h1 className="page-title">Scanners</h1></div>
        <div className="alert alert-error">{error}</div>
      </div>
    );
  }

  if (!scanners) {
    return (
      <div className="container">
        <div className="page-header"><h1 className="page-title">Scanners</h1></div>
        <div className="empty-state"><p>Loading...</p></div>
      </div>
    );
  }

  if (scanners.length === 0) {
    return (
      <div className="container">
        <div className="page-header"><h1 className="page-title">Scanners</h1></div>
        <div className="empty-state">
          <h3>No scanners yet</h3>
          <p>Scanners appear here once they've submitted at least one scan.</p>
        </div>
      </div>
    );
  }

  return (
    <div className="container">
      <div className="page-header"><h1 className="page-title">Scanners</h1></div>
      <div className="card">
        <div className="compare-scroll">
          <table>
            <thead>
              <tr>
                <th className="sticky-col">Scanner</th>
                <th className="text-center">Apps</th>
                <th className="text-center">Scans</th>
                <th className="text-center">TP</th>
                <th className="text-center">FP</th>
                <th className="text-center">FN</th>
                <th className="text-center">Precision</th>
                <th className="text-center">Recall</th>
                <th className="text-center">F1</th>
                <th className="text-center">Det. Rate</th>
              </tr>
            </thead>
            <tbody>
              {scanners.map((s) => {
                const m = s.metrics;
                const dr = detRate(m);
                return (
                  <tr key={s.name}>
                    <td className="sticky-col" style={{ fontWeight: 600 }}>
                      <Link to={'/scanners/' + encodeURIComponent(s.name)}>{s.name}</Link>
                    </td>
                    <td className="text-center font-mono">{s.app_count}</td>
                    <td className="text-center font-mono">{s.scan_count}</td>
                    <td className="text-center font-mono text-success">{m.tp}</td>
                    <td className="text-center font-mono text-error">{m.fp}</td>
                    <td className="text-center font-mono text-error">{m.fn}</td>
                    <td className={`text-center font-mono ${pctColor(m.precision)}`}>{fmt(m.precision)}</td>
                    <td className={`text-center font-mono ${pctColor(m.recall)}`}>{fmt(m.recall)}</td>
                    <td className={`text-center font-mono ${pctColor(m.f1)}`}>{fmt(m.f1)}</td>
                    <td className={`text-center font-mono ${pctColor(dr)}`}>{fmt(dr)}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
