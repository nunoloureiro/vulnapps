import { useCallback, useEffect, useState } from 'react';
import { api } from '../api/client';

/**
 * Audit trail of operations on a scan's findings or an app's vulnerabilities.
 * Pass exactly one of scanId/appId. Only renders when canView is true — the
 * real access control is server-side (the API 403s a non-write user
 * regardless), this is just UI polish matching how the rest of these pages
 * already gate on canEdit.
 */
export function HistoryLog({ scanId, appId, canView }) {
  const [entries, setEntries] = useState(null);

  const load = useCallback(() => {
    const path = scanId ? `/scans/${scanId}/history` : `/apps/${appId}/history`;
    api.get(path)
      .then(data => setEntries(data.entries || []))
      .catch(() => setEntries(null));
  }, [scanId, appId]);

  useEffect(() => { if (canView) load(); }, [canView, load]);

  if (!canView || entries === null) return null;

  return (
    <div className="card mt-3">
      <h3 className="card-title">History Log</h3>
      {entries.length === 0 ? (
        <p className="text-muted text-sm">No recorded activity yet.</p>
      ) : (
        <div className="table-wrap mt-2">
          <table className="cards-on-mobile">
            <thead>
              <tr><th>When</th><th>Event</th></tr>
            </thead>
            <tbody>
              {entries.map(e => (
                <tr key={e.id}>
                  <td data-label="When" className="text-sm text-secondary font-mono" style={{ whiteSpace: 'nowrap' }}>
                    {e.created_at}
                  </td>
                  <td data-label="Event">{e.message}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
