import { useState, useEffect, useMemo } from 'react';
import { api } from '../api/client';

// Every commit on main is a release: the app's version is v<major>.<minor>
// with minor = the commit count, so the log and the version line up one to
// one. Merge commits increment the version too, so they are part of the
// history rather than noise to be dropped — but they say nothing a reader
// wants, so they are collapsed behind a toggle instead of deleted.
const isNoise = e => e.is_merge;

function releaseDate(iso) {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return { day: '', time: '' };
  return {
    day: d.toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: '2-digit' }),
    time: d.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit' }),
  };
}

export default function AdminChangelog() {
  const [data, setData] = useState(null);
  const [error, setError] = useState(null);
  const [showMerges, setShowMerges] = useState(false);
  const [query, setQuery] = useState('');
  const [open, setOpen] = useState(() => new Set());

  useEffect(() => {
    api.get('/admin/changelog')
      .then(setData)
      .catch(e => setError(e.message || 'Could not load the change log'));
  }, []);

  const entries = data?.entries || [];

  const toggle = sha => setOpen(prev => {
    const next = new Set(prev);
    if (next.has(sha)) next.delete(sha); else next.add(sha);
    return next;
  });

  const visible = useMemo(() => {
    const q = query.trim().toLowerCase();
    return entries.filter(e => {
      if (!showMerges && isNoise(e)) return false;
      if (!q) return true;
      return `${e.version} ${e.subject} ${(e.bullets || []).join(' ')} ${e.author}`
        .toLowerCase().includes(q);
    });
  }, [entries, showMerges, query]);

  // Group by calendar day so a run of releases reads as one day's work.
  const days = useMemo(() => {
    const out = [];
    for (const e of visible) {
      const day = releaseDate(e.date).day;
      if (!out.length || out[out.length - 1].day !== day) out.push({ day, items: [] });
      out[out.length - 1].items.push(e);
    }
    return out;
  }, [visible]);

  if (error) return <div className="alert alert-error">{error}</div>;
  if (!data) return <p className="text-muted">Loading...</p>;

  const mergeCount = entries.filter(isNoise).length;
  const allOpen = visible.length > 0 && visible.every(e => open.has(e.sha));

  return (
    <>
      <h1 className="page-title mb-2">Change Log</h1>

      <div className="card mb-2">
        <div className="flex items-center justify-between" style={{ flexWrap: 'wrap', gap: '0.5rem' }}>
          <div>
            <span className="text-muted text-sm">Running </span>
            <span className="font-mono">{data.version}</span>
            <span className="text-muted text-sm">
              {' '}· {entries.length} releases · every commit to main is a version
            </span>
          </div>
          <div className="flex items-center gap-1" style={{ flexWrap: 'wrap' }}>
            <input
              className="form-input"
              placeholder="Filter…"
              value={query}
              onChange={e => setQuery(e.target.value)}
              style={{ width: 180 }}
            />
            <button type="button" className="btn btn-outline btn-sm"
              onClick={() => setOpen(allOpen ? new Set() : new Set(visible.map(e => e.sha)))}>
              {allOpen ? 'Collapse all' : 'Expand all'}
            </button>
            {mergeCount > 0 && (
              <label className="text-muted text-sm" style={{ cursor: 'pointer', whiteSpace: 'nowrap' }}>
                <input
                  type="checkbox"
                  checked={showMerges}
                  onChange={e => setShowMerges(e.target.checked)}
                  style={{ accentColor: 'var(--accent)', marginRight: 6 }}
                />
                Merges
              </label>
            )}
          </div>
        </div>
      </div>

      {visible.length === 0 ? (
        <p className="text-muted">Nothing matches that filter.</p>
      ) : days.map(({ day, items }) => (
        <div key={day} className="card mb-2">
          <h3 className="card-title mb-2">{day}</h3>
          {items.map(e => {
            const { time } = releaseDate(e.date);
            const bullets = e.bullets || [];
            const expanded = open.has(e.sha);
            const expandable = bullets.length > 0;
            return (
              <div key={e.sha} className="changelog-row">
                {/* One line per release by default. The subject is already a
                    summary, so the detail only appears when asked for. */}
                <div
                  className={`changelog-line${expandable ? ' is-expandable' : ''}`}
                  onClick={expandable ? () => toggle(e.sha) : undefined}
                  role={expandable ? 'button' : undefined}
                  tabIndex={expandable ? 0 : undefined}
                  onKeyDown={expandable ? (ev => {
                    if (ev.key === 'Enter' || ev.key === ' ') { ev.preventDefault(); toggle(e.sha); }
                  }) : undefined}
                >
                  <span className="changelog-caret">{expandable ? (expanded ? '▾' : '▸') : ''}</span>
                  <span className="changelog-version font-mono">{e.version}</span>
                  <span className="text-muted text-xs changelog-time">{time}</span>
                  <span className="changelog-subject">{e.subject}</span>
                </div>
                {expanded && (
                  <div className="changelog-detail">
                    <ul>
                      {bullets.map((b, i) => <li key={i}>{b}</li>)}
                    </ul>
                    <div className="text-muted text-xs">
                      <span className="font-mono">{e.sha}</span> · {e.author}
                    </div>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      ))}
    </>
  );
}
