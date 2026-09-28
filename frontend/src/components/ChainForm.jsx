import { useState } from 'react';

const SEVERITIES = ['critical', 'high', 'medium', 'low'];

// Create or edit a chain: title, severity and the member vulns in step order.
// Shared by the app page's chain editor and a scan finding's Promote -> Chain,
// so the two cannot drift into different rules for what a chain is.
//
// Severity is what a curator sets; the points derive from it server-side,
// exactly as for vulns. Members must already exist in the catalog: a step the
// catalog lacks is promoted as a vuln first, so every member is a flaw some
// scan actually showed.
export function ChainForm({ vulns, initial = {}, submitLabel = 'Save', onSubmit, onCancel, intro }) {
  const [title, setTitle] = useState(initial.title || '');
  const [severity, setSeverity] = useState(initial.severity || 'critical');
  const [members, setMembers] = useState(initial.member_vuln_ids || []);
  const [description, setDescription] = useState(initial.description || '');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);

  const byId = new Map(vulns.map(v => [v.id, v]));
  const available = vulns
    .filter(v => !members.includes(v.id))
    .sort((a, b) => a.vuln_id.localeCompare(b.vuln_id, undefined, { numeric: true }));

  const move = (index, delta) => setMembers(prev => {
    const next = [...prev];
    const target = index + delta;
    if (target < 0 || target >= next.length) return prev;
    [next[index], next[target]] = [next[target], next[index]];
    return next;
  });

  const submit = async (e) => {
    e.preventDefault();
    if (members.length < 2) { setError('A chain needs at least two member vulnerabilities.'); return; }
    setBusy(true);
    setError(null);
    try {
      await onSubmit({ title: title.trim(), severity, member_vuln_ids: members, description: description || null });
    } catch (err) {
      setError(err.message || 'Could not save the chain');
      setBusy(false);
    }
  };

  return (
    <form onSubmit={submit} className="chain-form">
      {intro && <p className="text-muted text-sm mb-2">{intro}</p>}
      {error && <div className="alert alert-error mb-1">{error}</div>}
      <div className="form-row">
        <div className="form-group" style={{ flex: 3 }}>
          <label className="form-label">Title</label>
          <input className="form-input" value={title} required onChange={e => setTitle(e.target.value)}
            placeholder="Step A -> Step B -> Outcome" />
        </div>
        <div className="form-group" style={{ flex: 1 }}>
          <label className="form-label">Severity</label>
          <select className="form-select" value={severity} onChange={e => setSeverity(e.target.value)}>
            {SEVERITIES.map(s => <option key={s} value={s}>{s[0].toUpperCase() + s.slice(1)}</option>)}
          </select>
        </div>
      </div>

      <div className="form-group">
        <label className="form-label">Steps, in order</label>
        {members.length === 0 && <div className="text-muted text-sm mb-1">No steps yet.</div>}
        <ol className="chain-steps">
          {members.map((vid, i) => {
            const v = byId.get(vid);
            return (
              <li key={vid}>
                <span>{v ? `${v.vuln_id} — ${v.title}` : `#${vid}`}</span>
                <span className="chain-step-actions">
                  <button type="button" className="btn-icon" onClick={() => move(i, -1)} disabled={i === 0} title="Move up">↑</button>
                  <button type="button" className="btn-icon" onClick={() => move(i, 1)} disabled={i === members.length - 1} title="Move down">↓</button>
                  <button type="button" className="btn-icon btn-icon-danger" onClick={() => setMembers(m => m.filter(x => x !== vid))} title="Remove">×</button>
                </span>
              </li>
            );
          })}
        </ol>
        <select className="form-select" value="" onChange={e => {
          const vid = Number(e.target.value);
          if (vid) setMembers(m => [...m, vid]);
        }}>
          <option value="">+ add a step…</option>
          {available.map(v => <option key={v.id} value={v.id}>{v.vuln_id} — {v.title}</option>)}
        </select>
      </div>

      <div className="form-group">
        <label className="form-label">Description (optional)</label>
        <textarea className="form-textarea" value={description} onChange={e => setDescription(e.target.value)}
          placeholder="How each step hands the next what it needs" style={{ minHeight: 70 }} />
      </div>

      <div className="flex gap-1">
        <button type="submit" className="btn btn-primary btn-sm" disabled={busy}>{busy ? 'Saving…' : submitLabel}</button>
        {onCancel && <button type="button" className="btn btn-outline btn-sm" onClick={onCancel} disabled={busy}>Cancel</button>}
      </div>
    </form>
  );
}
