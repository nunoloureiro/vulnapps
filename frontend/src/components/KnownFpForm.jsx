import { useState } from 'react';

const PENALTIES = [1, 3, 9, 27];

// Create or edit one of an app's known false positives. Planted decoys carry
// their catalog id (D1…); remembered review FPs get FP-NNN server-side when
// the id is left empty.
export function KnownFpForm({ initial = {}, submitLabel = 'Save', onSubmit, onCancel, intro }) {
  const [draft, setDraft] = useState({
    fp_id: initial.fp_id || '',
    source: initial.source || 'decoy',
    title: initial.title || '',
    vuln_type: initial.vuln_type || '',
    http_method: initial.http_method || '',
    url: initial.url || '',
    parameter: initial.parameter || '',
    filename: initial.filename || '',
    description: initial.description || '',
    penalty_weight: initial.penalty_weight ?? '',
  });
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);
  const set = patch => setDraft(d => ({ ...d, ...patch }));

  const submit = async (e) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await onSubmit({
        ...draft,
        fp_id: draft.fp_id.trim() || null,
        penalty_weight: draft.penalty_weight === '' ? null : Number(draft.penalty_weight),
      });
    } catch (err) {
      setError(err.message || 'Could not save the known false positive');
      setBusy(false);
    }
  };

  const text = (key, label, props = {}) => (
    <div className="form-group" style={{ flex: props.flex || 1 }}>
      <label className="form-label">{label}</label>
      <input className="form-input" value={draft[key]} onChange={e => set({ [key]: e.target.value })}
        required={props.required} placeholder={props.placeholder} />
    </div>
  );

  return (
    <form onSubmit={submit}>
      {intro && <p className="text-muted text-sm mb-2">{intro}</p>}
      {error && <div className="alert alert-error mb-1">{error}</div>}
      <div className="form-row">
        {text('fp_id', 'ID', { placeholder: draft.source === 'decoy' ? 'D1' : 'FP-NNN (auto)' })}
        <div className="form-group" style={{ flex: 1 }}>
          <label className="form-label">Source</label>
          <select className="form-select" value={draft.source} onChange={e => set({ source: e.target.value })}>
            <option value="decoy">Decoy (planted, in the catalog)</option>
            <option value="reviewed">Reviewed (remembered from a scan)</option>
          </select>
        </div>
        <div className="form-group" style={{ flex: 1 }}>
          <label className="form-label">Penalty</label>
          <select className="form-select" value={draft.penalty_weight} onChange={e => set({ penalty_weight: e.target.value })}>
            <option value="">Unreviewed (27 pts)</option>
            {PENALTIES.map(p => <option key={p} value={p}>{p} pts</option>)}
          </select>
        </div>
      </div>
      <div className="form-row">
        {text('title', 'Title', { required: true, flex: 3, placeholder: 'What a scanner reports' })}
        {text('vuln_type', 'Type', { placeholder: 'IDOR' })}
      </div>
      <div className="form-row">
        {text('http_method', 'Method', { placeholder: 'GET' })}
        {text('url', 'URL', { flex: 2, placeholder: '/orders/:id/receipt' })}
        {text('parameter', 'Parameter')}
        {text('filename', 'File')}
      </div>
      <div className="form-group">
        <label className="form-label">Why it is not real</label>
        <textarea className="form-textarea" value={draft.description} onChange={e => set({ description: e.target.value })}
          placeholder="What a scanner sees, and why it is not exploitable" />
      </div>
      <div style={{ display: 'flex', gap: 8 }}>
        <button type="submit" className="btn btn-primary" disabled={busy}>{busy ? 'Saving…' : submitLabel}</button>
        <button type="button" className="btn btn-outline" onClick={onCancel} disabled={busy}>Cancel</button>
      </div>
    </form>
  );
}
