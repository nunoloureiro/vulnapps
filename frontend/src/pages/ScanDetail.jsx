import React, { useState, useEffect, useMemo } from 'react';
import { useParams, Link } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import { api } from '../api/client';
import { Badge } from '../components/Badge';
import { LabelBadge } from '../components/LabelBadge';
import { HistoryLog } from '../components/HistoryLog';

// Finding-action icons (12px, inherit currentColor).
const svg = (children) => (props) => (
  <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" {...props}>{children}</svg>
);
const IconFP = svg(<><circle cx="12" cy="12" r="9" /><line x1="5.6" y1="5.6" x2="18.4" y2="18.4" /></>);
const IconIgnore = svg(<><path d="M9.9 5A9.5 9.5 0 0 1 12 4.8c6.3 0 9.5 7.2 9.5 7.2a14 14 0 0 1-1.7 2.6" /><path d="M6.2 6.2A13 13 0 0 0 2.5 12s3.2 7.2 9.5 7.2a9 9 0 0 0 4.9-1.4" /><line x1="3" y1="3" x2="21" y2="21" /></>);
const IconPromote = svg(<><circle cx="12" cy="12" r="9" /><line x1="12" y1="8" x2="12" y2="16" /><line x1="8" y1="12" x2="16" y2="12" /></>);

export default function ScanDetail() {
  const { id } = useParams();
  const { user } = useAuth();
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  const load = () => {
    api.get(`/scans/${id}`).then(d => { setData(d); setLoading(false); }).catch(e => { setError(e.message); setLoading(false); });
  };
  useEffect(load, [id]);

  if (loading) return <p className="text-muted">Loading...</p>;
  if (error) return <div className="alert alert-error">{error}</div>;
  if (!data) return null;

  const { scan, app, metrics, findings, missed_vulns, known_vulns, labels, can_edit,
          can_view_cost, revision } = data;

  return (
    <>
      <div className="page-header">
        <h1 className="page-title">{scan.scanner_name}</h1>
        <Link to={`/apps/${app.id}`} className="btn btn-outline">Back to App</Link>
      </div>

      <ScanMeta scan={scan} app={app} labels={labels || []} canEdit={can_edit} canViewCost={can_view_cost} scanId={id} onUpdate={load} />
      <Metrics metrics={metrics} app={app} revision={revision} scan={scan} />
      <Findings findings={findings} knownVulns={known_vulns || []} canEdit={can_edit} scanId={id} appId={app.id}
                onUpdate={load} />
      {missed_vulns && missed_vulns.length > 0 && <MissedVulns vulns={missed_vulns} appId={app.id} />}
      <HistoryLog scanId={id} canView={can_edit} />
    </>
  );
}

function EditableField({ label, value, editValue, canEdit, onSave, type = 'text', options }) {
  const edit = editValue !== undefined ? editValue : value;
  const [editing, setEditing] = useState(false);
  const [draft, setDraft] = useState(edit);

  const save = () => {
    const newVal = type === 'checkbox' ? draft : draft;
    if (newVal !== edit) onSave(newVal);
    setEditing(false);
  };

  if (!canEdit) {
    return (
      <>
        <span className="detail-label">{label}</span>
        <span className="detail-value">{type === 'checkbox' ? (value ? 'Yes' : 'No') : (value || '-')}</span>
      </>
    );
  }

  return (
    <>
      <span className="detail-label">{label}</span>
      <span className="detail-value">
        {editing ? (
          <div style={{ display: 'flex', gap: 4, alignItems: 'center' }}>
            {type === 'checkbox' ? (
              <select className="form-select" value={draft ? '1' : '0'} onChange={e => setDraft(e.target.value === '1')} style={{ width: 'auto', padding: '2px 6px', fontSize: '0.85rem' }} autoFocus>
                <option value="1">Yes</option>
                <option value="0">No</option>
              </select>
            ) : type === 'textarea' ? (
              <textarea className="form-textarea" value={draft || ''} onChange={e => setDraft(e.target.value)} style={{ fontSize: '0.85rem', minHeight: 60 }} autoFocus />
            ) : (
              <input className="form-input" type={type} value={draft || ''} onChange={e => setDraft(e.target.value)}
                style={{ padding: '2px 6px', fontSize: '0.85rem', width: 'auto' }} autoFocus
                onKeyDown={e => { if (e.key === 'Enter') save(); if (e.key === 'Escape') setEditing(false); }} />
            )}
            <button className="btn btn-primary btn-sm" onClick={save} style={{ height: 24, padding: '0 0.4rem', fontSize: '0.7rem' }}>Save</button>
            <button className="btn btn-outline btn-sm" onClick={() => { setDraft(edit); setEditing(false); }} style={{ height: 24, padding: '0 0.4rem', fontSize: '0.7rem' }}>Cancel</button>
          </div>
        ) : (
          <span onClick={() => { setDraft(edit); setEditing(true); }}
            className="editable-field"
            title="Click to edit">
            {type === 'checkbox' ? (value ? 'Yes' : 'No') : (value || '-')}
            <svg className="edit-icon" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="var(--text-muted)" strokeWidth="2">
              <path d="M17 3a2.85 2.85 0 1 1 4 4L7.5 20.5 2 22l1.5-5.5Z"/><path d="m15 5 4 4"/>
            </svg>
          </span>
        )}
      </span>
    </>
  );
}

function ScanMeta({ scan, app, labels, canEdit, canViewCost, scanId, onUpdate }) {
  const [showLabelInput, setShowLabelInput] = useState(false);
  const [labelName, setLabelName] = useState('');
  const [allLabels, setAllLabels] = useState([]);

  useEffect(() => {
    api.get('/labels').then(d => setAllLabels(d.labels || []));
  }, []);

  const addLabel = async (name, color = '#f97316') => {
    await api.post(`/scans/${scanId}/labels`, { name, color });
    setLabelName('');
    setShowLabelInput(false);
    onUpdate();
  };

  const removeLabel = async (labelId) => {
    await api.del(`/scans/${scanId}/labels/${labelId}`);
    onUpdate();
  };

  const updateField = async (field, value) => {
    await api.put(`/scans/${scanId}`, { [field]: value });
    onUpdate();
  };

  return (
    <div className="card">
      <div className="detail-grid">
        <EditableField label="Scanner" value={scan.scanner_name} canEdit={canEdit} onSave={v => updateField('scanner_name', v)} />
        <span className="detail-label">App</span>
        <span className="detail-value"><Link to={`/apps/${app.id}`}>{app.name}</Link></span>
        <EditableField label="Scan Date" value={scan.scan_date} canEdit={canEdit} type="date" onSave={v => updateField('scan_date', v)} />
        <span className="detail-label">Submitted By</span>
        <span className="detail-value text-secondary">{scan.submitter_name || scan.submitted_by}</span>
        <span className="detail-label">Labels</span>
        <span className="detail-value">
          <div className="scan-labels-cell">
            {labels.map(l => <LabelBadge key={l.id} label={l} onRemove={canEdit ? removeLabel : undefined} />)}
            {canEdit && !showLabelInput && (
              <button className="btn btn-outline btn-sm" onClick={() => setShowLabelInput(true)} style={{ height: 22, padding: '0 0.4rem', fontSize: '0.7rem' }}>+ Label</button>
            )}
            {showLabelInput && (
              <div style={{ display: 'flex', gap: 4, alignItems: 'center' }}>
                <input className="form-input" value={labelName} onChange={e => setLabelName(e.target.value)} placeholder="Label name..." style={{ width: 120, padding: '2px 6px', fontSize: '0.8rem' }}
                  onKeyDown={e => { if (e.key === 'Enter' && labelName.trim()) addLabel(labelName.trim()); if (e.key === 'Escape') setShowLabelInput(false); }}
                  list="label-suggestions" autoFocus />
                <datalist id="label-suggestions">
                  {allLabels.map(l => <option key={l.id} value={l.name} />)}
                </datalist>
                <button className="btn btn-primary btn-sm" onClick={() => labelName.trim() && addLabel(labelName.trim())} style={{ height: 22, padding: '0 0.4rem', fontSize: '0.7rem' }}>Add</button>
              </div>
            )}
          </div>
        </span>
        {canViewCost && scan.duration != null && (
          <>
            <span className="detail-label">Duration <span className="text-muted text-xs">(private)</span></span>
            <span className="detail-value font-mono">{scan.duration >= 60 ? `${Math.floor(scan.duration / 60)}m ${scan.duration % 60}s` : `${scan.duration}s`}</span>
          </>
        )}
        {canViewCost && scan.tokens != null && (
          <>
            <span className="detail-label">Tokens <span className="text-muted text-xs">(private)</span></span>
            <span className="detail-value font-mono">{scan.tokens.toLocaleString()}</span>
          </>
        )}
        {canViewCost && (
          <EditableField
            label={<>Cost <span className="text-muted text-xs">(private)</span></>}
            value={scan.cost != null ? `$${scan.cost.toFixed(4)}` : ''}
            editValue={scan.cost != null ? String(scan.cost) : ''}
            canEdit={canEdit}
            type="number"
            onSave={v => { const c = parseFloat(v); updateField('cost', isNaN(c) ? null : c); }}
          />
        )}
        {scan.state_filename && (
          <>
            <span className="detail-label">Scan State</span>
            <span className="detail-value">
              <button
                type="button"
                className="btn btn-outline btn-sm"
                onClick={() => api.download(`/scans/${scanId}/state`, scan.state_filename)}
                title={scan.state_sha256 ? `sha256: ${scan.state_sha256}` : 'Download zip'}
                style={{ height: 22, padding: '0 0.5rem', fontSize: '0.75rem' }}
              >
                ↓ {scan.state_filename}
                {scan.state_size != null && (
                  <span className="text-muted text-xs" style={{ marginLeft: 6 }}>({humanSize(scan.state_size)})</span>
                )}
              </button>
            </span>
          </>
        )}
        <EditableField label="Notes" value={scan.notes} canEdit={canEdit} type="textarea" onSave={v => updateField('notes', v)} />
      </div>
    </div>
  );
}

function humanSize(n) {
  if (n == null) return '';
  let u = 0;
  const units = ['B', 'KiB', 'MiB', 'GiB'];
  while (n >= 1024 && u < units.length - 1) { n /= 1024; u++; }
  return `${u === 0 ? n : n.toFixed(1)} ${units[u]}`;
}

const TIER_LABELS = {
  commodity: 'Commodity',
  business_logic: 'Business logic',
  chained: 'Chained',
};

const pct = v => v != null ? `${(v * 100).toFixed(1)}%` : 'N/A';

function Metrics({ metrics, app, revision, scan }) {
  const incomplete = metrics.adjudication_complete === false;
  const tiers = metrics.tiers || {};
  const asRun = scan?.corpus_revision;

  return (
    <>
      <div className="flex items-center justify-between mt-3 mb-2" style={{ flexWrap: 'wrap' }}>
        <h2 className="page-title">Metrics</h2>
        {/* Every number is labelled with the ground truth that produced it —
            scores drift down as ground truth grows, and an unlabelled chart
            makes that look like a regression. */}
        <span className="text-muted text-sm font-mono">
          {app?.name}@rev{revision}
          {asRun != null && asRun !== revision ? ` (ran at rev${asRun})` : ''}
        </span>
      </div>

      <div className="metrics-grid mb-2">
        <div className="metric-card">
          <div className="metric-value text-accent">{pct(metrics.weighted_rate)}</div>
          <div className="metric-label">
            Weighted Detection
            <span className="tooltip-wrap text-muted text-xs" style={{ marginLeft: 4 }}>ⓘ
              <span className="tooltip-text">
                Severity-weighted detection rate: points found / points available on the
                1/3/9/27 scale. The headline metric — a missed reflected XSS and a missed
                chained authz bypass are not the same miss.
              </span>
            </span>
          </div>
          <div className="text-muted text-xs font-mono">
            {metrics.weighted_found} / {metrics.weighted_total} pts
          </div>
        </div>
        <div className="metric-card"><div className="metric-value text-success">{metrics.tp}</div><div className="metric-label">True Positives</div></div>
        <div className="metric-card">
          <div className="metric-value text-error">{metrics.fp_groups ?? metrics.fp}</div>
          <div className="metric-label">
            False Positives
            <span className="tooltip-wrap text-muted text-xs" style={{ marginLeft: 4 }}>ⓘ
              <span className="tooltip-text">
                Distinct false-positive clusters. Findings sharing an fp_group count once,
                so precision is not depressed for a scanner that describes one non-issue
                three times.
              </span>
            </span>
          </div>
          {metrics.fp !== metrics.fp_groups && (
            <div className="text-muted text-xs font-mono">{metrics.fp} findings</div>
          )}
        </div>
        <div className="metric-card"><div className="metric-value text-error">{metrics.fn}</div><div className="metric-label">False Negatives</div></div>
        <div className="metric-card"><div className="metric-value text-muted">{metrics.ignored ?? 0}</div><div className="metric-label">Ignored</div></div>
        <div className="metric-card">
          {/* Precision is only meaningful after full adjudication. With pending
              findings we show the bounds instead of a single flattering number. */}
          <div className={`metric-value ${incomplete ? 'text-warning' : 'text-accent'}`}
               style={incomplete ? { fontSize: '1.1rem' } : undefined}>
            {incomplete
              ? `${pct(metrics.precision_lower)}–${pct(metrics.precision_upper)}`
              : pct(metrics.precision_upper)}
          </div>
          <div className="metric-label">
            Precision
            {incomplete && (
              <span className="tooltip-wrap text-muted text-xs" style={{ marginLeft: 4 }}>ⓘ
                <span className="tooltip-text">
                  {metrics.pending} finding(s) are still unadjudicated, so precision is a
                  range: the lower bound treats every pending finding as a false positive,
                  the upper bound as a true one. They converge as you adjudicate.
                </span>
              </span>
            )}
          </div>
          {incomplete && <div className="text-warning text-xs">{metrics.pending} pending</div>}
        </div>
        <div className="metric-card"><div className="metric-value text-accent">{pct(metrics.recall)}</div><div className="metric-label">Recall</div></div>
        <div className="metric-card"><div className="metric-value text-accent">{pct(metrics.f1)}</div><div className="metric-label">F1 Score</div></div>
      </div>

      {metrics.out_of_scope_matches > 0 && (
        <div className="alert alert-warning mb-2">
          {metrics.out_of_scope_matches} finding(s) match a vulnerability that is not in
          scope at revision {revision} — counted as neither true nor false positive.
        </div>
      )}

      <TierMatrix tiers={tiers} metrics={metrics} />
    </>
  );
}

// The default reporting view: where on the difficulty curve this run performed.
// Difficulty is a reporting axis, never a multiplier — folding it into the
// weight would collapse this table into one opaque number.
function TierMatrix({ tiers, metrics }) {
  const rows = Object.keys(TIER_LABELS).filter(t => tiers[t] && tiers[t].count > 0);
  if (rows.length === 0) return null;
  return (
    <div className="card mb-2">
      <h3 className="card-title mb-2">Difficulty Tiers</h3>
      <div className="table-wrap">
        <table className="cards-on-mobile">
          <thead>
            <tr>
              <th>Tier</th>
              <th className="text-center">Ground truth</th>
              <th className="text-center">Found</th>
              <th className="text-center">Weighted rate</th>
              <th className="text-center">Points</th>
            </tr>
          </thead>
          <tbody>
            {rows.map(t => {
              const row = tiers[t];
              return (
                <tr key={t}>
                  <td data-label="Tier">{TIER_LABELS[t]}</td>
                  <td data-label="Ground truth" className="text-center font-mono">{row.count}</td>
                  <td data-label="Found" className={`text-center font-mono ${row.rate >= 0.7 ? 'text-success' : row.rate >= 0.4 ? 'text-warning' : 'text-error'}`}>
                    {row.found}
                    <span className="text-muted text-xs"> ({pct(row.rate)})</span>
                  </td>
                  <td data-label="Weighted rate" className={`text-center font-mono ${row.weighted_rate >= 0.7 ? 'text-success' : row.weighted_rate >= 0.4 ? 'text-warning' : 'text-error'}`}>
                    {pct(row.weighted_rate)}
                  </td>
                  <td data-label="Points" className="text-center font-mono text-secondary">
                    {row.weighted_found} / {row.weighted_total}
                  </td>
                </tr>
              );
            })}
            <tr>
              <td className="detail-label">Weighted total</td>
              <td className="text-center font-mono">{metrics.tp + metrics.fn}</td>
              <td className="text-center font-mono">{metrics.tp}</td>
              <td className={`text-center font-mono ${metrics.weighted_rate >= 0.7 ? 'text-success' : metrics.weighted_rate >= 0.4 ? 'text-warning' : 'text-error'}`}>
                {pct(metrics.weighted_rate)}
              </td>
              <td className="text-center font-mono text-secondary">
                {metrics.weighted_found} / {metrics.weighted_total}
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>
  );
}

// Inline editor for the FP cluster key. Findings sharing a key count as one
// false positive, matching how several findings on one vuln count as one TP.
function FpGroup({ scanId, finding, canEdit, onUpdate }) {
  const [editing, setEditing] = useState(false);
  const [draft, setDraft] = useState(finding.fp_group || '');

  const save = async () => {
    await api.post(`/scans/${scanId}/findings/${finding.id}/mark-fp`, { fp_group: draft.trim() || null });
    setEditing(false);
    onUpdate();
  };

  if (!canEdit) {
    return finding.fp_group
      ? <span className="text-muted text-xs font-mono">group: {finding.fp_group}</span>
      : <span className="text-muted">FP</span>;
  }
  if (editing) {
    return (
      <div style={{ display: 'flex', gap: 4, alignItems: 'center' }}>
        <input className="form-input" value={draft} autoFocus
               onChange={e => setDraft(e.target.value)}
               placeholder="cluster key…"
               style={{ width: 120, padding: '2px 6px', fontSize: '0.8rem' }}
               onKeyDown={e => { if (e.key === 'Enter') save(); if (e.key === 'Escape') setEditing(false); }} />
        <button className="btn btn-primary btn-sm" onClick={save}
                style={{ height: 22, padding: '0 0.4rem', fontSize: '0.7rem' }}>Set</button>
      </div>
    );
  }
  return (
    <span className="editable-field text-xs" onClick={() => { setDraft(finding.fp_group || ''); setEditing(true); }}
          title="Group this false positive with others describing the same non-issue">
      {finding.fp_group ? <span className="font-mono">group: {finding.fp_group}</span> : <span className="text-muted">FP — ungrouped</span>}
    </span>
  );
}

function Findings({ findings, knownVulns, canEdit, scanId, appId, onUpdate }) {
  const [promoting, setPromoting] = useState(null);
  const [promoteError, setPromoteError] = useState('');
  const [expanded, setExpanded] = useState(() => new Set());

  useEffect(() => {
    if (!promoting) return;
    const onKey = (e) => { if (e.key === 'Escape') setPromoting(null); };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [promoting]);

  const toggleExpanded = (fid) => {
    setExpanded(prev => {
      const next = new Set(prev);
      if (next.has(fid)) next.delete(fid); else next.add(fid);
      return next;
    });
  };

  const matchFinding = async (findingId, vulnId) => {
    await api.post(`/scans/${scanId}/findings/${findingId}/match`, { vuln_id: vulnId });
    onUpdate();
  };

  const markFP = async (findingId) => {
    await api.post(`/scans/${scanId}/findings/${findingId}/mark-fp`, {});
    onUpdate();
  };

  const setIgnored = async (findingId, ignored) => {
    await api.post(`/scans/${scanId}/findings/${findingId}/ignore`, { ignored });
    onUpdate();
  };

  const rematch = async () => {
    if (!confirm('Re-run automatic matching for all findings?')) return;
    await api.post(`/scans/${scanId}/rematch`, {});
    onUpdate();
  };

  const openPromote = (f) => {
    setPromoteError('');
    setPromoting({
      findingId: f.id,
      draft: {
        vuln_id: '',
        title: f.title || f.vuln_type || '',
        severity: (f.severity || 'medium').toLowerCase(),
        // Deliberately unset: the operator has to state whether the flaw existed
        // all along (prior scans take the miss) or was introduced by a code
        // change (prior scans untouched). Defaulting it silently would make
        // every historical number quietly wrong in one direction or the other.
        existed_since: '',
        impact_weight: '',
        difficulty_tier: 'commodity',
        vuln_type: f.vuln_type || '',
        http_method: f.http_method || '',
        url: f.url || '',
        parameter: f.parameter || '',
        filename: f.filename || '',
        description: f.description || '',
        poc: f.poc || '',
        remediation: f.remediation || '',
        code_location: f.code_location || '',
      },
    });
  };

  const updateDraft = (patch) => setPromoting(p => ({ ...p, draft: { ...p.draft, ...patch } }));

  const submitPromote = async () => {
    const overrides = { ...promoting.draft };
    if (!overrides.vuln_id) delete overrides.vuln_id;
    if (!overrides.impact_weight) delete overrides.impact_weight;
    try {
      await api.post(`/scans/${scanId}/findings/${promoting.findingId}/promote`, overrides);
      setPromoting(null);
      onUpdate();
    } catch (e) {
      setPromoteError(e.message);
    }
  };

  return (
    <>
      <div className="flex items-center justify-between mt-3 mb-2">
        <h2 className="page-title">Findings <span className="text-muted text-sm">({findings.length})</span></h2>
        {canEdit && <button className="btn btn-outline btn-sm" onClick={rematch}>Re-match All</button>}
      </div>
      {findings.length > 0 ? (
        <div className="card">
          <div className="table-wrap">
            <table className="cards-on-mobile">
              <thead><tr>
                <th>Type</th><th>Location</th><th>Status</th><th>Matched Vuln</th>
                <th></th>
              </tr></thead>
              <tbody>
                {findings.map(f => {
                  const location = f.url || f.filename || '-';
                  const locationDisplay = f.http_method ? `${f.http_method} ${location}` : location;
                  const matchedVuln = f.matched_vuln_id ? knownVulns.find(v => v.id === f.matched_vuln_id) : null;
                  const severityMismatch = !!(f.severity && matchedVuln?.severity &&
                    f.severity.toLowerCase() !== matchedVuln.severity.toLowerCase());
                  const hasDetails = !!(f.title || f.severity || f.description || f.poc || f.remediation || f.code_location);
                  const isExpanded = expanded.has(f.id);
                  return (
                  <React.Fragment key={f.id}>
                  <tr>
                    <td data-label="Type">
                      <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                        {hasDetails && (
                          <button
                            type="button"
                            onClick={() => toggleExpanded(f.id)}
                            title={isExpanded ? 'Hide details' : 'Show finding details'}
                            style={{ background: 'none', border: 'none', cursor: 'pointer', padding: 0, color: 'var(--text-muted)', display: 'flex' }}>
                            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" style={{ transform: isExpanded ? 'rotate(90deg)' : 'none', transition: 'transform 0.1s' }}>
                              <polyline points="9 18 15 12 9 6"/>
                            </svg>
                          </button>
                        )}
                        <span>{f.vuln_type}</span>
                        {f.severity && <Badge severity={f.severity.toLowerCase()} />}
                      </div>
                      {f.title && f.title !== f.vuln_type && (
                        <div className="text-muted text-xs" style={{ marginTop: 2, marginLeft: hasDetails ? 18 : 0 }}>{f.title}</div>
                      )}
                    </td>
                    <td data-label="Location" className="font-mono text-sm">
                      {locationDisplay}
                      {f.parameter && (
                        <div className="text-muted text-xs" style={{ marginTop: 2 }}>param: {f.parameter}</div>
                      )}
                    </td>
                    <td data-label="Status">
                      {f.matched_vuln_id ? <Badge severity="low">TP</Badge> :
                       f.is_false_positive ? <Badge severity="critical">FP</Badge> :
                       f.is_ignored ? <Badge severity="ignored">Ignored</Badge> :
                       <Badge severity="pending">Pending</Badge>}
                    </td>
                    <td data-label="Matched Vuln">
                      {canEdit ? (
                        <div style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
                          <select className="form-select" style={{ width: 'auto', padding: '2px 4px', fontSize: '0.8rem', flex: 1 }}
                            value={f.matched_vuln_id || ''} onChange={e => matchFinding(f.id, e.target.value ? parseInt(e.target.value) : null)}>
                            <option value="">-- Unmapped --</option>
                            {knownVulns.map(v => <option key={v.id} value={v.id}>{v.vuln_id} - {v.title}</option>)}
                          </select>
                          {matchedVuln && (
                            <Link className="fa-link" to={`/apps/${appId}/vulns/${matchedVuln.id}`} title="View vulnerability">
                              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/><polyline points="15 3 21 3 21 9"/><line x1="10" y1="14" x2="21" y2="3"/></svg>
                            </Link>
                          )}
                        </div>
                      ) : (
                        matchedVuln ? <Link to={`/apps/${appId}/vulns/${matchedVuln.id}`}>{matchedVuln.vuln_id} - {matchedVuln.title}</Link> :
                        f.is_false_positive ? <span className="text-muted">FP</span> :
                        f.is_ignored ? <span className="text-muted">Ignored</span> : <span className="text-muted">Unmapped</span>
                      )}
                      {matchedVuln && matchedVuln.severity && (
                        <div style={{ marginTop: 2, display: 'flex', alignItems: 'center', gap: 4 }}>
                          <span style={severityMismatch ? { outline: '1px solid #f59e0b', borderRadius: 4 } : undefined}>
                            <Badge severity={matchedVuln.severity.toLowerCase()} />
                          </span>
                          {severityMismatch && (
                            <span title={`Reported ${f.severity} vs ground truth ${matchedVuln.severity}`} style={{ color: '#f59e0b', cursor: 'help' }}>⚠</span>
                          )}
                        </div>
                      )}
                      {!!f.is_false_positive && (
                        <div style={{ marginTop: 2 }}>
                          <FpGroup scanId={scanId} finding={f} canEdit={canEdit} onUpdate={onUpdate} />
                        </div>
                      )}
                    </td>
                    <td data-label="">
                      <div className="finding-actions">
                        {canEdit && !f.is_false_positive && (
                          <button className="fa-btn fa-fp" onClick={() => markFP(f.id)} title="Mark as False Positive"><IconFP />FP</button>
                        )}
                        {canEdit && !f.matched_vuln_id && !f.is_false_positive && !f.is_ignored && (
                          <button className="fa-btn fa-ignore" onClick={() => setIgnored(f.id, true)} title="Ignore — real-ish but irrelevant here (excluded from metrics)"><IconIgnore />Ignore</button>
                        )}
                        {canEdit && !f.matched_vuln_id && (
                          <button className="fa-btn fa-promote"
                            onClick={() => openPromote(f)}
                            title={f.is_false_positive ? 'Promote FP to a real vulnerability' : 'Promote to known vulnerability'}>
                            <IconPromote />Vuln
                          </button>
                        )}
                      </div>
                    </td>
                  </tr>
                  {isExpanded && hasDetails && (
                    <tr>
                      <td data-label="" colSpan="5" style={{ padding: '0.75rem 0' }}>
                        <div className="card">
                          <FindingDetails finding={f} />
                        </div>
                      </td>
                    </tr>
                  )}
                  </React.Fragment>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      ) : <div className="empty-state"><p>No findings in this scan.</p></div>}

      {promoting && (
        <div className="modal-backdrop" onClick={() => setPromoting(null)}>
          <div
            className="modal"
            style={{ maxWidth: 720, maxHeight: '90vh', overflowY: 'auto' }}
            onClick={e => e.stopPropagation()}>
            <button type="button" className="modal-close" onClick={() => setPromoting(null)} aria-label="Close">×</button>
            <h3 className="card-title mb-2">Promote to Vulnerability</h3>
            <PromoteForm
              draft={promoting.draft}
              onChange={updateDraft}
              onSubmit={submitPromote}
              onCancel={() => setPromoting(null)}
              error={promoteError}
            />
          </div>
        </div>
      )}
    </>
  );
}

const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'];

// The 1/3/9/27 scale. Log spacing is deliberate: with linear weights nine
// informational findings would outscore two criticals.
const WEIGHT_OPTIONS = [
  [1, 'Informational — version disclosure, verbose errors, missing headers'],
  [3, 'Medium — reflected XSS, open redirect, unauthenticated read of non-sensitive data'],
  [9, 'High — cross-tenant IDOR, stored XSS with session theft, SSRF, single-step authz bypass'],
  [27, 'Critical — chained exploit to admin, cross-tenant write, auth bypass, RCE, financial abuse'],
];

const TIER_OPTIONS = [
  ['commodity', 'Commodity — a technical/input-handling defect (injection, protocol, config)'],
  ['business_logic', 'Business logic — missing or client-trusted authorization/business-rule check'],
  ['chained', 'Chained — requires pivoting through more than one flaw'],
];

function FindingDetails({ finding }) {
  const hasGrid = !!(finding.severity || finding.code_location);
  return (
    <>
      {hasGrid && (
        <div className="detail-grid">
          {finding.severity && (
            <>
              <span className="detail-label">Severity</span>
              <span className="detail-value">
                <span className={'badge badge-' + finding.severity}>{finding.severity}</span>
              </span>
            </>
          )}
          {finding.code_location && (
            <>
              <span className="detail-label">Code Location</span>
              <span className="detail-value font-mono">{finding.code_location}</span>
            </>
          )}
        </div>
      )}

      {finding.description && (
        <div className="mt-2">
          <h3 className="card-title mb-1">Description</h3>
          <p className="text-sm" style={{ whiteSpace: 'pre-wrap' }}>{finding.description}</p>
        </div>
      )}

      {finding.poc && (
        <div className="mt-2">
          <h3 className="card-title mb-1">Proof of Concept</h3>
          <pre style={{
            background: 'var(--bg)',
            border: '1px solid var(--border)',
            borderRadius: 'var(--radius)',
            padding: '0.75rem',
            overflowX: 'auto',
            margin: 0,
          }}>
            <code className="font-mono text-sm">{finding.poc}</code>
          </pre>
        </div>
      )}

      {finding.remediation && (
        <div className="mt-2">
          <h3 className="card-title mb-1">Remediation</h3>
          <p className="text-sm" style={{ whiteSpace: 'pre-wrap' }}>{finding.remediation}</p>
        </div>
      )}
    </>
  );
}

function PromoteForm({ draft, onChange, onSubmit, onCancel, error }) {
  return (
    <form onSubmit={e => { e.preventDefault(); onSubmit(); }}>
      <div className="form-row">
        <div className="form-group">
          <label className="form-label" htmlFor="promote-vuln-id">Vuln ID</label>
          <input
            type="text"
            id="promote-vuln-id"
            className="form-input"
            value={draft.vuln_id}
            onChange={e => onChange({ vuln_id: e.target.value })}
            placeholder="auto (DISC-NNN)"
          />
        </div>
        <div className="form-group">
          <label className="form-label" htmlFor="promote-title">Title</label>
          <input
            type="text"
            id="promote-title"
            className="form-input"
            value={draft.title}
            onChange={e => onChange({ title: e.target.value })}
            required
          />
        </div>
      </div>

      <div className="form-row">
        <div className="form-group">
          <label className="form-label" htmlFor="promote-severity">Severity</label>
          <select
            id="promote-severity"
            className="form-select"
            value={draft.severity}
            onChange={e => onChange({ severity: e.target.value })}
            required
          >
            {SEVERITIES.map(s => (
              <option key={s} value={s}>{s.charAt(0).toUpperCase() + s.slice(1)}</option>
            ))}
          </select>
        </div>
        <div className="form-group">
          <label className="form-label" htmlFor="promote-vuln-type">Vulnerability Type</label>
          <input
            type="text"
            id="promote-vuln-type"
            className="form-input"
            value={draft.vuln_type}
            onChange={e => onChange({ vuln_type: e.target.value })}
          />
        </div>
      </div>

      <div className="form-row">
        <div className="form-group">
          <label className="form-label" htmlFor="promote-weight">
            Impact Weight <span className="text-muted text-xs">(scoring)</span>
          </label>
          <select
            id="promote-weight"
            className="form-select"
            value={draft.impact_weight}
            onChange={e => onChange({ impact_weight: e.target.value })}
          >
            <option value="">Derive from severity</option>
            {WEIGHT_OPTIONS.map(([w, label]) => (
              <option key={w} value={w}>{w} — {label}</option>
            ))}
          </select>
        </div>
        <div className="form-group">
          <label className="form-label" htmlFor="promote-tier">Difficulty Tier</label>
          <select
            id="promote-tier"
            className="form-select"
            value={draft.difficulty_tier}
            onChange={e => onChange({ difficulty_tier: e.target.value })}
            required
          >
            {TIER_OPTIONS.map(([t, label]) => <option key={t} value={t}>{label}</option>)}
          </select>
        </div>
      </div>

      {/* The two-field split (existed_since vs known_since) exists precisely so
          this question gets answered explicitly, once, by a human. */}
      <div className="form-group">
        <label className="form-label">Did this flaw exist before now?</label>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
          <label className="text-sm" style={{ cursor: 'pointer' }}>
            <input type="radio" name="existed-since" value="all_along"
                   checked={draft.existed_since === 'all_along'}
                   onChange={e => onChange({ existed_since: e.target.value })}
                   style={{ accentColor: 'var(--accent)', marginRight: 6 }} />
            It existed all along — every prior scan legitimately takes the miss
          </label>
          <label className="text-sm" style={{ cursor: 'pointer' }}>
            <input type="radio" name="existed-since" value="this_revision"
                   checked={draft.existed_since === 'this_revision'}
                   onChange={e => onChange({ existed_since: e.target.value })}
                   style={{ accentColor: 'var(--accent)', marginRight: 6 }} />
            A code change introduced it — prior scans are untouched
          </label>
        </div>
        <span className="text-muted text-xs">
          Promoting opens a new ground-truth revision either way. This choice decides
          whether older scans are re-scored against it.
        </span>
      </div>

      <div className="form-group">
        <label className="form-label" htmlFor="promote-description">Description</label>
        <textarea
          id="promote-description"
          className="form-textarea"
          value={draft.description}
          onChange={e => onChange({ description: e.target.value })}
        />
      </div>

      <div className="form-group">
        <label className="form-label" htmlFor="promote-code-location">Code Location</label>
        <input
          type="text"
          id="promote-code-location"
          className="form-input"
          value={draft.code_location}
          onChange={e => onChange({ code_location: e.target.value })}
        />
      </div>

      <div className="form-group">
        <label className="form-label" htmlFor="promote-poc">Proof of Concept</label>
        <textarea
          id="promote-poc"
          className="form-textarea"
          value={draft.poc}
          onChange={e => onChange({ poc: e.target.value })}
        />
      </div>

      <div className="form-group">
        <label className="form-label" htmlFor="promote-remediation">Remediation</label>
        <textarea
          id="promote-remediation"
          className="form-textarea"
          value={draft.remediation}
          onChange={e => onChange({ remediation: e.target.value })}
        />
      </div>

      {error && <div className="alert alert-error">{error}</div>}

      <div className="flex gap-1">
        <button type="submit" className="btn btn-primary"
                disabled={!draft.title.trim() || !draft.existed_since}
                title={!draft.existed_since ? 'Choose whether the flaw existed before now' : undefined}>
          Promote
        </button>
        <button type="button" className="btn btn-outline" onClick={onCancel}>Cancel</button>
      </div>
    </form>
  );
}

function MissedVulns({ vulns, appId }) {
  return (
    <>
      <h2 className="page-title mt-3 mb-2">Missed Vulnerabilities <span className="text-muted text-sm">({vulns.length})</span></h2>
      <div className="card">
        <div className="table-wrap">
          <table className="cards-on-mobile">
            <thead><tr><th>ID</th><th>Title</th><th>Type</th><th>Severity</th><th>Location</th></tr></thead>
            <tbody>
              {vulns.map(v => (
                <tr key={v.id}>
                  <td data-label="ID" className="font-mono">{v.vuln_id}</td>
                  <td data-label="Title"><Link to={`/apps/${appId}/vulns/${v.id}`}>{v.title}</Link></td>
                  <td data-label="Type">{v.vuln_type}</td>
                  <td data-label="Severity"><Badge severity={v.severity} /></td>
                  <td data-label="Location" className="font-mono text-sm">{v.url || v.filename || '-'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </>
  );
}
