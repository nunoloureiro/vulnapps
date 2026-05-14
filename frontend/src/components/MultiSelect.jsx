import { useState, useEffect, useRef } from 'react';

/**
 * A checkbox-popover multi-select. Options can be strings (label = value)
 * or { value, label } objects. `selected` is an array of values.
 */
export function MultiSelect({ options, selected, onChange, allLabel = 'All', minWidth = 140 }) {
  const [open, setOpen] = useState(false);
  const containerRef = useRef(null);

  useEffect(() => {
    if (!open) return;
    const onDoc = (e) => {
      if (containerRef.current && !containerRef.current.contains(e.target)) setOpen(false);
    };
    document.addEventListener('mousedown', onDoc);
    return () => document.removeEventListener('mousedown', onDoc);
  }, [open]);

  const items = options.map((o) => (typeof o === 'string' ? { value: o, label: o } : o));

  const toggle = (value) => {
    if (selected.includes(value)) onChange(selected.filter((v) => v !== value));
    else onChange([...selected, value]);
  };

  const label = selected.length === 0
    ? allLabel
    : selected.length === 1
      ? items.find((i) => i.value === selected[0])?.label ?? String(selected[0])
      : `${selected.length} selected`;

  return (
    <div ref={containerRef} style={{ position: 'relative', display: 'inline-block' }}>
      <button
        type="button"
        className="form-select"
        onClick={() => setOpen((o) => !o)}
        style={{ textAlign: 'left', cursor: 'pointer', minWidth }}
      >
        {label}
      </button>
      {open && (
        <div
          style={{
            position: 'absolute',
            top: '100%',
            left: 0,
            marginTop: 4,
            background: 'var(--bg-panel)',
            border: '1px solid var(--border)',
            borderRadius: 'var(--radius)',
            padding: '0.5rem',
            zIndex: 10,
            minWidth: 200,
            maxHeight: 280,
            overflowY: 'auto',
            boxShadow: '0 4px 12px rgba(0,0,0,0.4)',
          }}
        >
          <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '0.4rem' }}>
            <button
              type="button"
              className="text-xs text-muted"
              style={{ background: 'none', border: 'none', cursor: 'pointer', padding: 0 }}
              onClick={() => onChange([])}
            >
              Clear
            </button>
            <button
              type="button"
              className="text-xs text-muted"
              style={{ background: 'none', border: 'none', cursor: 'pointer', padding: 0 }}
              onClick={() => onChange(items.map((i) => i.value))}
            >
              Select all
            </button>
          </div>
          {items.map((opt) => (
            <label
              key={opt.value}
              style={{ display: 'flex', alignItems: 'center', gap: 6, padding: '0.2rem 0.1rem', cursor: 'pointer', fontSize: '0.875rem' }}
            >
              <input
                type="checkbox"
                checked={selected.includes(opt.value)}
                onChange={() => toggle(opt.value)}
              />
              <span>{opt.label}</span>
            </label>
          ))}
        </div>
      )}
    </div>
  );
}
