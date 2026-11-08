import { useLayoutEffect, useRef, useState } from 'react';
import { createPortal } from 'react-dom';

// An "ⓘ" with an explanation on hover or keyboard focus. The text is rendered
// in a portal at a fixed position, so no scrolling table or card can clip it:
// Compare's metrics table scrolls sideways, and the old CSS-only tooltip,
// absolutely positioned inside it, lost everything above the table's top edge.
// Opens above the icon when there's room, else below; kept inside the window.
const WIDTH = 260;
const GAP = 8;

export function InfoTip({ children, style }) {
  const icon = useRef(null);
  const tip = useRef(null);
  const [open, setOpen] = useState(false);
  const [pos, setPos] = useState(null);

  useLayoutEffect(() => {
    if (!open || !icon.current || !tip.current) return;
    const r = icon.current.getBoundingClientRect();
    const h = tip.current.offsetHeight;
    const above = r.top - GAP - h >= 0;
    const top = above ? r.top - GAP - h : Math.min(r.bottom + GAP, window.innerHeight - h - GAP);
    const left = Math.max(GAP, Math.min(r.left, window.innerWidth - WIDTH - GAP));
    setPos({ top, left });
  }, [open]);

  const show = () => { setPos(null); setOpen(true); };
  const hide = () => setOpen(false);

  return (
    <>
      <span ref={icon} className="info-tip text-muted text-xs" style={{ marginLeft: 4, ...style }}
            tabIndex={0} role="button" aria-label="More information"
            onMouseEnter={show} onMouseLeave={hide} onFocus={show} onBlur={hide}>
        ⓘ
      </span>
      {open && createPortal(
        <div ref={tip} role="tooltip" className="info-tip-text"
             style={{ width: WIDTH, top: pos?.top ?? -9999, left: pos?.left ?? -9999,
                      visibility: pos ? 'visible' : 'hidden' }}>
          {children}
        </div>,
        document.body,
      )}
    </>
  );
}
