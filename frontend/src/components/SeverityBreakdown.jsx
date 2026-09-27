// A count split by catalog severity, e.g. "8C 19H 14M 4L", shown beside the
// number it adds up to. `counts` is {critical, high, medium, low, info}.
// `info` is dropped when zero — it nearly always is, and rows are already wide.
const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'];

export function SeverityBreakdown({ counts, label = 'found', style }) {
  if (!counts) return null;
  const buckets = SEVERITIES
    .map(sev => [sev, counts[sev] ?? 0])
    .filter(([sev, n]) => sev !== 'info' || n > 0);
  if (buckets.every(([, n]) => n === 0)) return null;
  return (
    <span className="tp-split" style={style}>
      {buckets.map(([sev, n]) => (
        <span key={sev}
          className={`tp-split-${sev}${n === 0 ? ' tp-split-zero' : ''}`}
          title={`${n} ${label} at ground-truth severity ${sev}`}>
          {n}{sev[0].toUpperCase()}
        </span>
      ))}
    </span>
  );
}
