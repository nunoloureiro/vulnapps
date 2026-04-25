export function Badge({ severity, children }) {
  return <span className={`badge badge-${severity}`}>{children || severity}</span>;
}
