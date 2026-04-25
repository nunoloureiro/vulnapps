export function EmptyState({ title, children }) {
  return (
    <div className="empty-state">
      <h3>{title || 'Nothing here'}</h3>
      {children && <p>{children}</p>}
    </div>
  );
}
