export function LabelBadge({ label, onRemove }) {
  const style = {
    background: `${label.color}1a`,
    color: label.color,
    border: `1px solid ${label.color}40`,
  };
  return (
    <span className="label-badge" style={style}>
      {label.name}
      {onRemove && (
        <button className="label-remove" onClick={() => onRemove(label.id)}>&times;</button>
      )}
    </span>
  );
}
