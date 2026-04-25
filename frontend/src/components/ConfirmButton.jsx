export function ConfirmButton({ onConfirm, message, className, children, ...props }) {
  const handleClick = () => {
    if (window.confirm(message || 'Are you sure?')) {
      onConfirm();
    }
  };
  return (
    <button onClick={handleClick} className={className} {...props}>
      {children}
    </button>
  );
}
