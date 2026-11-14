// A scan's cost in USD as shown in the UI: two decimals ($281.35), with
// thousands separators. Stored values keep full precision; cost-per-point is
// formatted separately (it needs more decimals to tell runs apart).
export function formatCost(value, empty = '-') {
  if (value == null || !Number.isFinite(Number(value))) return empty;
  return '$' + Number(value).toLocaleString('en-US', { minimumFractionDigits: 2, maximumFractionDigits: 2 });
}
