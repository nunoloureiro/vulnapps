export function scanStatistics(scans, field) {
  const values = scans.map(scan => scan[field]).filter(Number.isFinite);
  const n = values.length;
  if (!n) return { n, mean: null, std: null, min: null, max: null };
  const mean = values.reduce((sum, value) => sum + value, 0) / n;
  const std = n > 1
    ? Math.sqrt(values.reduce((sum, value) => sum + (value - mean) ** 2, 0) / (n - 1))
    : null;
  return { n, mean, std, min: Math.min(...values), max: Math.max(...values) };
}

export function scanQuality(scan) {
  const { tp_count: tp, fp_count: fp, fn_count: fn } = scan;
  const valid = (...values) => values.every(value => Number.isFinite(value) && value >= 0);
  return {
    ...scan,
    precision: valid(tp, fp) && tp + fp > 0 ? tp / (tp + fp) : null,
    recall: valid(tp, fn) && tp + fn > 0 ? tp / (tp + fn) : null,
    f1: valid(tp, fp, fn) && 2 * tp + fp + fn > 0 ? 2 * tp / (2 * tp + fp + fn) : null,
  };
}
