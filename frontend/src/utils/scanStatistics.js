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
  const metrics = scan.metrics;
  const tp = metrics ? metrics.tp : scan.tp_count;
  const fp = metrics ? metrics.fp_groups : scan.fp_count;
  const fn = metrics ? metrics.fn : scan.fn_count;
  const valid = (...values) => values.every(value => Number.isFinite(value) && value >= 0);
  return {
    ...scan,
    weighted_found: valid(metrics?.weighted_found) ? metrics.weighted_found : null,
    weighted_total: valid(metrics?.weighted_total) ? metrics.weighted_total : null,
    weighted_rate: valid(metrics?.weighted_found, metrics?.weighted_total) && metrics.weighted_total > 0
      ? metrics.weighted_found / metrics.weighted_total : null,
    precision: valid(tp, fp) && tp + fp > 0 ? tp / (tp + fp) : null,
    recall: valid(tp, fn) && tp + fn > 0 ? tp / (tp + fn) : null,
    f1: valid(tp, fp, fn) && 2 * tp + fp + fn > 0 ? 2 * tp / (2 * tp + fp + fn) : null,
  };
}
