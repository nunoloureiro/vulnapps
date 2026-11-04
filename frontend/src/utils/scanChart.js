import { scanQuality, scanStatistics } from './scanStatistics.js';

export const chartMetrics = {
  weighted_f05: 'Weighted F₀.₅',
  f05: 'F₀.₅ (conservative)',
  weighted_rate: 'Weighted detection',
  weighted_precision: 'Weighted precision',
  precision: 'Precision',
  recall: 'Recall',
  f1: 'F1',
};
export const chartResources = { cost: 'Cost (USD)', duration: 'Duration (minutes)' };

export function conservativeF05(scan) {
  const { tp, fp_groups: fp, fn, pending } = scan.metrics || {};
  if (![tp, fp, fn, pending].every(value => Number.isFinite(value) && value >= 0) || tp + fn === 0) return null;
  return 1.25 * tp / (1.25 * tp + 0.25 * fn + fp + pending);
}

export function chartRuns(scans, resource, metric) {
  const points = [];
  let missingResource = 0;
  let missingScore = 0;
  for (const scan of scans) {
    const rawX = scan[resource];
    const y = metric === 'f05' ? conservativeF05(scan) : scan.metrics ? scanQuality(scan)[metric] : null;
    const validX = Number.isFinite(rawX) && rawX >= 0;
    const validY = Number.isFinite(y) && y >= 0 && y <= 1;
    if (!validX) missingResource++;
    if (!validY) missingScore++;
    if (validX && validY) points.push({ scan, x: resource === 'duration' ? rawX / 60 : rawX, y });
  }
  return { points, missingResource, missingScore, excluded: scans.length - points.length };
}

export function scannerColor(name) {
  let hash = 0;
  for (const character of name || 'Unknown scanner') hash = ((hash * 31) + character.codePointAt(0)) >>> 0;
  return `hsl(${hash % 360} 75% 65%)`;
}

export function formatChartResource(value, resource) {
  const number = value.toLocaleString(undefined, { maximumSignificantDigits: 6 });
  return resource === 'cost' ? `$${number}` : `${number} min`;
}

const validScore = value => Number.isFinite(value) && value >= 0 && value <= 1;
const validResource = value => Number.isFinite(value) && value >= 0;
const normalizeType = value => {
  const type = String(value || '').trim().toLowerCase().replace('graybox', 'greybox');
  return ['blackbox', 'greybox', 'whitebox'].includes(type) ? type : null;
};

export function scanType(scan, labelsMap = {}) {
  if (scan.scan_type) return normalizeType(scan.scan_type) || 'unknown';
  const types = [...new Set((labelsMap[scan.id] || []).map(label => normalizeType(label.name)).filter(Boolean))];
  return types.length === 1 ? types[0] : 'unknown';
}

export function chartObservations(scans, labelsMap = {}, {
  view = 'quality', resource = 'cost', metric = 'weighted_f05', weight = 'plain', grouped = false, splitLabels = [],
} = {}) {
  const buckets = new Map();
  let missingResource = 0, missingScore = 0, excluded = 0;
  const labelNames = [...new Set(splitLabels)].sort();
  for (const scan of scans) {
    const quality = scanQuality(scan);
    const { tp, fp_groups: fp, pending } = scan.metrics || {};
    const precision = [tp, fp, pending].every(validResource) && tp + fp + pending > 0 ? tp / (tp + fp + pending) : null;
    const plain = { x: quality.recall, y: precision };
    const weighted = { x: scan.metrics?.weighted_score_provisional === false ? quality.weighted_rate : null, y: quality.weighted_precision };
    const pair = weight === 'plain' ? plain : weighted;
    const rawResource = scan[resource];
    const x = view === 'pr' ? pair.x : validResource(rawResource) ? rawResource / (resource === 'duration' ? 60 : 1) : null;
    const y = view === 'pr' ? pair.y : metric === 'f05' ? conservativeF05(scan) : quality[metric];
    const availableResource = view === 'pr' || validResource(x);
    const availableScore = validScore(y) && (view !== 'pr' || validScore(x))
      && (view !== 'pr' || weight !== 'shift' || validScore(plain.x) && validScore(plain.y));
    if (!availableResource) missingResource++;
    if (!availableScore) missingScore++;
    if (!availableResource || !availableScore) { excluded++; continue; }
    const scanner = scan.scanner_name || 'Unknown scanner';
    const type = scanType(scan, labelsMap);
    const membership = labelNames.map(name => (labelsMap[scan.id] || []).some(label => label.name === name));
    const id = grouped ? JSON.stringify([scan.scanner_id ?? scanner, type, labelNames, membership]) : String(scan.id);
    if (!buckets.has(id)) buckets.set(id, { id, scanner, type, name: grouped
      ? [scanner, type, ...(labelNames.length ? [labelNames.filter((name, i) => membership[i]).join(', ') || 'Other variations'] : [])].join(' · ')
      : `#${scan.id} · ${scanner} · ${type} · ${scan.app_name || 'Unknown app'}`, rows: [] });
    buckets.get(id).rows.push({ scan, x, y, plain, weighted, cost: validResource(scan.cost) ? scan.cost : null });
  }
  const meanPair = (rows, key) => {
    const paired = rows.filter(row => validScore(row[key].x) && validScore(row[key].y));
    return { x: scanStatistics(paired.map(row => row[key]), 'x').mean, y: scanStatistics(paired.map(row => row[key]), 'y').mean };
  };
  const points = [...buckets.values()].map(({ rows, ...point }) => ({
    ...point, scans: rows.map(row => row.scan), x: scanStatistics(rows, 'x').mean, y: scanStatistics(rows, 'y').mean,
    xStats: scanStatistics(rows, 'x'), yStats: scanStatistics(rows, 'y'), plain: meanPair(rows, 'plain'), weighted: meanPair(rows, 'weighted'),
    cost: rows.every(row => row.cost !== null) ? scanStatistics(rows, 'cost').mean : null,
    targetCount: new Set(rows.map(row => row.scan.app_id ?? `${row.scan.app_name}|${row.scan.app_version || ''}`)).size,
  }));
  return { points, excluded, missingResource, missingScore };
}
