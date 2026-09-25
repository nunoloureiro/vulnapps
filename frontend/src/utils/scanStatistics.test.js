import test from 'node:test';
import assert from 'node:assert/strict';
import { scanStatistics, scanQuality } from './scanStatistics.js';

const summarize = values => scanStatistics(values.map(tp_count => ({ tp_count })), 'tp_count');

test('summarizes observed scan counts with sample standard deviation, retaining zero and excluding missing data', () => {
  assert.deepEqual(summarize([0, 4, 8, null, undefined, NaN, Infinity]), {
    n: 3, mean: 4, std: 4, min: 0, max: 8,
  });
});

test('distinguishes no observations, a single scan, and constant repeated scans', () => {
  assert.deepEqual(summarize([null]), { n: 0, mean: null, std: null, min: null, max: null });
  assert.deepEqual(summarize([7]), { n: 1, mean: 7, std: null, min: 7, max: 7 });
  assert.deepEqual(summarize([7, 7]), { n: 2, mean: 7, std: 0, min: 7, max: 7 });
});

test('computes per-scan quality and excludes undefined denominators rather than manufacturing scores', () => {
  const scan = scanQuality({ tp_count: 3, fp_count: 1, fn_count: 2 });
  assert.equal(scan.precision, 0.75);
  assert.equal(scan.recall, 0.6);
  assert.equal(scan.f1, 2 / 3);
  const empty = scanQuality({ tp_count: 0, fp_count: 0, fn_count: 0 });
  assert.equal(empty.precision, null);
  assert.equal(empty.recall, null);
  assert.equal(empty.f1, null);
  const missing = scanQuality({ tp_count: 0, fp_count: null, fn_count: 4 });
  assert.equal(missing.precision, null);
  assert.equal(missing.recall, 0);
  assert.equal(missing.f1, null);
  const runs = [scanQuality({ tp_count: 1, fp_count: 0, fn_count: 0 }), scanQuality({ tp_count: 1, fp_count: 9, fn_count: 0 })];
  assert.equal(scanStatistics(runs, 'precision').mean, 0.55);
});

test('weighted detection uses canonical impact points, including fractional credit, with no count fallback', () => {
  const scan = scanQuality({ tp_count: 9, fp_count: 0, fn_count: 1,
    metrics: { tp: 1, fp_groups: 1, fn: 3, weighted_found: 13.5, weighted_total: 30 } });
  assert.equal(scan.weighted_rate, 0.45);
  assert.equal(scan.weighted_found, 13.5);
  assert.equal(scan.recall, 0.25);
  assert.equal(scan.precision, 0.5);
  assert.equal(scanQuality({ tp_count: 9, fn_count: 1 }).weighted_rate, null);
  assert.equal(scanQuality({ metrics: { weighted_found: 0, weighted_total: 0 } }).weighted_rate, null);
  assert.equal(scanQuality({ metrics: { weighted_found: 0, weighted_total: 30 } }).weighted_rate, 0);
});
