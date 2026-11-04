import test from 'node:test';
import assert from 'node:assert/strict';
import { conservativeF05, chartRuns, formatChartResource, scanType, chartObservations } from './scanChart.js';

const scan = { id: 1, cost: 2, duration: 120, metrics: { tp: 8, fp_groups: 2, fn: 2, pending: 3, weighted_found: 27, weighted_total: 30 } };

test('conservative F0.5 penalizes unresolved items with canonical clustered FP and requires a corpus', () => {
  assert.equal(conservativeF05(scan), 10 / 15.5);
  assert.equal(conservativeF05({ ...scan, metrics: { ...scan.metrics, pending: 0 } }), 10 / 12.5);
  assert.equal(conservativeF05({ metrics: { tp: 0, fp_groups: 0, fn: 5, pending: 0 } }), 0);
  assert.equal(conservativeF05({ metrics: { tp: 0, fp_groups: 1, fn: 0, pending: 0 } }), null);
  assert.equal(conservativeF05({ metrics: { tp: 1, fp_groups: 0, fn: 2 } }), null);
});

test('chart preserves individual runs and zero values, excludes unavailable axes, and converts seconds to minutes', () => {
  const runs = [scan, { ...scan, id: 2, cost: 0 }, { ...scan, id: 3, cost: null }, { ...scan, id: 4, metrics: null }, { ...scan, id: 5, cost: -1, metrics: null }];
  const result = chartRuns(runs, 'cost', 'f05');
  assert.deepEqual(result.points.map(p => p.scan.id), [1, 2]);
  assert.equal(result.points[1].x, 0);
  assert.equal(result.excluded, 3);
  assert.equal(result.missingResource, 2);
  assert.equal(result.missingScore, 2);
  assert.equal(chartRuns([scan], 'duration', 'recall').points[0].x, 2);
  assert.equal(chartRuns([scan], 'cost', 'weighted_rate').points[0].y, 0.9);
});

test('short-duration and tiny-cost ticks remain distinct instead of rounding to zero', () => {
  for (const resource of ['cost', 'duration']) {
    const ticks = [0, .005, .01, .015, .02].map(value => formatChartResource(value, resource));
    assert.equal(new Set(ticks).size, 5);
    assert.notEqual(formatChartResource(.000001, resource), formatChartResource(0, resource));
  }
});


test('weighted chart plots only reviewed scores and excludes awaiting or unscored runs', () => {
  const scored = { ...scan, metrics: { ...scan.metrics, weighted_score_provisional: false, weighted_f05: .42, weighted_f05_upper: .9 } };
  const zero = { ...scored, id: 2, metrics: { ...scored.metrics, weighted_f05: 0 } };
  const runs = chartRuns([scored, zero, scan, { ...scored, metrics: { ...scored.metrics, weighted_score_provisional: true } }], 'cost', 'weighted_f05');
  assert.deepEqual(runs.points.map(point => point.y), [.42, 0]);
  assert.equal(runs.missingScore, 2);
});

const reviewed = (id, changes = {}) => ({
  ...scan, id, scanner_id: 1, scanner_name: 'COS', app_id: 1, scan_type: 'blackbox',
  ...changes,
  metrics: {
    ...scan.metrics, pending: 0, weighted_score_provisional: false,
    weighted_f05: .8, weighted_precision: .9,
    ...(changes.metrics || {}),
  },
});

test('scan type uses recorded type or assessment labels without guessing from scanner or model', () => {
  const labels = {
    1: [{ id: 1, name: ' GrayBox ' }, { id: 10, name: 'model:opus' }],
    2: [{ id: 2, name: 'blackbox' }, { id: 3, name: 'whitebox' }],
  };
  assert.equal(scanType({ id: 1 }, labels), 'greybox');
  assert.equal(scanType({ id: 2 }, labels), 'unknown');
  assert.equal(scanType({ id: 2, scan_type: 'whitebox' }, labels), 'whitebox');
  assert.equal(scanType({ id: 3, scanner_name: 'RIFT', model: 'opus' }, labels), 'unknown');
});

test('grouped chart keeps scanners and scan types separate and weights individual runs equally', () => {
  const runs = [
    reviewed(1, { cost: 2, metrics: { weighted_f05: .2 } }),
    reviewed(2, { cost: 4, app_id: 2, metrics: { weighted_f05: .8 } }),
    reviewed(3, { cost: 6, app_id: 2, metrics: { weighted_f05: .8 } }),
    reviewed(4, { scan_type: 'greybox' }),
    reviewed(5, { scanner_id: 2, scanner_name: 'RIFT', scan_type: 'whitebox' }),
  ];
  const result = chartObservations(runs, {}, { grouped: true });
  assert.equal(result.points.length, 3);
  const blended = result.points.find(point => point.scans.length === 3);
  assert.equal(blended.x, 4);
  assert.ok(Math.abs(blended.y - .6) < 1e-12);
  assert.equal(blended.targetCount, 2);
  assert.equal(blended.xStats.std, 2);
  assert.ok(Math.abs(blended.yStats.std - Math.sqrt(.12)) < 1e-12);
  assert.equal(result.points.find(point => point.type === 'whitebox').yStats.std, null);
});

test('selected labels split scanner variations while unrelated labels do not fragment groups', () => {
  const runs = [reviewed(1), reviewed(2), reviewed(3)];
  const labels = {
    1: [{ id: 10, name: 'model:opus' }, { id: 20, name: 'harness:a' }],
    2: [{ id: 10, name: 'model:opus' }, { id: 21, name: 'harness:b' }],
    3: [{ id: 11, name: 'model:haiku' }],
  };
  assert.equal(chartObservations(runs, labels, { grouped: true }).points.length, 1);
  const split = chartObservations(runs, labels, { grouped: true, splitLabels: ['model:opus'] });
  assert.deepEqual(split.points.map(point => point.scans.map(scan => scan.id)).sort((a, b) => a[0] - b[0]), [[1, 2], [3]]);
});

test('precision recall retains unknown cost and does not average partial cost evidence as complete', () => {
  const runs = [reviewed(1, { cost: 10 }), reviewed(2, { cost: null })];
  const pr = chartObservations(runs, {}, { view: 'pr', grouped: true });
  assert.equal(pr.excluded, 0);
  assert.equal(pr.points[0].cost, null);
  assert.equal(pr.points[0].scans.length, 2);
  assert.equal(pr.points[0].x, .8);
  assert.equal(pr.points[0].y, .8);
  const unresolved = chartObservations([reviewed(3, { metrics: { pending: 3 } })], {}, { view: 'pr' });
  assert.equal(unresolved.points[0].y, 8 / 13);
  const quality = chartObservations(runs, {}, { grouped: true });
  assert.equal(quality.excluded, 1);
  assert.equal(quality.missingResource, 1);
  assert.deepEqual(quality.points[0].scans.map(scan => scan.id), [1]);
});

test('weighted shifts use the same reviewed runs at both endpoints and preserve zero scores', () => {
  const runs = [
    reviewed(1),
    reviewed(2, { metrics: { weighted_score_provisional: true } }),
    reviewed(3, { metrics: { tp: 0, fn: 10, fp_groups: 2, weighted_found: 0, weighted_precision: 0 } }),
  ];
  const plain = chartObservations(runs, {}, { view: 'pr', weight: 'plain', grouped: true });
  assert.equal(plain.points[0].scans.length, 3);
  const shift = chartObservations(runs, {}, { view: 'pr', weight: 'shift', grouped: true });
  assert.equal(shift.excluded, 1);
  assert.deepEqual(shift.points[0].scans.map(scan => scan.id), [1, 3]);
  assert.equal(shift.points[0].plain.x, .4);
  assert.equal(shift.points[0].plain.y, .4);
  assert.equal(shift.points[0].weighted.x, .45);
  assert.equal(shift.points[0].weighted.y, .45);
});
