import test from 'node:test';
import assert from 'node:assert/strict';
import { initialScanRequest, scanRequestReducer as reduce, scanResultForKey } from './scanRequest.js';

test('hides unscored or stale rows immediately when the query changes, then reveals the matching response', () => {
  let state = reduce(initialScanRequest, { type: 'start', key: 'list', id: 1 });
  state = reduce(state, { type: 'success', key: 'list', id: 1, data: { scans: [{ id: 1 }] } });
  assert.equal(scanResultForKey(state, 'list').data.scans.length, 1);
  assert.deepEqual(scanResultForKey(state, 'scored'), { loading: true, data: null, error: '' });
  state = reduce(state, { type: 'start', key: 'scored', id: 2 });
  const stale = reduce(state, { type: 'success', key: 'list', id: 1, data: { scans: [{ id: 2 }] } });
  assert.equal(stale, state);
  assert.equal(scanResultForKey(state, 'scored').data, null);
  state = reduce(state, { type: 'success', key: 'scored', id: 2, data: { scans: [{ id: 1, metrics: { tp: 1 } }] } });
  assert.equal(scanResultForKey(state, 'scored').data.scans[0].metrics.tp, 1);
});

test('failures clear stale results and retry stays loading until its own response', () => {
  let state = reduce(initialScanRequest, { type: 'start', key: 'scored', id: 1 });
  state = reduce(state, { type: 'failure', key: 'scored', id: 1, error: 'Unavailable' });
  assert.deepEqual(scanResultForKey(state, 'scored'), { loading: false, data: null, error: 'Unavailable' });
  state = reduce(state, { type: 'start', key: 'scored', id: 2 });
  assert.deepEqual(scanResultForKey(state, 'scored'), { loading: true, data: null, error: '' });
  assert.equal(reduce(state, { type: 'failure', key: 'scored', id: 1, error: 'Old failure' }), state);
});
