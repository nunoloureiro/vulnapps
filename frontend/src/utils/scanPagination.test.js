import test from 'node:test';
import assert from 'node:assert/strict';
import { scanPagination, changeScanParams } from './scanPagination.js';

test('pagination defaults to newest timestamp and rejects invalid URL state', () => {
  const defaults = { page: 1, pageSize: 50, sort: 'date', direction: 'desc' };
  assert.deepEqual(scanPagination(new URLSearchParams()), defaults);
  assert.deepEqual(scanPagination(new URLSearchParams('page=-2&page_size=100000&sort=unknown&direction=unknown')), defaults);
  assert.deepEqual(scanPagination(new URLSearchParams('page=2&page_size=100&sort=cost_per_point&direction=asc')),
    { page: 2, pageSize: 100, sort: 'cost_per_point', direction: 'asc' });
});

test('filters and sorting reset the page while navigation preserves filters and repeated labels', () => {
  const params = new URLSearchParams('page=4&app_id=8&label=blackbox&label=gpt&sort=date');
  const sorted = changeScanParams(params, { sort: 'weighted_found', direction: 'desc' });
  assert.equal(sorted.has('page'), false);
  assert.deepEqual(sorted.getAll('label'), ['blackbox', 'gpt']);
  const page = changeScanParams(sorted, { page: 2 });
  assert.equal(page.get('app_id'), '8');
  assert.equal(page.get('sort'), 'weighted_found');
  assert.equal(page.get('page'), '2');
  assert.equal(changeScanParams(page, { label: ['greybox'] }).has('page'), false);
  assert.equal(changeScanParams(page, { page_size: 100 }).has('page'), false);
  assert.equal(params.get('page'), '4');
});
