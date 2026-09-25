import test from 'node:test';
import assert from 'node:assert/strict';
import { searchableFilterOptions } from './searchableFilterOptions.js';

test('typing a filter query never offers a reset, including when Enter has no match to select', () => {
  const options = [{ value: 'greybox', label: 'Greybox' }, { value: 'blackbox', label: 'Blackbox' }];
  assert.deepEqual(searchableFilterOptions(options, ' GrEy ', 'All labels'), [options[0]]);
  assert.deepEqual(searchableFilterOptions(options, 'missing-label', 'All labels'), []);
  assert.deepEqual(searchableFilterOptions(options, 'All labels', 'All labels'), []);
  assert.deepEqual(searchableFilterOptions(options, '   ', 'All labels'), [{ value: '', label: 'All labels' }, ...options]);
});
