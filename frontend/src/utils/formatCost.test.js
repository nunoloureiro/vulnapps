import test from 'node:test';
import assert from 'node:assert/strict';
import { formatCost } from './formatCost.js';

test('scan cost shows two decimals', () => {
  assert.equal(formatCost(281.35187975), '$281.35');
  assert.equal(formatCost(60.077042), '$60.08');
  assert.equal(formatCost(1234.5), '$1,234.50');
  assert.equal(formatCost(0), '$0.00');
  assert.equal(formatCost(null), '-');
  assert.equal(formatCost(undefined, ''), '');
});
