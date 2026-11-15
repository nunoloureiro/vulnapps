import test from 'node:test';
import assert from 'node:assert/strict';
import { groupBreaksAfter } from './compareGroups.js';

test('an empty slot in ?scans= puts a break after the previous scan', () => {
  assert.deepEqual([...groupBreaksAfter('1592,1594,,1466')], [1594]);
  assert.deepEqual([...groupBreaksAfter('1,,2,,,3')], [1, 2]);
  assert.deepEqual([...groupBreaksAfter(',1,2,')], [], 'leading/trailing empties draw nothing');
  assert.deepEqual([...groupBreaksAfter('1,2,3')], []);
  assert.deepEqual([...groupBreaksAfter('')], []);
});
