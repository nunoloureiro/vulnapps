import test from 'node:test';
import assert from 'node:assert/strict';
import { compareQuery } from './compareQuery.js';

test('title comes first and the scans list keeps its commas and gaps', () => {
  assert.equal(compareQuery('Greybox vs blackbox', '1413,1594,,1466'),
    '?title=Greybox%20vs%20blackbox&scans=1413,1594,,1466');
  assert.equal(compareQuery('', '1,2'), '?scans=1,2', 'no title -> no title param');
  assert.equal(compareQuery('  ', '1,2'), '?scans=1,2', 'blank title is dropped');
  assert.equal(compareQuery('A&B=C', '1'), '?title=A%26B%3DC&scans=1', 'title is URL-encoded');
  assert.equal(compareQuery('Only title', ''), '?title=Only%20title');
  assert.equal(compareQuery('', ''), '');
});
