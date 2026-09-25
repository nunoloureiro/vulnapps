import test from 'node:test';
import assert from 'node:assert/strict';
import { groupScans } from './scanGroups.js';

test('recorded configurations separate apps, scanner versions, and label sets but ignore label order', () => {
  const base = { app_id: 1, app_name: 'Demo', scanner_name: 'Agent', scanner_version: '1' };
  const scans = [
    { ...base, id: 1 }, { ...base, id: 2 },
    { ...base, id: 3, scanner_version: '2' },
    { ...base, id: 4, app_id: 2 }, { ...base, id: 5 },
    { ...base, id: 6, scanner_version: null },
  ];
  const labels = { 1: [{ name: 'model-a' }, { name: 'greybox' }], 2: [{ name: 'greybox' }, { name: 'model-a' }] };
  for (const id of [3, 4, 6]) labels[id] = labels[1];
  labels[5] = [{ name: 'model-b' }];
  const groups = groupScans(scans, labels, 'configuration');
  assert.equal(groups.length, 5);
  assert.deepEqual(groups.find(group => group.scans.length === 2).scans.map(scan => scan.id), [1, 2]);
  assert.equal(groupScans(scans, labels, 'scanner_version').length, 3);
  assert.equal(groupScans(scans, labels, 'scanner').length, 1);
});

test('label groups overlap without repeating a scan for duplicate label metadata', () => {
  const scans = [{ id: 1 }, { id: 2 }];
  const groups = groupScans(scans, { 1: [{ name: 'a' }, { name: 'a' }, { name: 'b' }] }, 'label');
  assert.equal(groups.length, 3);
  assert.ok(groups.every(group => group.scans.length === 1));
  assert.equal(groupScans(scans, {}, '')[0].scans.length, 2);
});
