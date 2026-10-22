/** Self-test for the CI guards: `node --test e2e/tools/tools.selftest.mjs` (US-019 T-027). */
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { assertExecuted } from './assert-executed.mjs';
import { blindIndex, needlesFor, scan, zipEntries } from './scan-pii.mjs';

const report = (name) =>
  JSON.parse(readFileSync(new URL(`./fixtures/${name}`, import.meta.url), 'utf8'));

test('a report with executed tests and no skips passes', () => {
  assert.deepEqual(assertExecuted(report('report-ok.json'), 3), { executed: 3, problems: [] });
});

test('a report with one skip fails', () => {
  const { problems } = assertExecuted(report('report-one-skip.json'), 1);
  assert.deepEqual(problems, ['skipped: needs backend']);
});

test('a report with zero tests fails', () => {
  const { problems } = assertExecuted(report('report-zero-tests.json'), 1);
  assert.equal(problems.length, 1);
});

test('fewer tests than the minimum fails', () => {
  assert.equal(assertExecuted(report('report-ok.json'), 4).problems.length, 1);
});

const KEY = 'unit-test-hmac-key-not-a-secret-32-bytes';
const needles = needlesFor(['Person@Example.test'], KEY);

function stored(name, data) {
  const nameBytes = Buffer.from(name);
  const local = Buffer.alloc(30);
  local.writeUInt32LE(0x04034b50, 0);
  local.writeUInt32LE(data.length, 18);
  local.writeUInt32LE(data.length, 22);
  local.writeUInt16LE(nameBytes.length, 26);
  const central = Buffer.alloc(46);
  central.writeUInt32LE(0x02014b50, 0);
  central.writeUInt32LE(data.length, 20);
  central.writeUInt32LE(data.length, 24);
  central.writeUInt16LE(nameBytes.length, 28);
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0);
  eocd.writeUInt16LE(1, 10);
  eocd.writeUInt32LE(46 + nameBytes.length, 12);
  eocd.writeUInt32LE(30 + nameBytes.length + data.length, 16);
  return Buffer.concat([local, nameBytes, data, central, nameBytes, eocd]);
}

function write(name, content) {
  const dir = mkdtempSync(join(tmpdir(), 'pii-'));
  writeFileSync(join(dir, name), content);
  return dir;
}

test('a log containing a blind index fails', () => {
  const dir = write('backend.log', `lookup key=${blindIndex('person@example.test', KEY)}\n`);
  assert.deepEqual(scan([dir], needles), [`email blind index found in ${join(dir, 'backend.log')}`]);
});

test('a log containing an address fails, whatever its case', () => {
  const dir = write('backend.log', 'user PERSON@example.test signed in\n');
  assert.equal(scan([dir], needles).length, 1);
});

test('a clean log passes', () => {
  assert.deepEqual(scan([write('backend.log', 'started\n')], needles), []);
});

test('an address inside a zip entry fails', () => {
  const archive = stored('trace.network', Buffer.from('{"email":"person@example.test"}'));
  assert.equal(zipEntries(archive)[0].name, 'trace.network');
  const dir = write('trace.zip', archive);
  assert.ok(scan([dir], needles).some((hit) => hit.endsWith('trace.zip!trace.network')));
});
