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
  assert.deepEqual(scan([dir], needles), [
    `email blind index found in ${join(dir, 'backend.log')}`,
  ]);
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

test('a URL-encoded, JSON-escaped or entity-encoded address fails', () => {
  for (const form of [
    'person%40example.test',
    'PERSON%40EXAMPLE.TEST',
    'person%2540example.test',
    'person\\u0040example.test',
    'person&#64;example.test',
    'person&#x40;example.test',
    'person&commat;example.test',
  ]) {
    const dir = write('access.log', `GET /v1/users?email=${form} 200\n`);
    assert.equal(scan([dir], needles).length, 1, form);
  }
});

test('a generated registrant address fails in raw and encoded form', () => {
  for (const form of ['e2e-1730000000000@example.com', 'e2e-1730000000000%40example.com']) {
    const dir = write('trace.network', `{"email":"${form}"}`);
    assert.ok(
      scan([dir], needles).some((hit) => hit.startsWith('generated registrant')),
      form,
    );
  }
});

test('an e2e- prefix without a timestamp is not a registrant', () => {
  assert.deepEqual(scan([write('a.log', 'e2e-suite@example.com')], needles), []);
});

test('every embedded report zip is scanned, not only the first', () => {
  const clean = stored('ok.txt', Buffer.from('nothing here')).toString('base64');
  const dirty = stored('trace.network', Buffer.from('person@example.test')).toString('base64');
  const html = `<script>data:application/zip;base64,${clean}</script>
<script>data:application/zip;base64,${dirty}</script>`;
  const dir = write('index.html', html);
  assert.ok(scan([dir], needles).some((hit) => hit.endsWith('index.html!report1!trace.network')));
});

test('a clean embedded report passes', () => {
  const clean = stored('ok.txt', Buffer.from('nothing here')).toString('base64');
  assert.deepEqual(
    scan([write('index.html', `data:application/zip;base64,${clean}`)], needles),
    [],
  );
});

test('a screenshot in the scanned set fails', () => {
  for (const name of ['test-failed-1.png', 'frame.JPEG']) {
    const dir = write(name, Buffer.from([0x89, 0x50, 0x4e, 0x47]));
    assert.deepEqual(scan([dir], needles), [`screenshot found in ${join(dir, name)}`]);
  }
});

test('the text printed around a match never contains another needle', () => {
  const other = blindIndex('person@example.test', KEY);
  const content = `"email":"person@example.test","hmac":"${other}","registrant":"e2e-1700000000000@example.com"`;
  const printed = [];
  const hits = scan([write('trace.json', content)], needles, (context) => printed.push(context));
  assert.ok(hits.length > 0);
  assert.ok(printed.length > 0);
  for (const { before, after } of printed) {
    const text = `${before}${after}`;
    assert.ok(!text.includes('person@example.test'), text);
    assert.ok(!text.includes(other), text);
    assert.ok(!/e2e-\d+@example\.com/.test(text), text);
  }
});
