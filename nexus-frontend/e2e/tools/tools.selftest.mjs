/** Self-test for the CI guards: `node --test e2e/tools/tools.selftest.mjs` (US-019 T-027). */
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { assertExecuted } from './assert-executed.mjs';
import {
  classifyEtag,
  identityVerdict,
  isMeaningful,
  negativeControlAllowed,
  parseArgs,
  resolveCredentials,
  runSmoke,
} from './etag-edge-smoke.mjs';
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

// US-020 T-014: the scan's needles come from every PERSONAS entry, so the personas nobody signs in
// as (the assignment targets) are scanned too. Addresses are read from the fixture, never written
// here, and the CLI's output is captured, not printed.
test('the scan CLI flags the address of every persona, including the assignment targets', async () => {
  const { PERSONAS } = await import('../fixtures/personas.ts');
  for (const key of ['roleReaderUserManager', 'auditor', 'targetA', 'targetB']) {
    assert.ok(PERSONAS[key], `persona ${key} is missing from PERSONAS`);
  }
  for (const [key, persona] of Object.entries(PERSONAS)) {
    const dir = write('backend.log', `user ${persona.email} signed in\n`);
    const run = spawnSync(
      process.execPath,
      [fileURLToPath(new URL('./scan-pii.mjs', import.meta.url)), '--hmac-key', KEY, dir],
      { encoding: 'utf8' },
    );
    assert.equal(run.status, 1, `persona ${key} was not flagged`);
  }
});

// ---- US-020 T-004: the edge keeps strong ETags (ADR-0029, RC-72, D-3) ----

/** Removes `#` comments outside quoted strings, keeping line breaks. */
function stripNginxComments(conf) {
  let out = '';
  let quote = null;
  for (let i = 0; i < conf.length; i += 1) {
    const ch = conf[i];
    if (quote) {
      if (ch === '\\') {
        out += ch + (conf[i + 1] ?? '');
        i += 1;
        continue;
      }
      if (ch === quote) quote = null;
      out += ch;
    } else if (ch === '"' || ch === "'") {
      quote = ch;
      out += ch;
    } else if (ch === '#') {
      while (i < conf.length && conf[i] !== '\n') i += 1;
      out += '\n';
    } else {
      out += ch;
    }
  }
  return out;
}

/** The body of the `location <prefix> { ... }` block (exact prefix), or null. */
function locationBlock(conf, prefix) {
  const text = stripNginxComments(conf);
  const escaped = prefix.replace(/[.*+?^${}()|[\]\\/]/g, '\\$&');
  const open = new RegExp(`(^|[\\s;{}])location\\s+${escaped}\\s*\\{`).exec(text);
  if (!open) return null;
  const start = open.index + open[0].length;
  let depth = 1;
  for (let i = start; i < text.length; i += 1) {
    if (text[i] === '{') depth += 1;
    if (text[i] === '}') depth -= 1;
    if (depth === 0) return text.slice(start, i);
  }
  return null;
}

/** True when `directive` (for example `gzip off`) is a statement of the block itself. */
function hasDirective(block, directive) {
  let depth = 0;
  let statement = '';
  for (const ch of block) {
    if (ch === '{') depth += 1;
    if (ch === '}') {
      depth -= 1;
      statement = '';
      continue;
    }
    if (depth > 0) continue;
    if (ch === ';') {
      if (statement.trim().split(/\s+/).join(' ') === directive) return true;
      statement = '';
    } else {
      statement += ch;
    }
  }
  return false;
}

const apiGzipOff = (conf) => {
  const block = locationBlock(conf, '/api/');
  return block !== null && hasDirective(block, 'gzip off');
};

const NGINX_FIXTURE = (apiBody, authBody = 'proxy_pass http://backend:1000/api/v1/auth/;') => `
server {
    gzip on;
    location /api/v1/auth/ {
        ${authBody}
    }
    location /api/ {
        ${apiBody}
    }
}
`;

test('nginx.conf turns gzip off inside location /api/', () => {
  const conf = readFileSync(new URL('../../nginx.conf', import.meta.url), 'utf8');
  assert.ok(apiGzipOff(conf));
  // The auth location and the server level keep compression (ADR-0029 decision 2).
  assert.equal(hasDirective(locationBlock(conf, '/api/v1/auth/'), 'gzip off'), false);
});

test('a config without gzip off in location /api/ fails the static check', () => {
  assert.equal(apiGzipOff(NGINX_FIXTURE('proxy_pass http://backend:1000/api/;')), false);
});

test('gzip off only in a comment or only in the auth location fails the static check', () => {
  assert.equal(
    apiGzipOff(NGINX_FIXTURE('proxy_pass http://backend:1000/api/; # gzip off;')),
    false,
  );
  assert.equal(
    apiGzipOff(NGINX_FIXTURE('proxy_pass http://backend:1000/api/;', 'gzip off;')),
    false,
  );
  assert.equal(apiGzipOff(NGINX_FIXTURE('proxy_pass http://backend:1000/api/;\n gzip off;')), true);
});

test('ETag classification: strong, weak, missing, malformed', () => {
  assert.equal(classifyEtag('"0190a000-v7"'), 'strong');
  assert.equal(classifyEtag('W/"0190a000-v7"'), 'weak');
  assert.equal(classifyEtag(null), 'missing');
  assert.equal(classifyEtag(''), 'missing');
  assert.equal(classifyEtag('0190a000-v7'), 'malformed');
  assert.equal(classifyEtag('"a", "b"'), 'malformed');
});

test('D-3 (a): an administrator or any permission beyond role:read and role:write aborts', () => {
  const profile = (permissions, isAdministrator = false) => ({ permissions, isAdministrator });
  assert.equal(identityVerdict(profile(['role:read', 'role:write'], true)).allowed, false);
  assert.equal(identityVerdict(profile(['role:read', 'role:write', 'audit:read'])).allowed, false);
  assert.equal(identityVerdict(profile(['role:read', 'role:write'])).allowed, true);
  assert.equal(identityVerdict({ permissions: 'role:read' }).allowed, false);
  assert.equal(identityVerdict(null).allowed, false);
});

test('D-3 (b): --negative-control is refused with CI unset against a remote host', () => {
  assert.equal(negativeControlAllowed({}, 'https://edge.nexus.invalid'), false);
  assert.equal(negativeControlAllowed({ CI: 'false' }, 'https://edge.nexus.invalid'), false);
  assert.equal(negativeControlAllowed({ CI: 'true' }, 'https://edge.nexus.invalid'), true);
  for (const base of [
    'http://localhost:2000',
    'http://127.0.0.1:2000',
    'http://[::1]:2000',
    'http://frontend',
  ]) {
    assert.equal(negativeControlAllowed({}, base), true, base);
  }
  assert.equal(negativeControlAllowed({}, 'http://localhost.nexus.invalid'), false);
});

test('a permission set under 1,024 bytes is not meaningful', () => {
  assert.equal(isMeaningful(1023), false);
  assert.equal(isMeaningful(1024), true);
});

test('arguments: only --base and --negative-control, and an unknown value is never echoed', () => {
  assert.deepEqual(parseArgs(['--base', 'http://localhost:2000', '--negative-control']), {
    base: 'http://localhost:2000',
    negativeControl: true,
  });
  assert.deepEqual(parseArgs(['--base=https://edge.nexus.invalid']), {
    base: 'https://edge.nexus.invalid',
    negativeControl: false,
  });
  assert.throws(
    () => parseArgs(['--base', 'http://localhost:2000', '--password', 'hunter2']),
    (e) => {
      assert.ok(!e.message.includes('hunter2'));
      assert.ok(!e.message.includes('--password'));
      return true;
    },
  );
  assert.throws(() => parseArgs([]));
});

test('a base URL with credentials, a path or plain http to a remote host is refused', () => {
  assert.throws(
    () => parseArgs(['--base', 'https://someone:pw@127.0.0.1']),
    (e) => {
      assert.ok(!e.message.includes('pw'));
      return true;
    },
  );
  assert.throws(() => parseArgs(['--base', 'https://edge.nexus.invalid/app']));
  assert.throws(() => parseArgs(['--base', 'http://edge.nexus.invalid']));
});

test('credentials come only from NEXUS_SMOKE_*, or the persona in CI', async () => {
  const persona = async () => ({ user: 'persona-user', password: 'persona-pass' });
  assert.deepEqual(
    await resolveCredentials({ NEXUS_SMOKE_USER: 'u', NEXUS_SMOKE_PASSWORD: 'p' }, persona),
    { mode: 'env', user: 'u', password: 'p' },
  );
  assert.deepEqual(await resolveCredentials({ CI: 'true' }, persona), {
    mode: 'ci-persona',
    user: 'persona-user',
    password: 'persona-pass',
  });
  await assert.rejects(resolveCredentials({}, persona));
  await assert.rejects(resolveCredentials({ CI: 'true', NEXUS_SMOKE_USER: 'u' }, persona));
});

// A fixture edge: answers the smoke's requests the way nginx plus the backend do.
const SECRET = {
  user: 'fixture-smoke-identity',
  password: 'fixture-password-not-real',
  token: 'fixture-access-token-not-real',
  cookie: 'fixture-refresh-cookie-not-real',
  etag: '"fixture-version-tag-1"',
  roleId: '0190a000-0000-7000-8000-00000000a001',
};

function fixtureEdge({
  profile = { permissions: ['role:read', 'role:write'], isAdministrator: false },
  etag = SECRET.etag,
  permissionCount = 9,
  failOn = null,
} = {}) {
  const calls = [];
  const permissions = Array.from({ length: permissionCount }, (_, i) => ({
    id: `0190a000-0000-7000-8000-${String(100 + i).padStart(12, '0')}`,
    name: `fixture:permission-${i}`,
    description: 'A fixture permission with a description long enough to fill the body',
    isSensitive: false,
  }));
  const json = (status, body, headers = {}) =>
    new Response(body === null ? null : JSON.stringify(body), {
      status,
      headers: { 'content-type': 'application/json', ...headers },
    });
  const problem = (status, code) => json(status, { status, code, detail: 'fixture detail text' });
  const fetchImpl = async (url, init = {}) => {
    const { pathname, search } = new URL(url);
    const method = init.method ?? 'GET';
    const headers = new Headers(init.headers);
    calls.push({ method, path: pathname, headers, body: init.body });
    if (failOn === pathname) throw new TypeError('fetch failed');
    const authed = headers.get('authorization') === `Bearer ${SECRET.token}`;
    if (method === 'POST' && pathname === '/api/v1/auth/login') {
      const body = JSON.parse(init.body);
      if (body.email !== SECRET.user || body.password !== SECRET.password) {
        return problem(401, 'AUTH_001');
      }
      return json(
        200,
        { accessToken: SECRET.token, tokenType: 'Bearer', expiresIn: 900, userId: 'u-1' },
        { 'set-cookie': `refresh_token=${SECRET.cookie}; Path=/api/v1/auth; HttpOnly; Secure` },
      );
    }
    if (method === 'POST' && pathname === '/api/v1/auth/logout') {
      return new Response(null, { status: 204 });
    }
    if (!authed) return problem(401, 'AUTH_003');
    if (pathname === '/api/v1/users/me/authorization')
      return json(200, { userId: 'u-1', roles: [], ...profile });
    if (pathname === '/api/v1/permissions') {
      return json(200, { data: permissions.slice(0, 1), page: { totalElements: permissionCount } });
    }
    if (pathname === '/api/v1/roles' && search === '?size=100') {
      return json(200, {
        data: [
          { id: '0190a000-0000-7000-8000-00000000a002', isSystemRole: false, permissionCount },
          {
            id: '0190a000-0000-7000-8000-00000000a003',
            isSystemRole: true,
            permissionCount: permissionCount - 1,
          },
          { id: SECRET.roleId, isSystemRole: true, permissionCount },
        ],
        page: { totalElements: 3 },
      });
    }
    if (pathname === `/api/v1/roles/${SECRET.roleId}/permissions`) {
      if (method === 'GET') return json(200, { data: permissions }, etag ? { etag } : {});
      const ifMatch = headers.get('if-match');
      if (ifMatch === SECRET.etag) return problem(409, 'RBAC_003');
      if (ifMatch?.startsWith('W/')) return problem(428, 'PRECONDITION_REQUIRED');
      return problem(412, 'PRECONDITION_FAILED');
    }
    return problem(404, 'RESOURCE_NOT_FOUND');
  };
  return { calls, fetchImpl };
}

async function fixtureRun(options = {}, run = {}) {
  const edge = fixtureEdge(options);
  const lines = [];
  const code = await runSmoke({
    base: 'http://localhost:2000',
    negativeControl: false,
    env: {},
    credentials: { mode: 'env', user: SECRET.user, password: SECRET.password },
    fetchImpl: edge.fetchImpl,
    log: (line) => lines.push(line),
    ...run,
  });
  const output = lines.join('\n');
  for (const value of [...Object.values(SECRET), SECRET.etag.slice(1, -1)]) {
    assert.ok(!output.includes(value), `output leaks a fixture secret: ${output}`);
  }
  assert.ok(!output.includes('fixture detail text'));
  const loggedOut = edge.calls.some((c) => c.path === '/api/v1/auth/logout');
  const puts = edge.calls.filter((c) => c.method === 'PUT');
  return { code, output, loggedOut, puts, calls: edge.calls };
}

test('fixture run: a strong tag survives, 409 RBAC_003, negative control 428, then logout', async () => {
  const { code, output, loggedOut, puts, calls } = await fixtureRun(
    {},
    { negativeControl: true, env: { CI: 'true' } },
  );
  assert.equal(code, 0, output);
  assert.ok(loggedOut);
  assert.equal(puts.length, 2);
  assert.equal(puts[0].headers.get('if-match'), SECRET.etag);
  assert.equal(puts[1].headers.get('if-match'), `W/${SECRET.etag}`);
  assert.equal(JSON.parse(puts[0].body).permissionIds.length, 9);
  const get = calls.find(
    (c) =>
      c.method === 'GET' && c.path.endsWith('/permissions') && c.path.startsWith('/api/v1/roles/'),
  );
  assert.equal(get.headers.get('accept-encoding'), 'gzip');
  const logout = calls.find((c) => c.path === '/api/v1/auth/logout');
  assert.equal(logout.headers.get('cookie'), `refresh_token=${SECRET.cookie}`);
  assert.match(output, /strong/);
  assert.match(output, /409 RBAC_003/);
  assert.match(output, /428 PRECONDITION_REQUIRED/);
});

test('fixture run: without --negative-control no weak-tag PUT is sent', async () => {
  const { code, puts } = await fixtureRun();
  assert.equal(code, 0);
  assert.equal(puts.length, 1);
});

test('fixture run: an administrator identity aborts after logging out, with no PUT', async () => {
  const { code, loggedOut, puts } = await fixtureRun({
    profile: { permissions: ['role:read', 'role:write'], isAdministrator: true },
  });
  assert.equal(code, 2);
  assert.ok(loggedOut);
  assert.equal(puts.length, 0);
});

test('fixture run: an extra permission aborts after logging out, with no PUT', async () => {
  const { code, loggedOut, puts } = await fixtureRun({
    profile: { permissions: ['role:read', 'role:write', 'user:read'], isAdministrator: false },
  });
  assert.equal(code, 2);
  assert.ok(loggedOut);
  assert.equal(puts.length, 0);
});

test('fixture run: CI persona mode skips the identity check', async () => {
  const { code, calls } = await fixtureRun(
    { profile: { permissions: ['role:read'], isAdministrator: true } },
    {
      env: { CI: 'true' },
      credentials: { mode: 'ci-persona', user: SECRET.user, password: SECRET.password },
    },
  );
  assert.equal(code, 0);
  assert.ok(!calls.some((c) => c.path === '/api/v1/users/me/authorization'));
});

test('fixture run: a body under 1,024 bytes fails as "smoke not meaningful" and logs out', async () => {
  const { code, output, loggedOut, puts } = await fixtureRun({ permissionCount: 2 });
  assert.equal(code, 1);
  assert.match(output, /smoke not meaningful/);
  assert.ok(loggedOut);
  assert.equal(puts.length, 0);
});

test('fixture run: a weak or missing tag fails and logs out', async () => {
  for (const etag of [`W/${SECRET.etag}`, null]) {
    const { code, loggedOut, puts } = await fixtureRun({ etag });
    assert.equal(code, 1, String(etag));
    assert.ok(loggedOut);
    assert.equal(puts.length, 0);
  }
});

test('fixture run: a request that throws mid-run still logs out', async () => {
  const { code, loggedOut } = await fixtureRun({ failOn: '/api/v1/roles' });
  assert.equal(code, 1);
  assert.ok(loggedOut);
});

test('fixture run: refused --negative-control sends no request at all', async () => {
  const { code, output, calls } = await fixtureRun(
    {},
    { base: 'https://edge.nexus.invalid', negativeControl: true, env: {} },
  );
  assert.equal(code, 2);
  assert.match(output, /negative-control/);
  assert.equal(calls.length, 0);
});

test('fixture run: a failed login sends nothing else', async () => {
  const { code, calls } = await fixtureRun(
    {},
    { credentials: { mode: 'env', user: SECRET.user, password: 'wrong-fixture-password' } },
  );
  assert.equal(code, 1);
  assert.equal(calls.length, 1);
});
