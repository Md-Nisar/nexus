#!/usr/bin/env node
/**
 * Edge ETag smoke (US-020 T-004; design §19.6; ADR-0029; threat model RC-72, D-3). Proves that a
 * strong `ETag` and `If-Match` survive the edge in front of `/api/` without mutating anything:
 *
 *   1. log in through the base URL;
 *   2. find the system role that carries the whole permission catalogue;
 *   3. GET its permission set with `Accept-Encoding: gzip`: the `ETag` must be strong and the body
 *      at least 1,024 bytes (nginx's `gzip_min_length`), otherwise the smoke is not meaningful;
 *   4. PUT the same ids with that `If-Match`: 409 `RBAC_003` (system role, decided before any write);
 *   5. only with `--negative-control`: PUT with `If-Match: W/<tag>`: 428;
 *   then log out, on every exit path once a login succeeded (D-3 (c)).
 *
 * Usage: node etag-edge-smoke.mjs --base <url> [--negative-control]
 *
 * Credentials come only from NEXUS_SMOKE_USER and NEXUS_SMOKE_PASSWORD, never from argv. With
 * both unset and `CI` set, the e2e administrator persona is used (CI persona mode, dev data
 * only). Outside that mode the identity must not be an administrator and must hold nothing beyond
 * role:read and role:write, or the script logs out and exits 2 (D-3 (a)). `--negative-control` is
 * refused unless `CI` is set or the base host is loopback or the compose service (D-3 (b)), so a
 * release check never trips the `precondition_required` alert.
 *
 * Output is step names, HTTP status, problem codes and tag classes only: never a credential,
 * token, cookie, tag value, id or response body. Exit codes: 0 passed, 1 smoke failed, 2 refused.
 */
import { pathToFileURL } from 'node:url';

export const ALLOWED_SMOKE_PERMISSIONS = Object.freeze(['role:read', 'role:write']);
/** nginx `gzip_min_length`: a smaller body would never be compressed, so it proves nothing. */
export const MIN_MEANINGFUL_BYTES = 1024;
/** The compose service of the nginx edge (docker-compose.yml `frontend`). */
const COMPOSE_EDGE_HOST = 'frontend';
const REQUEST_TIMEOUT_MS = 15_000;
const EXIT = Object.freeze({ PASSED: 0, FAILED: 1, REFUSED: 2 });
const ETAGC = '[\\x21\\x23-\\x7e\\x80-\\xff]*';
const STRONG_ETAG = new RegExp(`^"${ETAGC}"$`);
const WEAK_ETAG = new RegExp(`^W/"${ETAGC}"$`);
const PROBLEM_CODE = /^[A-Z][A-Z0-9_]{1,63}$/;

class SmokeError extends Error {
  constructor(message, exitCode = EXIT.FAILED) {
    super(message);
    this.exitCode = exitCode;
  }
}

/** `strong`, `weak`, `missing` or `malformed` (anything else, including a list of tags). */
export function classifyEtag(value) {
  if (value === null || value === undefined || value.trim() === '') return 'missing';
  if (STRONG_ETAG.test(value)) return 'strong';
  if (WEAK_ETAG.test(value)) return 'weak';
  return 'malformed';
}

/** D-3 (a): only a non-administrator holding nothing beyond role:read and role:write may run. */
export function identityVerdict(profile) {
  if (!profile || typeof profile !== 'object' || !Array.isArray(profile.permissions)) {
    return { allowed: false, reason: 'the authorization profile is malformed' };
  }
  if (profile.isAdministrator !== false) {
    return { allowed: false, reason: 'the identity is an administrator' };
  }
  if (profile.permissions.some((p) => !ALLOWED_SMOKE_PERMISSIONS.includes(p))) {
    return {
      allowed: false,
      reason: 'the identity holds a permission beyond role:read and role:write',
    };
  }
  return { allowed: true, reason: 'the identity holds only role:read and role:write' };
}

function ciSet(env) {
  const value = (env.CI ?? '').trim().toLowerCase();
  return value !== '' && value !== 'false' && value !== '0';
}

function isLocalHost(hostname) {
  const host = hostname.replace(/^\[|\]$/g, '').toLowerCase();
  return (
    host === 'localhost' ||
    host === '::1' ||
    host === COMPOSE_EDGE_HOST ||
    /^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(host)
  );
}

/** D-3 (b): the weak-tag control runs only in CI or against a local edge. */
export function negativeControlAllowed(env, base) {
  return ciSet(env) || isLocalHost(new URL(base).hostname);
}

export function isMeaningful(byteLength) {
  return byteLength >= MIN_MEANINGFUL_BYTES;
}

function validateBase(raw) {
  let url;
  try {
    url = new URL(raw);
  } catch {
    throw new SmokeError('--base is not a URL', EXIT.REFUSED);
  }
  if (url.username || url.password) {
    throw new SmokeError('--base must not carry credentials', EXIT.REFUSED);
  }
  if (url.protocol !== 'https:' && !(url.protocol === 'http:' && isLocalHost(url.hostname))) {
    throw new SmokeError('--base must be https unless it is a local edge', EXIT.REFUSED);
  }
  if (url.pathname !== '/' || url.search || url.hash) {
    throw new SmokeError('--base must be an origin, without path, query or fragment', EXIT.REFUSED);
  }
  return url.origin;
}

/** Accepts `--base <url>`, `--base=<url>` and `--negative-control`; never echoes an argument. */
export function parseArgs(argv) {
  let base = null;
  let negativeControl = false;
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === '--negative-control') {
      negativeControl = true;
    } else if (arg === '--base' && i + 1 < argv.length) {
      base = argv[i + 1];
      i += 1;
    } else if (arg.startsWith('--base=')) {
      base = arg.slice('--base='.length);
    } else {
      throw new SmokeError(
        `unsupported argument at position ${i + 1}; credentials are read from NEXUS_SMOKE_USER and NEXUS_SMOKE_PASSWORD only`,
        EXIT.REFUSED,
      );
    }
  }
  if (!base) throw new SmokeError('--base <url> is required', EXIT.REFUSED);
  return { base: validateBase(base), negativeControl };
}

/** `loadPersona` supplies the e2e administrator persona; it is called only in CI persona mode. */
export async function resolveCredentials(env, loadPersona) {
  const user = env.NEXUS_SMOKE_USER ?? '';
  const password = env.NEXUS_SMOKE_PASSWORD ?? '';
  if (user !== '' && password !== '') return { mode: 'env', user, password };
  if (user === '' && password === '' && ciSet(env)) {
    const persona = await loadPersona();
    return { mode: 'ci-persona', user: persona.user, password: persona.password };
  }
  throw new SmokeError(
    'set both NEXUS_SMOKE_USER and NEXUS_SMOKE_PASSWORD (only CI may use the e2e persona)',
    EXIT.REFUSED,
  );
}

async function problemCode(response) {
  try {
    const code = (await response.json())?.code;
    return typeof code === 'string' && PROBLEM_CODE.test(code) ? code : null;
  } catch {
    return null;
  }
}

async function describe(response) {
  const code = await problemCode(response);
  return code ? `${response.status} ${code}` : String(response.status);
}

async function readJson(response, step) {
  try {
    return await response.json();
  } catch {
    throw new SmokeError(`${step}: ${response.status}, body is not JSON`);
  }
}

/**
 * Runs the smoke and returns the exit code. `fetchImpl` and `log` are injectable for the
 * self-test; nothing but fixed text, statuses, problem codes and tag classes is passed to `log`.
 */
export async function runSmoke({ base, negativeControl, env, credentials, fetchImpl, log }) {
  if (negativeControl && !negativeControlAllowed(env, base)) {
    log('refused: --negative-control runs only in CI or against a loopback or compose edge');
    return EXIT.REFUSED;
  }
  const send = async (step, path, init = {}) => {
    try {
      return await fetchImpl(new URL(path, base).href, {
        ...init,
        redirect: 'error',
        signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
      });
    } catch (error) {
      const cause = typeof error?.cause?.code === 'string' ? ` (${error.cause.code})` : '';
      throw new SmokeError(`${step}: request failed${cause}`);
    }
  };

  let session = null;
  let exitCode = EXIT.PASSED;
  try {
    const login = await send('login', '/api/v1/auth/login', {
      method: 'POST',
      headers: { 'content-type': 'application/json', accept: 'application/json' },
      body: JSON.stringify({ email: credentials.user, password: credentials.password }),
    });
    if (login.status !== 200) throw new SmokeError(`login: ${await describe(login)}`);
    const { accessToken } = await readJson(login, 'login');
    if (typeof accessToken !== 'string' || accessToken === '') {
      throw new SmokeError('login: 200 without an access token');
    }
    const refresh = (login.headers.getSetCookie?.() ?? [])
      .map((cookie) => cookie.split(';')[0])
      .find((pair) => pair.startsWith('refresh_token='));
    session = { accessToken, refresh };
    log('login: 200');
    const authorized = (extra = {}) => ({
      accept: 'application/json',
      authorization: `Bearer ${accessToken}`,
      ...extra,
    });

    if (credentials.mode === 'ci-persona') {
      log('identity check: skipped (CI persona mode)');
    } else {
      const me = await send('authorization', '/api/v1/users/me/authorization', {
        headers: authorized(),
      });
      if (me.status !== 200) throw new SmokeError(`authorization: ${await describe(me)}`);
      const verdict = identityVerdict(await readJson(me, 'authorization'));
      if (!verdict.allowed) throw new SmokeError(`refused: ${verdict.reason}`, EXIT.REFUSED);
      log(`authorization: 200, ${verdict.reason}`);
    }

    const catalogue = await send('catalogue', '/api/v1/permissions?size=1', {
      headers: authorized(),
    });
    if (catalogue.status !== 200) throw new SmokeError(`catalogue: ${await describe(catalogue)}`);
    const total = (await readJson(catalogue, 'catalogue'))?.page?.totalElements;
    if (!Number.isInteger(total) || total < 1) throw new SmokeError('catalogue: 200, no total');
    log('catalogue: 200');

    const roles = await send('roles', '/api/v1/roles?size=100', { headers: authorized() });
    if (roles.status !== 200) throw new SmokeError(`roles: ${await describe(roles)}`);
    const role = ((await readJson(roles, 'roles'))?.data ?? []).find(
      (r) => r?.isSystemRole === true && r.permissionCount === total && typeof r.id === 'string',
    );
    if (!role) throw new SmokeError('roles: 200, no system role carries the whole catalogue');
    log('roles: 200, whole-catalogue system role found');

    const setPath = `/api/v1/roles/${encodeURIComponent(role.id)}/permissions`;
    const set = await send('role permissions', setPath, {
      headers: authorized({ 'accept-encoding': 'gzip' }),
    });
    if (set.status !== 200) throw new SmokeError(`role permissions: ${await describe(set)}`);
    const etag = set.headers.get('etag');
    const tagClass = classifyEtag(etag);
    const body = Buffer.from(await set.arrayBuffer());
    log(`role permissions: 200, etag ${tagClass}`);
    if (tagClass !== 'strong') {
      throw new SmokeError(`role permissions: expected a strong etag, got ${tagClass}`);
    }
    if (!isMeaningful(body.byteLength)) {
      throw new SmokeError(
        `smoke not meaningful: the permission set is under ${MIN_MEANINGFUL_BYTES} bytes, below nginx gzip_min_length`,
      );
    }
    let ids;
    try {
      ids = JSON.parse(body.toString('utf8')).data.map((p) => p.id);
    } catch {
      throw new SmokeError('role permissions: 200, body is not a permission list');
    }

    const replace = (ifMatch) =>
      send('replace', setPath, {
        method: 'PUT',
        headers: authorized({ 'content-type': 'application/json', 'if-match': ifMatch }),
        body: JSON.stringify({ permissionIds: ids }),
      });
    const strong = await describe(await replace(etag));
    log(`replace with the strong If-Match: ${strong}`);
    if (strong !== '409 RBAC_003') {
      throw new SmokeError('replace: expected 409 RBAC_003, the tag did not survive the edge');
    }

    if (negativeControl) {
      const weak = await describe(await replace(`W/${etag}`));
      log(`negative control, weak If-Match: ${weak}`);
      if (weak !== '428 PRECONDITION_REQUIRED') {
        throw new SmokeError('negative control: expected 428 PRECONDITION_REQUIRED');
      }
    }
  } catch (error) {
    exitCode = error instanceof SmokeError ? error.exitCode : EXIT.FAILED;
    log(error instanceof SmokeError ? error.message : `failed: unexpected ${error?.name}`);
  } finally {
    if (session) {
      try {
        const logout = await send('logout', '/api/v1/auth/logout', {
          method: 'POST',
          headers: {
            authorization: `Bearer ${session.accessToken}`,
            ...(session.refresh ? { cookie: session.refresh } : {}),
          },
        });
        log(`logout: ${logout.status}`);
        if (logout.status !== 204 && exitCode === EXIT.PASSED) exitCode = EXIT.FAILED;
      } catch (error) {
        log(error instanceof SmokeError ? error.message : 'logout: failed');
        if (exitCode === EXIT.PASSED) exitCode = EXIT.FAILED;
      }
    }
  }
  log(exitCode === EXIT.PASSED ? 'PASS: strong ETag and If-Match survive the edge' : 'FAIL');
  return exitCode;
}

async function loadCiPersona() {
  const { PERSONAS, PERSONA_PASSWORD } = await import('../fixtures/personas.ts');
  return { user: PERSONAS.admin.email, password: PERSONA_PASSWORD };
}

async function main(argv, env) {
  const log = (line) => console.log(`etag-edge-smoke: ${line}`);
  try {
    const { base, negativeControl } = parseArgs(argv);
    const credentials = await resolveCredentials(env, loadCiPersona);
    return await runSmoke({ base, negativeControl, env, credentials, fetchImpl: fetch, log });
  } catch (error) {
    log(error instanceof SmokeError ? error.message : 'failed: unexpected error');
    return error instanceof SmokeError ? error.exitCode : EXIT.FAILED;
  }
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? '').href) {
  process.exitCode = await main(process.argv.slice(2), process.env);
}
