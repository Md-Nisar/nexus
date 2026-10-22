import http from 'k6/http';
import exec from 'k6/execution';
import { check, fail, sleep } from 'k6';
import { Counter, Gauge } from 'k6/metrics';
import { config } from '../config/environment.js';
import { bearer, scrapeHeaders } from '../utils/auth.js';
import { checkResponse } from '../utils/checks.js';
import { get, postJson } from '../utils/http.js';
import { requireWritableTarget, runPassword } from '../utils/write-scenario.js';

/**
 * US-018 T-013 merge gate: a permission detach on a 200-holder role behind ONE client IP must not
 * log anyone out, even while an attacker behind the same IP keeps failing refreshes and replaying
 * rotated refresh tokens (design §9.7; RC-32.3, RC-43.3, RC-51).
 *
 * This is the suite's first WRITE-PATH scenario. It creates a role, `STORM_HOLDERS + STORM_REPLAYS`
 * users and their assignments, so it needs the backend's mail readable through MailHog (accounts
 * are verified from the emailed token) and a login limit high enough to sign them in from one IP.
 * See "Detach-refresh storm" in the README for the required backend settings and for what cleanup
 * can and cannot undo.
 *
 * Flows (each `exec` target of tests/load/detach-refresh-storm.js):
 * - detach:  an administrator detaches `user:read` from the role (RoleManagementService bumps every
 *            holder's permission epoch).
 * - holder:  one seeded holder. Its next guarded request is rejected as stale (401), it refreshes
 *            once, and the retried request succeeds. Any refresh that is not 200 is a forced
 *            logout, because the SPA clears the session on a refresh 401/429.
 * - attacker: invalid refreshes from the same IP, at a steady rate through the whole run.
 * - replay:  presents a rotated (already used) refresh token of its own victim account. The
 *            response must be the reuse response (401 AUTH_004), never a 429, because reuse
 *            detection must not be gated by the failure bucket (RC-51); the victim's successor
 *            token must then not refresh.
 */

const ROLE_PERMISSIONS = ['role:read', 'user:read'];
const DETACHED_PERMISSION = 'user:read';

export const forcedLogouts = new Counter('storm_forced_logouts');
export const recoveryFailed = new Counter('storm_recovery_failed');
export const staleAccepted = new Counter('storm_stale_token_accepted');
export const replaysNotReuse = new Counter('storm_replay_not_answered_as_reuse');
export const successorStillValid = new Counter('storm_replay_successor_refreshed');
export const throttledFailures = new Gauge('storm_refresh_failure_throttled');

/**
 * Seeds the role, the holders and the replay victims, and returns what the flows need. Call from
 * setup() with an administrator's access token (the dev-seeded TENANT_ADMIN user qualifies).
 */
export function seedStorm(adminToken) {
  requireWritableTarget('detach-refresh-storm');
  const PASSWORD = runPassword();
  const { holders, replays, mailhogUrl } = config.refreshStorm;
  if (!mailhogUrl) {
    fail('Set MAILHOG_URL (e.g. http://localhost:8025) so seeded accounts can be verified');
  }
  const admin = bearer(adminToken);
  const runId = Date.now().toString(36);

  const permissionIds = permissionIdsByName(admin);
  const roleRes = postJson(
    '/api/v1/roles',
    { name: `perf-storm-${runId}`, description: 'k6 detach-refresh-storm run; safe to remove' },
    admin,
  );
  if (roleRes.status !== 201) {
    fail(`Creating the role failed with HTTP ${roleRes.status}`);
  }
  const roleId = roleRes.json('id');
  for (const name of ROLE_PERMISSIONS) {
    const attach = postJson(
      `/api/v1/roles/${roleId}/permissions`,
      { permissionId: permissionIds[name] },
      { ...admin, tags: { name: '/api/v1/roles/{roleId}/permissions' } },
    );
    if (attach.status !== 201) {
      fail(`Attaching ${name} failed with HTTP ${attach.status}`);
    }
  }

  const emails = [];
  for (let i = 0; i < holders + replays; i++) {
    emails.push(`perf-storm-${runId}-${i}@example.com`);
    const reg = postJson('/api/v1/auth/register', { email: emails[i], password: PASSWORD });
    if (reg.status !== 201) {
      fail(`Registering account ${i} failed with HTTP ${reg.status}`);
    }
  }
  const tokens = awaitVerificationTokens(mailhogUrl, emails);

  // Teardown does not run when setup() fails, so a failure below revokes what was assigned so far.
  const assigned = [];
  const accounts = [];
  try {
    emails.forEach((email, i) => accounts.push(seedAccount(email, i)));
  } catch (e) {
    for (const userId of assigned) {
      http.del(`${config.baseUrl}/api/v1/users/${userId}/roles/${roleId}`, null, {
        ...admin,
        tags: { name: '/api/v1/users/{userId}/roles/{roleId}' },
        responseCallback: http.expectedStatuses(204, 404),
      });
    }
    throw e;
  }

  function seedAccount(email, i) {
    const verify = postJson('/api/v1/auth/verify-email', { token: tokens[email] });
    if (verify.status !== 200) {
      fail(`Verifying account ${i} failed with HTTP ${verify.status}`);
    }
    const login = postJson('/api/v1/auth/login', { email, password: PASSWORD }, noJar());
    if (login.status !== 200) {
      fail(`Login of account ${i} failed with HTTP ${login.status}; raise the login IP limit`);
    }
    const userId = login.json('userId');
    const assign = postJson(
      `/api/v1/users/${userId}/roles`,
      { roleId },
      { ...admin, tags: { name: '/api/v1/users/{userId}/roles' } },
    );
    if (assign.status !== 201) {
      fail(`Assigning the role to account ${i} failed with HTTP ${assign.status}`);
    }
    assigned.push(userId);
    // The login token predates the assignment: rotate once so the token carries the role. For a
    // replay victim the pre-rotation token becomes the "stolen" one.
    const loginRefresh = refreshCookie(login);
    const rotated = refresh(loginRefresh);
    if (rotated.status !== 200) {
      fail(`Initial refresh of account ${i} failed with HTTP ${rotated.status}`);
    }
    return {
      userId,
      accessToken: rotated.json('accessToken'),
      refreshToken: refreshCookie(rotated),
      rotatedRefreshToken: loginRefresh,
    };
  }

  // Let the seeding traffic (sign-ins and rotations from this IP) leave the per-IP windows, so the
  // measured window contains only the storm.
  sleep(65);

  return {
    adminToken,
    roleId,
    detachedPermissionId: permissionIds[DETACHED_PERMISSION],
    holders: accounts.slice(0, holders),
    victims: accounts.slice(holders),
    throttledBefore: scrapeThrottled(),
    startedAt: new Date().toISOString(),
  };
}

/** Detaches the permission from the role: the event that turns every holder's token stale. */
export function detach(data) {
  const res = http.del(
    `${config.baseUrl}/api/v1/roles/${data.roleId}/permissions/${data.detachedPermissionId}`,
    null,
    {
      ...bearer(data.adminToken),
      tags: { name: '/api/v1/roles/{roleId}/permissions/{permissionId}' },
    },
  );
  checkResponse(res, 204);
}

/** One holder: stale rejection, one refresh, retry. VU id picks the holder (1-based). */
export function holder(data) {
  const index = exec.vu.idInScenario - 1;
  const account = data.holders[index];
  const { holderSpreadSeconds, holders } = config.refreshStorm;
  sleep((index * holderSpreadSeconds) / holders);

  const stale = get('/api/v1/roles', {
    ...bearer(account.accessToken),
    responseCallback: http.expectedStatuses(200, 401),
  });
  if (stale.status === 200) {
    staleAccepted.add(1);
  }
  const rotated = refresh(account.refreshToken);
  if (rotated.status !== 200) {
    forcedLogouts.add(1);
    return;
  }
  const retry = get('/api/v1/roles', bearer(rotated.json('accessToken')));
  if (!checkResponse(retry, 200)) {
    recoveryFailed.add(1);
  }
}

/** One invalid refresh from the shared IP: a random value that matches no stored token. */
export function attacker() {
  const res = refresh(randomHex(64), http.expectedStatuses(401, 429));
  check(res, { 'attacker is refused (401 or 429)': (r) => r.status === 401 || r.status === 429 });
}

/** One replay of a rotated token, then the victim's successor token. */
export function replay(data) {
  const index = exec.vu.idInScenario - 1;
  const victim = data.victims[index];
  const { holderSpreadSeconds, replays } = config.refreshStorm;
  sleep((index * holderSpreadSeconds) / replays);

  const stolen = refresh(victim.rotatedRefreshToken, http.expectedStatuses(401, 429));
  const answeredAsReuse = stolen.status === 401 && safeJson(stolen, 'code') === 'AUTH_004';
  if (!answeredAsReuse) {
    replaysNotReuse.add(1);
  }
  checkResponse(stolen, 401, { 'replay is AUTH_004': (body) => body.code === 'AUTH_004' });

  // The family is revoked, so the successor must never rotate again (401 or, with the failure
  // bucket exhausted, 429 as an ordinary failure; never 200).
  const successor = refresh(victim.refreshToken, http.expectedStatuses(401, 429));
  if (successor.status === 200) {
    successorStillValid.add(1);
  }
}

/**
 * Revokes the seeded role assignments (the API has no user or role delete, see the README) and
 * records the throttle counter's increase.
 */
export function cleanupStorm(data) {
  const admin = bearer(data.adminToken);
  for (const account of [...data.holders, ...data.victims]) {
    http.del(`${config.baseUrl}/api/v1/users/${account.userId}/roles/${data.roleId}`, null, {
      ...admin,
      tags: { name: '/api/v1/users/{userId}/roles/{roleId}' },
      responseCallback: http.expectedStatuses(204, 404),
    });
  }
  const throttled = scrapeThrottled();
  throttledFailures.add(throttled - data.throttledBefore);
  console.log(
    `detach-refresh-storm finished: run started ${data.startedAt}, ${data.victims.length} replays; ` +
      `expect that many TOKEN_REFRESH_REUSE rows in auth_events since then (README, "Detach-refresh storm")`,
  );
}

export function refresh(refreshToken, expected) {
  return http.post(`${config.baseUrl}/api/v1/auth/refresh`, null, {
    headers: { Cookie: `refresh_token=${refreshToken}` },
    jar: new http.CookieJar(),
    tags: { name: '/api/v1/auth/refresh' },
    ...(expected ? { responseCallback: expected } : {}),
  });
}

// Each request uses its own empty jar so cookies never leak between the simulated browsers.
export function noJar() {
  return { jar: new http.CookieJar() };
}

export function refreshCookie(res) {
  const cookies = res.cookies.refresh_token;
  if (!cookies || cookies.length === 0) {
    fail('Response carried no refresh_token cookie');
  }
  return cookies[0].value;
}

function permissionIdsByName(admin) {
  const res = get('/api/v1/permissions', admin);
  if (res.status !== 200) {
    fail(`Listing permissions failed with HTTP ${res.status}`);
  }
  const ids = {};
  for (const permission of res.json('data')) {
    ids[permission.name] = permission.id;
  }
  for (const name of ROLE_PERMISSIONS) {
    if (!ids[name]) {
      fail(`Permission ${name} not found`);
    }
  }
  return ids;
}

/** Polls MailHog until every address has its verification mail; returns { email: token }. */
export function awaitVerificationTokens(mailhogUrl, emails) {
  const found = {};
  for (let attempt = 0; attempt < 60; attempt++) {
    const res = http.get(`${mailhogUrl}/api/v2/messages?limit=${emails.length * 4 + 50}`, {
      tags: { name: 'mailhog-messages' },
    });
    if (res.status !== 200) {
      fail(`MailHog returned HTTP ${res.status}`);
    }
    for (const message of res.json('items')) {
      const to = (message.Content.Headers.To || []).join(',').toLowerCase();
      const token = /token=([0-9a-f]{64})/.exec(message.Content.Body);
      const email = emails.find((candidate) => to.includes(candidate));
      if (email && token) {
        found[email] = token[1];
      }
    }
    if (emails.every((email) => found[email])) {
      return found;
    }
    sleep(2);
  }
  return fail('Timed out waiting for verification emails in MailHog');
}

function scrapeThrottled() {
  const res = get('/actuator/prometheus', { headers: scrapeHeaders() });
  if (res.status !== 200) {
    fail(`GET /actuator/prometheus returned HTTP ${res.status}`);
  }
  const line = res.body
    .split('\n')
    .find((candidate) => candidate.startsWith('nexus_auth_refresh_failure_throttled_total'));
  // Absent until the first rejection (Micrometer registers the counter lazily).
  return line ? Number(line.trim().split(' ').pop()) : 0;
}

function safeJson(res, selector) {
  try {
    return res.json(selector);
  } catch {
    return undefined;
  }
}

export function randomHex(length) {
  let out = '';
  while (out.length < length) {
    out += Math.floor(Math.random() * 16).toString(16);
  }
  return out;
}
