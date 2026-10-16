import http from 'k6/http';
import exec from 'k6/execution';
import { fail } from 'k6';
import { Counter } from 'k6/metrics';
import { config } from '../config/environment.js';
import { bearer } from '../utils/auth.js';
import { checkResponse } from '../utils/checks.js';
import { get, postJson } from '../utils/http.js';
import { requireWritableTarget, runPassword } from '../utils/write-scenario.js';
import { awaitVerificationTokens, noJar, refresh, refreshCookie } from './detach-refresh-storm.js';

/**
 * US-018 T-023 (B6): steady token refresh by accounts that hold 1 to 5 roles, the traffic the
 * permission cache is meant to speed up (design §10.6). Every refresh mints a token, and minting
 * resolves the account's roles and permissions: from the cache when it is on, from MySQL when it
 * is off.
 *
 * Write path, like detach-refresh-storm.js: it registers `CACHE_BENCH_ACCOUNTS` accounts and
 * assigns them five roles of growing size, so read "Permission cache benchmark" in the README
 * first (backend settings, MailHog, the per-IP refresh limit that must be raised).
 *
 * Account i holds roles 0..(i mod 5), so the population is evenly 1, 2, 3, 4 and 5 roles. A
 * rotated refresh token is single-use, so an account is refreshed by exactly one VU (VU k owns the
 * accounts with index mod VUs equal to k) and keeps its newest token in that VU's memory.
 */

const ROLE_PERMISSIONS = [
  ['user:read'],
  ['user:read', 'role:read'],
  ['user:read', 'role:read', 'audit:read'],
  ['user:read', 'role:read', 'audit:read', 'tenant:read'],
  ['user:read', 'role:read', 'audit:read', 'tenant:read', 'role:write'],
];

export const refreshFailed = new Counter('cache_bench_refresh_failed');

/** Seeds the roles and accounts. Call from setup() with an administrator's access token. */
export function seedRefreshAccounts(adminToken) {
  requireWritableTarget('permission-cache-benchmark');
  const { accounts, mailhogUrl } = config.cacheBenchmark;
  if (!mailhogUrl) {
    fail('Set MAILHOG_URL (e.g. http://localhost:8025) so seeded accounts can be verified');
  }
  const PASSWORD = runPassword();
  const admin = bearer(adminToken);
  const runId = Date.now().toString(36);

  const permissionIds = {};
  const listed = get('/api/v1/permissions', admin);
  if (listed.status !== 200) {
    fail(`Listing permissions failed with HTTP ${listed.status}`);
  }
  for (const permission of listed.json('data')) {
    permissionIds[permission.name] = permission.id;
  }

  const roleIds = ROLE_PERMISSIONS.map((names, k) => {
    const created = postJson(
      '/api/v1/roles',
      {
        name: `perf-cache-${runId}-${k}`,
        description: 'k6 permission-cache benchmark; safe to remove',
      },
      admin,
    );
    if (created.status !== 201) {
      fail(`Creating role ${k} failed with HTTP ${created.status}`);
    }
    const roleId = created.json('id');
    for (const name of names) {
      const attach = postJson(
        `/api/v1/roles/${roleId}/permissions`,
        { permissionId: permissionIds[name] },
        { ...admin, tags: { name: '/api/v1/roles/{roleId}/permissions' } },
      );
      if (attach.status !== 201) {
        fail(`Attaching ${name} to role ${k} failed with HTTP ${attach.status}`);
      }
    }
    return roleId;
  });

  const emails = [];
  for (let i = 0; i < accounts; i++) {
    emails.push(`perf-cache-${runId}-${i}@example.com`);
    const reg = postJson('/api/v1/auth/register', { email: emails[i], password: PASSWORD });
    if (reg.status !== 201) {
      fail(`Registering account ${i} failed with HTTP ${reg.status}`);
    }
  }
  const tokens = awaitVerificationTokens(mailhogUrl, emails);

  const seeded = [];
  emails.forEach((email, i) => {
    const verify = postJson('/api/v1/auth/verify-email', { token: tokens[email] });
    if (verify.status !== 200) {
      fail(`Verifying account ${i} failed with HTTP ${verify.status}`);
    }
    const login = postJson('/api/v1/auth/login', { email, password: PASSWORD }, noJar());
    if (login.status !== 200) {
      fail(`Login of account ${i} failed with HTTP ${login.status}; raise the login IP limit`);
    }
    const userId = login.json('userId');
    const held = roleIds.slice(0, (i % ROLE_PERMISSIONS.length) + 1);
    for (const roleId of held) {
      const assign = postJson(
        `/api/v1/users/${userId}/roles`,
        { roleId },
        { ...admin, tags: { name: '/api/v1/users/{userId}/roles' } },
      );
      if (assign.status !== 201) {
        fail(`Assigning a role to account ${i} failed with HTTP ${assign.status}`);
      }
    }
    // The login token predates the assignments: rotate once so refreshes start from a live family.
    const rotated = refresh(refreshCookie(login));
    if (rotated.status !== 200) {
      fail(`Initial refresh of account ${i} failed with HTTP ${rotated.status}`);
    }
    seeded.push({ userId, roleIds: held, refreshToken: refreshCookie(rotated) });
  });

  return { adminToken, accounts: seeded, startedAt: new Date().toISOString() };
}

// Per-VU state: k6 gives every VU its own copy of module-level variables.
let owned;
let next = 0;

/** One refresh by the next account this VU owns; the new token replaces the used one. */
export function refreshOne(data) {
  if (!owned) {
    const vus = config.cacheBenchmark.vus;
    const index = exec.vu.idInScenario - 1;
    owned = data.accounts.map((account) => ({ ...account })).filter((_, i) => i % vus === index);
    if (owned.length === 0) {
      fail('More VUs than accounts: raise CACHE_BENCH_ACCOUNTS or lower CACHE_BENCH_VUS');
    }
  }
  const account = owned[next++ % owned.length];
  const res = refresh(account.refreshToken);
  if (!checkResponse(res, 200)) {
    refreshFailed.add(1);
    return;
  }
  account.refreshToken = refreshCookie(res);
}

/** Revokes the seeded assignments (the API has no user or role delete, see the README). */
export function cleanupRefreshAccounts(data) {
  const admin = bearer(data.adminToken);
  for (const account of data.accounts) {
    for (const roleId of account.roleIds) {
      http.del(`${config.baseUrl}/api/v1/users/${account.userId}/roles/${roleId}`, null, {
        ...admin,
        tags: { name: '/api/v1/users/{userId}/roles/{roleId}' },
        responseCallback: http.expectedStatuses(204, 404),
      });
    }
  }
  console.log(
    `permission-cache-benchmark finished (arm=${config.cacheBenchmark.arm}): run started ` +
      `${data.startedAt}; ${data.accounts.length} accounts remain registered`,
  );
}
