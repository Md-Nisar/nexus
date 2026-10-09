import http from 'k6/http';
import exec from 'k6/execution';
import { check, fail, sleep } from 'k6';
import { Counter } from 'k6/metrics';
import { config } from '../config/environment.js';
import { postJson } from '../utils/http.js';
import { awaitVerificationTokens, noJar, refresh, refreshCookie } from './detach-refresh-storm.js';

/**
 * US-018 security review M7 part 2, M-1 (accepted as RES-40): one client IP sends cookie-less
 * junk refreshes above the per-IP refresh total (REFRESH_IP, 300 per 60 s) while valid users
 * behind the same IP refresh. The filter counts junk against that total, so valid refreshes are
 * expected to be answered 429 during the flood. The documented, accepted outcome is:
 * - a valid refresh is answered 200 or 429, never 401: a 429 is a throttle, not a logout;
 * - every 429 carries Retry-After as whole seconds in 1..60, which the SPA honours before
 *   retrying (3 attempts) while keeping the session, mirrored here;
 * - once the flood has stopped and the window has slid, the same user's refresh is 200 with the
 *   session intact.
 *
 * Flows:
 * - flooder: one cookie-less POST /api/v1/auth/refresh per iteration, at floodPerMinute.
 * - validUser: one seeded user; refreshes during the flood (with SPA-style retries), then again
 *   after the flood plus one window.
 */

const PASSWORD = 'Pr3f-Junk-Pass-99!';
const WINDOW_SECONDS = 60;
const SPA_ATTEMPTS = 3;

export const forcedLogouts = new Counter('junk_forced_logouts');
export const retryAfterInvalid = new Counter('junk_retry_after_invalid');
export const notRecovered = new Counter('junk_not_recovered');
export const validThrottled = new Counter('junk_valid_refresh_throttled');
export const validRefreshed = new Counter('junk_valid_refresh_ok');

/** Registers, verifies and signs in the valid users. Call from setup(). */
export function seedJunkFlood() {
  const { validUsers, mailhogUrl } = config.refreshJunkFlood;
  if (!mailhogUrl) {
    fail('Set MAILHOG_URL (e.g. http://localhost:8025) so seeded accounts can be verified');
  }
  const runId = Date.now().toString(36);
  const emails = [];
  for (let i = 0; i < validUsers; i++) {
    emails.push(`perf-junk-${runId}-${i}@example.com`);
    const reg = postJson('/api/v1/auth/register', { email: emails[i], password: PASSWORD });
    if (reg.status !== 201) {
      fail(`Registering account ${i} failed with HTTP ${reg.status}`);
    }
  }
  const tokens = awaitVerificationTokens(mailhogUrl, emails);
  const users = emails.map((email, i) => {
    const verify = postJson('/api/v1/auth/verify-email', { token: tokens[email] });
    if (verify.status !== 200) {
      fail(`Verifying account ${i} failed with HTTP ${verify.status}`);
    }
    const login = postJson('/api/v1/auth/login', { email, password: PASSWORD }, noJar());
    if (login.status !== 200) {
      fail(`Login of account ${i} failed with HTTP ${login.status}; raise the login IP limit`);
    }
    return { refreshToken: refreshCookie(login) };
  });
  // Let the seeding traffic leave the per-IP windows so the measured window holds only the flood.
  sleep(WINDOW_SECONDS + 5);
  return { users };
}

/** One junk refresh: no cookie at all, the cheapest request that still consumes REFRESH_IP. */
export function flooder() {
  const res = http.post(`${config.baseUrl}/api/v1/auth/refresh`, null, {
    jar: new http.CookieJar(),
    tags: { name: '/api/v1/auth/refresh' },
    responseCallback: http.expectedStatuses(401, 429),
  });
  check(res, {
    'junk refresh is refused (401 or 429)': (r) => r.status === 401 || r.status === 429,
  });
}

/** One valid user: refresh during the flood, then again once it is over and the window slid. */
export function validUser(data) {
  const index = exec.vu.idInScenario - 1;
  const { validUsers, floodSeconds } = config.refreshJunkFlood;
  const startedAt = Date.now();
  sleep(5 + (index * (floodSeconds - 30)) / validUsers);

  let token = data.users[index].refreshToken;
  for (let attempt = 1; attempt <= SPA_ATTEMPTS; attempt++) {
    const res = refresh(token, http.expectedStatuses(200, 401, 429));
    if (res.status === 200) {
      validRefreshed.add(1);
      token = refreshCookie(res);
      break;
    }
    if (res.status !== 429) {
      // 401 (or anything else) is a logout in the SPA: the gate's failure condition.
      forcedLogouts.add(1);
      return;
    }
    validThrottled.add(1);
    const wait = Number(res.headers['Retry-After']);
    if (!Number.isInteger(wait) || wait < 1 || wait > WINDOW_SECONDS) {
      retryAfterInvalid.add(1);
      return;
    }
    sleep(wait);
  }

  // Recovery: the flood is over and the sliding window has passed.
  sleep(Math.max(0, floodSeconds + WINDOW_SECONDS + 5 - (Date.now() - startedAt) / 1000));
  const after = refresh(token, http.expectedStatuses(200, 401, 429));
  if (after.status !== 200) {
    notRecovered.add(1);
  }
}
