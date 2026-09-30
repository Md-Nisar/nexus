import { fail } from 'k6';
import { config } from '../config/environment.js';
import { get, postJson } from './http.js';

/**
 * Returns a bearer access token: ACCESS_TOKEN if set, otherwise one obtained by logging in as
 * PERF_USER_EMAIL / PERF_USER_PASSWORD.
 *
 * Call this from a test's setup(), once per run — never from the VU loop. POST /api/v1/auth/login
 * is rate limited per client IP (nexus.security.rate-limit.ip-max-attempts), so logging in on every
 * iteration would measure the rate limiter, not the application.
 */
export function obtainAccessToken() {
  const { accessToken, email, password } = config.auth;
  if (accessToken) {
    return accessToken;
  }
  if (!email || !password) {
    fail('Set ACCESS_TOKEN, or PERF_USER_EMAIL and PERF_USER_PASSWORD, for authenticated tests');
  }

  const res = postJson('/api/v1/auth/login', { email, password });
  if (res.status !== 200) {
    fail(`Login failed with HTTP ${res.status}; check PERF_USER_EMAIL / PERF_USER_PASSWORD`);
  }
  return res.json('accessToken');
}

/**
 * Returns the id of the user the access token belongs to (GET /api/v1/users/me), for scenarios
 * that call user-scoped endpoints such as /api/v1/users/{userId}/roles. Call it from setup().
 */
export function currentUserId(accessToken) {
  const res = get('/api/v1/users/me', bearer(accessToken));
  if (res.status !== 200) {
    fail(`GET /api/v1/users/me failed with HTTP ${res.status}; is the access token valid?`);
  }
  return res.json('userId');
}

export function bearer(accessToken) {
  return { headers: { Authorization: `Bearer ${accessToken}` } };
}
