import { sleep } from 'k6';
import { bearer } from '../utils/auth.js';
import { checkResponse } from '../utils/checks.js';
import { get } from '../utils/http.js';

/**
 * UserProfile: an authenticated user loading their own profile (GET /api/v1/users/me).
 *
 * Exercises the full JWT authentication path; the endpoint itself only reads token claims.
 * Expects `data.accessToken` from the test's setup() (see utils/auth.js). Access tokens expire
 * after nexus.jwt.access-token-ttl-seconds (900s), so this scenario is not suitable for a soak
 * test until a token-refresh step is added.
 */
export function userProfile(data) {
  const res = get('/api/v1/users/me', bearer(data.accessToken));
  checkResponse(res, 200, {
    'profile has userId': (body) => typeof body.userId === 'string' && body.userId.length > 0,
  });
  sleep(1);
}
