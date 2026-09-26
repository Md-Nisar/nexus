import { sleep } from 'k6';
import { checkResponse } from '../utils/checks.js';
import { get } from '../utils/http.js';

/**
 * PlatformHealth: a client polling nexus-backend's readiness probe.
 *
 * GET /actuator/health/readiness needs no authentication and no feature flag, so it works in
 * every environment. The aggregate /actuator/health is deliberately not used: it includes
 * security-observability indicators (e.g. rbacZeroActiveAdmins) that report DOWN on a fresh
 * database while the application is serving normally.
 */
export function platformHealth() {
  const res = get('/actuator/health/readiness');
  checkResponse(res, 200, { 'readiness is UP': (body) => body.status === 'UP' });
  sleep(1);
}
