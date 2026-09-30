import { baseOptions } from '../../config/base-options.js';
import { rbacRead } from '../../scenarios/rbac-read.js';
import {
  INTERIM_LATENCY_MS,
  errorThresholds,
  latencyThresholds,
} from '../../thresholds/default-thresholds.js';
import { currentUserId, obtainAccessToken } from '../../utils/auth.js';
import { smoke } from '../../workloads/smoke.js';

export const options = {
  ...baseOptions,
  scenarios: {
    rbac_read: { ...smoke(), exec: 'rbacRead' },
  },
  thresholds: {
    ...errorThresholds,
    ...latencyThresholds('rbac_read', INTERIM_LATENCY_MS),
  },
};

export function setup() {
  const accessToken = obtainAccessToken();
  return { accessToken, userId: currentUserId(accessToken) };
}

export { rbacRead };
