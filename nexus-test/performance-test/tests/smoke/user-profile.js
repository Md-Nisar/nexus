import { baseOptions } from '../../config/base-options.js';
import { userProfile } from '../../scenarios/user-profile.js';
import {
  EXAMPLE_LATENCY_MS,
  errorThresholds,
  latencyThresholds,
} from '../../thresholds/default-thresholds.js';
import { obtainAccessToken } from '../../utils/auth.js';
import { smoke } from '../../workloads/smoke.js';

export const options = {
  ...baseOptions,
  scenarios: {
    user_profile: { ...smoke(), exec: 'userProfile' },
  },
  thresholds: {
    ...errorThresholds,
    ...latencyThresholds('user_profile', EXAMPLE_LATENCY_MS),
  },
};

export function setup() {
  return { accessToken: obtainAccessToken() };
}

export { userProfile };
