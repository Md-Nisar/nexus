import { baseOptions } from '../../config/base-options.js';
import { rbacRoleLifecycle, setupRbacRoleLifecycle } from '../../scenarios/rbac-role-lifecycle.js';
import {
  INTERIM_LATENCY_MS,
  errorThresholds,
  latencyThresholds,
} from '../../thresholds/default-thresholds.js';
import { load } from '../../workloads/load.js';

export const options = {
  ...baseOptions,
  scenarios: {
    rbac_role_lifecycle: { ...load(), exec: 'rbacRoleLifecycle' },
  },
  thresholds: {
    ...errorThresholds,
    ...latencyThresholds('rbac_role_lifecycle', INTERIM_LATENCY_MS),
  },
};

export { setupRbacRoleLifecycle as setup, rbacRoleLifecycle };
