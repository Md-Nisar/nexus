import { baseOptions } from '../../config/base-options.js';
import { platformHealth } from '../../scenarios/platform-health.js';
import {
  EXAMPLE_LATENCY_MS,
  errorThresholds,
  latencyThresholds,
} from '../../thresholds/default-thresholds.js';
import { soak } from '../../workloads/soak.js';

export const options = {
  ...baseOptions,
  scenarios: {
    platform_health: { ...soak(), exec: 'platformHealth' },
  },
  thresholds: {
    ...errorThresholds,
    ...latencyThresholds('platform_health', EXAMPLE_LATENCY_MS),
  },
};

export { platformHealth };
