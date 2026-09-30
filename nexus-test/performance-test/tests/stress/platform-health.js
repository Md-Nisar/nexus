import { baseOptions } from '../../config/base-options.js';
import { platformHealth } from '../../scenarios/platform-health.js';
import {
  EXAMPLE_LATENCY_MS,
  errorThresholds,
  latencyThresholds,
} from '../../thresholds/default-thresholds.js';
import { stress } from '../../workloads/stress.js';

export const options = {
  ...baseOptions,
  scenarios: {
    platform_health: { ...stress(), exec: 'platformHealth' },
  },
  thresholds: {
    ...errorThresholds,
    ...latencyThresholds('platform_health', EXAMPLE_LATENCY_MS),
  },
};

export { platformHealth };
