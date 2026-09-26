import { baseOptions } from '../../config/base-options.js';
import { platformHealth } from '../../scenarios/platform-health.js';
import {
  EXAMPLE_LATENCY_MS,
  errorThresholds,
  latencyThresholds,
} from '../../thresholds/default-thresholds.js';
import { load } from '../../workloads/load.js';

export const options = {
  ...baseOptions,
  scenarios: {
    platform_health: { ...load(), exec: 'platformHealth' },
  },
  thresholds: {
    ...errorThresholds,
    ...latencyThresholds('platform_health', EXAMPLE_LATENCY_MS),
  },
};

export { platformHealth };
