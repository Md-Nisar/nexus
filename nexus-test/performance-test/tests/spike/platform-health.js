import { baseOptions } from '../../config/base-options.js';
import { platformHealth } from '../../scenarios/platform-health.js';
import {
  EXAMPLE_LATENCY_MS,
  errorThresholds,
  latencyThresholds,
} from '../../thresholds/default-thresholds.js';
import { spike } from '../../workloads/spike.js';

export const options = {
  ...baseOptions,
  scenarios: {
    platform_health: { ...spike(), exec: 'platformHealth' },
  },
  thresholds: {
    ...errorThresholds,
    ...latencyThresholds('platform_health', EXAMPLE_LATENCY_MS),
  },
};

export { platformHealth };
