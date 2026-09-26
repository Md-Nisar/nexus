import { config } from '../config/environment.js';

/**
 * Soak: normal load held for a long time. Surfaces problems that only appear over time, such as
 * memory leaks, connection-pool exhaustion or unbounded caches.
 *
 * VUS = steady-state users (default 10), DURATION = hold time (default 1h).
 */
export function soak() {
  const vus = config.workload.vus ?? 10;
  return {
    executor: 'ramping-vus',
    startVUs: 0,
    stages: [
      { duration: '2m', target: vus },
      { duration: config.workload.duration ?? '1h', target: vus },
      { duration: '2m', target: 0 },
    ],
  };
}
