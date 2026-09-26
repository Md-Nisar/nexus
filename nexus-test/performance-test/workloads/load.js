import { config } from '../config/environment.js';

/**
 * Load: ramp up to the expected concurrency, hold it, ramp down. Answers "does the system meet
 * its thresholds under normal expected traffic?".
 *
 * VUS = steady-state users (default 10), DURATION = hold time (default 5m). The defaults are
 * sized for a laptop or CI runner; set real values per environment.
 */
export function load() {
  const vus = config.workload.vus ?? 10;
  return {
    executor: 'ramping-vus',
    startVUs: 0,
    stages: [
      { duration: '1m', target: vus },
      { duration: config.workload.duration ?? '5m', target: vus },
      { duration: '30s', target: 0 },
    ],
  };
}
