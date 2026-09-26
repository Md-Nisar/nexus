import { config } from '../config/environment.js';

/**
 * Stress: step the load up in thirds to a peak above normal traffic, then recover. Answers
 * "where does it start to degrade, and does it recover?".
 *
 * VUS = peak users (default 30), DURATION = hold time at peak (default 2m).
 */
export function stress() {
  const peak = config.workload.vus ?? 30;
  const step = (fraction) => Math.max(1, Math.ceil(peak * fraction));
  return {
    executor: 'ramping-vus',
    startVUs: 0,
    stages: [
      { duration: '1m', target: step(1 / 3) },
      { duration: '2m', target: step(1 / 3) },
      { duration: '1m', target: step(2 / 3) },
      { duration: '2m', target: step(2 / 3) },
      { duration: '1m', target: peak },
      { duration: config.workload.duration ?? '2m', target: peak },
      { duration: '1m', target: 0 },
    ],
  };
}
