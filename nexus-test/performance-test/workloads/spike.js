import { config } from '../config/environment.js';

/**
 * Spike: a low baseline, a near-instant jump to peak, then back to baseline. Answers "does a
 * sudden burst break it, and does it recover once the burst passes?".
 *
 * VUS = spike peak (default 50; baseline is 10% of it), DURATION = time held at peak
 * (default 1m).
 */
export function spike() {
  const peak = config.workload.vus ?? 50;
  const baseline = Math.max(1, Math.ceil(peak * 0.1));
  return {
    executor: 'ramping-vus',
    startVUs: 0,
    stages: [
      { duration: '30s', target: baseline },
      { duration: '1m', target: baseline },
      { duration: '10s', target: peak },
      { duration: config.workload.duration ?? '1m', target: peak },
      { duration: '10s', target: baseline },
      { duration: '1m', target: baseline },
      { duration: '30s', target: 0 },
    ],
  };
}
