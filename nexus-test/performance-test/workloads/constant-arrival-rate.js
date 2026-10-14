import { config } from '../config/environment.js';

/**
 * Constant arrival rate: starts iterations at a fixed rate per second, whatever the response time,
 * so the server sees the same request rate on a fast and a slow build. Answers "does the system
 * meet its thresholds at this exact throughput?".
 *
 * RATE = iterations per second, DURATION = run time. Both override the values the test passes
 * (conservative defaults: 10/s for 1m). VUs are allocated on demand up to maxVUs; iterations that
 * find no free VU are counted in k6's `dropped_iterations`, which a test should gate on.
 */
export function constantArrivalRate({ rate = 10, duration = '1m' } = {}) {
  const effectiveRate = config.workload.rate ?? rate;
  return {
    executor: 'constant-arrival-rate',
    rate: effectiveRate,
    timeUnit: '1s',
    duration: config.workload.duration ?? duration,
    preAllocatedVUs: Math.max(10, Math.ceil(effectiveRate / 4)),
    maxVUs: Math.max(50, effectiveRate),
  };
}
