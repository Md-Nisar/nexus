import { baseOptions } from '../../config/base-options.js';
import { config } from '../../config/environment.js';
import { flooder, seedJunkFlood, validUser } from '../../scenarios/refresh-junk-flood.js';
import { errorThresholds } from '../../thresholds/default-thresholds.js';

/**
 * US-018 security review M7 part 2, M-1 (RES-40): cookie-less junk refreshes at 400 per minute from
 * one IP, above the per-IP refresh total of 300 per 60 s, next to valid users. The accepted
 * outcome (see scenarios/refresh-junk-flood.js): valid refreshes are throttled with a valid
 * Retry-After, never answered 401, and succeed again after the flood. Run it in the production
 * ingress topology, once per deployment shape, next to the detach-refresh storm gate; read "Refresh
 * junk flood" in the README for the backend settings (they match the storm gate's).
 *
 * Timeline, in seconds from the start of the run (after setup()):
 *   0                          flood starts, steady rate
 *   5 .. floodSeconds - 25     valid users refresh once each (retrying on 429)
 *   floodSeconds               flood stops
 *   floodSeconds + 65          valid users refresh again and must get 200
 */

const { floodPerMinute, validUsers, floodSeconds } = config.refreshJunkFlood;

export const options = {
  ...baseOptions,
  setupTimeout: '10m',
  scenarios: {
    flooder: {
      executor: 'constant-arrival-rate',
      rate: floodPerMinute,
      timeUnit: '1m',
      duration: `${floodSeconds}s`,
      preAllocatedVUs: 5,
      maxVUs: 30,
      exec: 'flooder',
    },
    validUsers: {
      executor: 'per-vu-iterations',
      vus: validUsers,
      iterations: 1,
      maxDuration: `${floodSeconds + 200}s`,
      exec: 'validUser',
    },
  },
  thresholds: {
    ...errorThresholds,
    junk_forced_logouts: ['count==0'],
    junk_retry_after_invalid: ['count==0'],
    junk_not_recovered: ['count==0'],
  },
};

export function setup() {
  return seedJunkFlood();
}

export { flooder, validUser };
