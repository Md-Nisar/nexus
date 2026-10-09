import { baseOptions } from '../../config/base-options.js';
import { config } from '../../config/environment.js';
import {
  attacker,
  cleanupStorm,
  detach,
  holder,
  replay,
  seedStorm,
} from '../../scenarios/detach-refresh-storm.js';
import { errorThresholds } from '../../thresholds/default-thresholds.js';
import { obtainAccessToken } from '../../utils/auth.js';

/**
 * US-018 T-013 merge gate (design §9.7; RC-32.3, RC-43.3, RC-51): detach on a role with 200 holders
 * behind one IP must give ZERO forced logouts, including while an attacker behind the same IP sends
 * invalid refreshes at 100 per minute throughout and replays rotated refresh tokens, and no reuse
 * response may be suppressed. Run it in the production ingress topology, once per deployment shape
 * (direct client IP, and behind the proxy), and record both results.
 *
 * Write-path test: read "Detach-refresh storm" in the README first (backend settings, MailHog,
 * cleanup limits). Timeline, in seconds from the start of the run (after setup()):
 *   0                      attacker starts, steady rate until the end
 *   leadIn                 detach
 *   leadIn + 2             holders (spread over holderSpreadSeconds) and replay victims start
 *   leadIn + 2 + spread + 60   attacker stops
 * Keep the whole run, setup included, well inside the 900 s access-token lifetime.
 */

const { holders, holderSpreadSeconds, attackerPerMinute, replays, leadInSeconds } =
  config.refreshStorm;
const stormStart = leadInSeconds + 2;
const runSeconds = stormStart + holderSpreadSeconds + 60;

export const options = {
  ...baseOptions,
  // Seeding registers, verifies, signs in and rotates every account, then waits out the IP windows.
  setupTimeout: '15m',
  teardownTimeout: '5m',
  scenarios: {
    attacker: {
      executor: 'constant-arrival-rate',
      rate: attackerPerMinute,
      timeUnit: '1m',
      duration: `${runSeconds}s`,
      preAllocatedVUs: 5,
      maxVUs: 20,
      exec: 'attacker',
    },
    detach: {
      executor: 'per-vu-iterations',
      vus: 1,
      iterations: 1,
      startTime: `${leadInSeconds}s`,
      exec: 'detach',
    },
    holders: {
      executor: 'per-vu-iterations',
      vus: holders,
      iterations: 1,
      startTime: `${stormStart}s`,
      maxDuration: `${holderSpreadSeconds + 120}s`,
      exec: 'holder',
    },
    replays: {
      executor: 'per-vu-iterations',
      vus: replays,
      iterations: 1,
      startTime: `${stormStart}s`,
      maxDuration: `${holderSpreadSeconds + 120}s`,
      exec: 'replay',
    },
  },
  thresholds: {
    ...errorThresholds,
    // The gate: nobody is forced to log out, and every holder recovers with its new token.
    storm_forced_logouts: ['count==0'],
    storm_recovery_failed: ['count==0'],
    // RC-51: every replay is answered as reuse (401 AUTH_004), none throttled; the stolen family
    // is dead afterwards.
    storm_replay_not_answered_as_reuse: ['count==0'],
    storm_replay_successor_refreshed: ['count==0'],
    // The attacker really exceeded the failure bucket, so the gate exercised it.
    storm_refresh_failure_throttled: ['value>0'],
  },
};

export function setup() {
  return seedStorm(obtainAccessToken());
}

export function teardown(data) {
  cleanupStorm(data);
}

export { attacker, detach, holder, replay };
