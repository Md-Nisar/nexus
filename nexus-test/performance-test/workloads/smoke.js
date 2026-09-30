import { config } from '../config/environment.js';

/**
 * Smoke: minimal traffic for a short time. Proves the script, the configuration and the
 * environment work end to end. It is a correctness check, not a measurement.
 */
export function smoke() {
  return {
    executor: 'constant-vus',
    vus: config.workload.vus ?? 1,
    duration: config.workload.duration ?? '30s',
  };
}
