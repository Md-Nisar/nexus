import { config } from './environment.js';

/**
 * k6 options shared by every test. Tests spread this and add their own `scenarios` and
 * `thresholds`.
 */
export const baseOptions = {
  // k6's default summary stops at p(95); p(99) is added so every run reports both.
  summaryTrendStats: ['avg', 'min', 'med', 'max', 'p(90)', 'p(95)', 'p(99)', 'count'],
  tags: { test_env: config.testEnv },
};
