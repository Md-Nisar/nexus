#!/usr/bin/env node
import { readFileSync } from 'node:fs';
import { decide } from './cache-benchmark-verdict.js';

/**
 * Applies the B6 rule to k6 summary exports (US-018 T-023).
 *
 *   node utils/cache-benchmark-verdict-cli.mjs \
 *     --on results/on-1.json,results/on-2.json,results/on-3.json \
 *     --off results/off-1.json,results/off-2.json,results/off-3.json \
 *     [--qps-on 120,118,121 --qps-off 190,187,192]
 *
 * The summary files come from `k6 run --summary-export=<file> tests/load/permission-cache-benchmark.js`.
 * `--qps-*` are the MySQL queries per second attributable to minting during each run (for example
 * the `Questions` delta from SHOW GLOBAL STATUS over the run window, minus the idle baseline).
 */

const METRIC = 'http_req_duration{name:/api/v1/auth/refresh}';

function argument(name) {
  const at = process.argv.indexOf(`--${name}`);
  return at === -1 ? undefined : process.argv[at + 1];
}

function numbers(list) {
  return list ? list.split(',').map(Number) : [];
}

function p95FromSummary(file) {
  const metric = JSON.parse(readFileSync(file, 'utf8')).metrics?.[METRIC];
  // k6 exports the percentile either at the top level or under `values`, depending on its version.
  const value = metric?.['p(95)'] ?? metric?.values?.['p(95)'];
  if (typeof value !== 'number') {
    throw new Error(`${file} has no ${METRIC} p(95)`);
  }
  return value;
}

const on = argument('on');
const off = argument('off');
if (!on || !off) {
  console.error('Usage: --on <summary,...> --off <summary,...> [--qps-on n,... --qps-off n,...]');
  process.exit(2);
}

const result = decide({
  p95OnMs: on.split(',').map(p95FromSummary),
  p95OffMs: off.split(',').map(p95FromSummary),
  qpsOn: numbers(argument('qps-on')),
  qpsOff: numbers(argument('qps-off')),
});
console.log(result.reasons.join('\n'));
console.log(`DECISION: ${result.decision.toUpperCase()}`);
