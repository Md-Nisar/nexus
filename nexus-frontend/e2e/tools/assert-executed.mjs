#!/usr/bin/env node
/**
 * Fails when a Playwright JSON report shows any skipped test, or fewer executed tests than the
 * expected minimum (US-019 T-027, R6). A suite that skips or runs nothing must never read green.
 *
 * Usage: node assert-executed.mjs <report.json> --min <count>
 */
import { readFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';

const EXECUTED = new Set(['expected', 'unexpected', 'flaky']);

function* tests(suite) {
  for (const spec of suite.specs ?? []) {
    for (const test of spec.tests ?? []) yield { title: spec.title, status: test.status };
  }
  for (const child of suite.suites ?? []) yield* tests(child);
}

export function assertExecuted(report, min) {
  const problems = [];
  let executed = 0;
  for (const root of report.suites ?? []) {
    for (const { title, status } of tests(root)) {
      if (EXECUTED.has(status)) executed += 1;
      if (status === 'skipped') problems.push(`skipped: ${title}`);
    }
  }
  if (executed < min) problems.push(`executed ${executed} tests, expected at least ${min}`);
  return { executed, problems };
}

function main(argv) {
  const [file, flag, value] = argv;
  const min = Number(value);
  if (!file || flag !== '--min' || !Number.isInteger(min) || min < 1) {
    console.error('Usage: assert-executed.mjs <report.json> --min <count>');
    return 2;
  }
  const { executed, problems } = assertExecuted(JSON.parse(readFileSync(file, 'utf8')), min);
  if (problems.length > 0) {
    for (const problem of problems) console.error(problem);
    return 1;
  }
  console.log(`${executed} tests executed, 0 skipped (minimum ${min}).`);
  return 0;
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? '').href) {
  process.exitCode = main(process.argv.slice(2));
}
