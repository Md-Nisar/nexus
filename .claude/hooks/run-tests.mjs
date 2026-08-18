#!/usr/bin/env node
// Stop — runs the fast unit tests for whichever side has uncommitted source changes,
// so a session never ends on red. Doc/config-only sessions exit instantly.
//
// Scope is deliberately limited to fast feedback: backend unit tests (-DskipITs) and
// frontend Vitest. Integration tests, coverage gates and lint are enforced by
// /pre-pr-check, the pre-push git hook, and CI. Exit 2 → blocks stop until fixed.

import { readStdin, changedFiles, side, run } from './_hooklib.mjs';
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { resolve, join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

// Derive repo root from this file's location (.claude/hooks/ → .claude/ → repo root)
// so the hook works regardless of which sub-directory Claude Code was started from.
const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..');

const backendDir = resolve(repoRoot, 'nexus-backend');
const frontendDir = resolve(repoRoot, 'nexus-frontend');

/**
 * Returns true when target/surefire-reports XML files are all recent (< maxAgeSeconds)
 * and show zero failures/errors. Used to skip a redundant Maven re-run when a Bash-tool
 * Maven invocation just completed successfully — avoids the Windows file-lock race where
 * a second Maven JVM contends with the first JVM's lingering handles on target/.
 */
function isFreshGreen(cwd, maxAgeSeconds = 600) {
  try {
    const dir = resolve(cwd, 'target', 'surefire-reports');
    const xmls = readdirSync(dir).filter((f) => f.endsWith('.xml'));
    if (xmls.length === 0) return false;
    const now = Date.now();
    // Use the most-recently-written report as the anchor for this run.
    const mostRecent = Math.max(...xmls.map((f) => statSync(join(dir, f)).mtimeMs));
    // If the most recent report is older than our threshold, no fresh run occurred.
    if (now - mostRecent > maxAgeSeconds * 1000) return false;
    // Check only reports written within the last 10 minutes relative to the anchor —
    // this covers a full Maven test run while ignoring stale IT reports from earlier
    // sessions (e.g. a previous `mvn verify` with Docker that left *IT.xml files behind).
    const runWindowStart = mostRecent - 10 * 60 * 1000;
    for (const f of xmls) {
      const { mtimeMs } = statSync(join(dir, f));
      if (mtimeMs < runWindowStart) continue; // predates this run — skip
      const content = readFileSync(join(dir, f), 'utf8');
      const fail = Number(content.match(/\bfailures="(\d+)"/)?.[1] ?? '0');
      const errs = Number(content.match(/\berrors="(\d+)"/)?.[1] ?? '0');
      if (fail > 0 || errs > 0) return false;
    }
    return true;
  } catch {
    return false; // unreadable → fall through to Maven re-run
  }
}

const input = await readStdin();

// Avoid re-trigger loops: if we already ran as part of this stop, do nothing.
if (input?.stop_hook_active) process.exit(0);

const sides = new Set(changedFiles().map(side).filter(Boolean));
if (sides.size === 0) process.exit(0);

const failures = [];

if (sides.has('backend')) {
  if (isFreshGreen(backendDir)) {
    console.log('\n[stop-hook] Backend: recent surefire reports are green — skipping re-run.');
  } else {
    console.log('\n[stop-hook] Backend source changed — running unit tests (skipping ITs)...');
    if (run('mvnw', ['-q', 'test', '-DskipITs'], backendDir) !== 0) {
      failures.push('backend unit tests');
    }
  }
}

if (sides.has('frontend')) {
  console.log('\n[stop-hook] Frontend source changed — running Vitest (no watch)...');
  // Use test:ci (ng test --no-watch --coverage) rather than `npm test -- --no-watch`:
  // the :ci variant exits reliably on Windows and avoids port conflicts with any
  // foreground ng-test process still winding down from a Claude tool call.
  if (run('npm', ['run', 'test:ci'], frontendDir) !== 0) {
    failures.push('frontend unit tests');
  }
}

if (failures.length) {
  const msg = `Tests failing: ${failures.join(', ')}.\nFix them before ending the session, or tell the user explicitly that tests are red.`;
  if (input?.terminationReason || input?.executionNum !== undefined) {
    process.stdout.write(JSON.stringify({ decision: 'continue', reason: msg }) + '\n');
    process.exit(0);
  } else {
    process.stderr.write(`\n${msg}\n`);
    process.exit(2);
  }
}

if (input?.terminationReason || input?.executionNum !== undefined) {
  process.stdout.write(JSON.stringify({ decision: 'allow' }) + '\n');
}
process.exit(0);
