#!/usr/bin/env node
// Stop — runs the fast unit tests for whichever side has uncommitted source changes,
// so a session never ends on red. Doc/config-only sessions exit instantly.
//
// Scope is deliberately limited to fast feedback: backend unit tests (-DskipITs) and
// frontend Vitest. Integration tests, coverage gates and lint are enforced by
// /pre-pr-check, the pre-push git hook, and CI. Exit 2 → blocks stop until fixed.

import { readStdin, changedFiles, side, run } from './_hooklib.mjs';

const input = await readStdin();

// Avoid re-trigger loops: if we already ran as part of this stop, do nothing.
if (input?.stop_hook_active) process.exit(0);

const sides = new Set(changedFiles().map(side).filter(Boolean));
if (sides.size === 0) process.exit(0);

const failures = [];

if (sides.has('backend')) {
  console.log('\n[stop-hook] Backend source changed — running unit tests (skipping ITs)...');
  if (run('mvnw', ['-q', 'test', '-DskipITs'], 'nexus-backend') !== 0) failures.push('backend unit tests');
}

if (sides.has('frontend')) {
  console.log('\n[stop-hook] Frontend source changed — running Vitest (no watch)...');
  // Use test:ci (ng test --no-watch --coverage) rather than `npm test -- --no-watch`:
  // the :ci variant exits reliably on Windows and avoids port conflicts with any
  // foreground ng-test process still winding down from a Claude tool call.
  if (run('npm', ['run', 'test:ci'], 'nexus-frontend') !== 0) failures.push('frontend unit tests');
}

if (failures.length) {
  process.stderr.write(
    `\nTests failing: ${failures.join(', ')}.\n` +
      `Fix them before ending the session, or tell the user explicitly that tests are red.\n`,
  );
  process.exit(2);
}

process.exit(0);
