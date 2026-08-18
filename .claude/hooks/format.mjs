#!/usr/bin/env node
// PostToolUse(Write|Edit) — auto-formats frontend files with Prettier.
//
// Fast, best-effort, never blocks (exit 0 always): formatting is also enforced by
// the pre-push git hook and `npm run format:check` in CI. Java formatting is NOT
// done here (no per-file formatter configured) — Checkstyle enforces Java style in CI.

import { readStdin, run, targetFilePath } from './_hooklib.mjs';

const FRONTEND_EXT = /\.(ts|tsx|html|scss|css|json|mjs)$/;

const input = await readStdin();
const target = targetFilePath(input).replace(/\\/g, '/');

if (target && FRONTEND_EXT.test(target) && target.includes('nexus-frontend/')) {
  // Run Prettier from the frontend package so its config (package.json) applies.
  const rel = target.slice(target.indexOf('nexus-frontend/') + 'nexus-frontend/'.length);
  run('npx', ['prettier', '--write', '--log-level', 'warn', rel], 'nexus-frontend');
}

process.stdout.write('{}\n');
process.exit(0);
