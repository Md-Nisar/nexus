// Shared helpers for Claude Code hooks. Cross-platform (Windows/macOS/Linux):
// invoked via `node`, no shell-specific syntax.

import { spawnSync } from 'node:child_process';
import { resolve } from 'node:path';

/** Read and JSON-parse the hook payload delivered on stdin. Returns {} on empty/invalid. */
export async function readStdin() {
  const chunks = [];
  for await (const chunk of process.stdin) chunks.push(chunk);
  const raw = Buffer.concat(chunks).toString('utf8').trim();
  if (!raw) return {};
  try {
    return JSON.parse(raw);
  } catch {
    return {};
  }
}

/** The text a Write/Edit tool is about to persist (content or new_string). */
export function textBeingWritten(input) {
  const ti = input?.tool_input ?? {};
  return ti.content ?? ti.new_string ?? '';
}

/** Returns a reason string if the path is protected from agent writes, else null. */
export function blockedTargetPath(filePath) {
  if (!filePath) return null;
  const p = filePath.replace(/\\/g, '/');
  if (/application-prod\.(ya?ml|properties)$/.test(p)) return 'production Spring config';
  if (/(^|\/)\.env(\.|$)/.test(p) && !/\.env\.example$/.test(p)) return 'environment secrets file';
  if (/\.(pem|key|p12|pfx|jks)$/.test(p)) return 'key material';
  if (/(^|\/)id_rsa$/.test(p)) return 'SSH private key';
  return null;
}

/** Which side of the repo a changed file belongs to. */
export function side(path) {
  const p = path.replace(/\\/g, '/');
  if (p.startsWith('nexus-backend/src/')) return 'backend';
  if (p.startsWith('nexus-frontend/src/')) return 'frontend';
  return null;
}

/** Run a command, inheriting stdio. Picks the right Maven/npm wrapper per platform.
 *  The Maven wrapper lives in `cwd` (not on PATH), so resolve it to an absolute path —
 *  Windows cmd does not reliably find `mvnw.cmd` via the child cwd. `.cmd` shims require
 *  a shell on Windows (Node refuses to exec them directly since the 2024 security change). */
export function run(cmd, args, cwd) {
  const isWin = process.platform === 'win32';
  let bin;
  if (cmd === 'mvnw') bin = resolve(cwd ?? '.', isWin ? 'mvnw.cmd' : 'mvnw');
  else bin = isWin ? `${cmd}.cmd` : cmd; // npm / npx live on PATH
  const res = spawnSync(bin, args, { cwd, stdio: 'inherit', shell: isWin, timeout: 300_000 });
  // res.status is null when the process was killed by a signal (e.g. port conflict with a
  // concurrent build). Treat that as indeterminate — not a test failure — so the hook doesn't
  // produce false positives when two ng-test processes compete for the same Vitest port.
  if (res.signal) return 0;
  return res.status ?? 1;
}

/** List working-tree changed file paths (porcelain), excluding deletions. */
export function changedFiles() {
  const res = spawnSync('git', ['status', '--porcelain'], { encoding: 'utf8' });
  if (res.status !== 0 || !res.stdout) return [];
  return res.stdout
    .split('\n')
    .filter(Boolean)
    .filter((l) => !l.startsWith(' D') && !l.startsWith('D '))
    .map((l) => l.slice(3).trim());
}
