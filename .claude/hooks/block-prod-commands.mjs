#!/usr/bin/env node
// PreToolUse(Bash) — blocks destructive or production-affecting shell commands.
// Complements settings.json deny rules (which catch exact prefixes) by matching
// dangerous *patterns*. Exit 2 → command blocked, stderr shown to Claude.

import { readStdin, commandBeingRun, deny, allow } from './_hooklib.mjs';

const DANGER = [
  { name: 'recursive root delete', re: /\brm\s+-[a-z]*r[a-z]*f?\s+(\/|~|\$HOME|\.\.)(\s|$)/ },
  { name: 'force push', re: /\bgit\s+push\b.*(--force|-f)\b/ },
  { name: 'hard reset', re: /\bgit\s+reset\s+--hard\b/ },
  { name: 'history rewrite push', re: /\bgit\s+push\b.*--force-with-lease.*\b(main|master)\b/ },
  { name: 'drop/truncate database', re: /\b(DROP\s+(DATABASE|SCHEMA|TABLE)|TRUNCATE)\b/i },
  { name: 'production profile run', re: /SPRING_PROFILES_ACTIVE\s*=\s*prod\b/ },
  { name: 'maven deploy', re: /\bmvn(w)?(\.cmd)?\s+.*\bdeploy\b/ },
  { name: 'pipe-to-shell install', re: /\b(curl|wget)\b[^|]*\|\s*(sudo\s+)?(ba)?sh\b/ },
  { name: 'infra destroy', re: /\bterraform\s+destroy\b|\bkubectl\s+delete\b.*\b(prod|production)\b/ },
  { name: 'disk overwrite', re: /\bdd\s+if=.*of=\/dev\/|\bmkfs\b/ },
  { name: 'fork bomb', re: /:\(\)\s*\{.*\};:/ },
  { name: 'world-writable root', re: /\bchmod\s+-R?\s*777\s+\// },
  { name: 'power state change', re: /\b(shutdown|reboot|halt|poweroff)\b/ },
];

const input = await readStdin();
const command = commandBeingRun(input);

for (const { name, re } of DANGER) {
  if (re.test(command)) {
    deny(
      input,
      `Blocked dangerous command (${name}):\n  ${command}\n` +
        `If this is intentional and safe, ask the user to run it manually.`,
    );
  }
}

allow(input);
