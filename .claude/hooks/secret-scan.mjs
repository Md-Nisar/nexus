#!/usr/bin/env node
// PreToolUse(Write|Edit) — defense-in-depth secret scanner.
//
// Blocks writes that introduce high-confidence secrets or that target protected
// files (prod config, key material). This is a backstop, NOT the only control:
// settings.json deny rules and the weekly Trivy scan (security.yml, secret
// detection included in its fs scan) complete the net.
// Exit 2 → the write is blocked and stderr is shown to Claude.

import { readStdin, textBeingWritten, blockedTargetPath } from './_hooklib.mjs';

// High-confidence patterns only — kept tight to avoid blocking legitimate writes
// (e.g. documentation that mentions a key format). Placeholders are exempted below.
const SECRET_PATTERNS = [
  { name: 'Private key block', re: /-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----/ },
  { name: 'AWS access key id', re: /\bAKIA[0-9A-Z]{16}\b/ },
  { name: 'AWS secret access key', re: /aws_secret_access_key\s*[=:]\s*['"][A-Za-z0-9/+]{40}['"]/i },
  { name: 'Google API key', re: /\bAIza[0-9A-Za-z_\-]{35}\b/ },
  { name: 'Slack token', re: /\bxox[baprs]-[0-9A-Za-z-]{10,}\b/ },
  { name: 'GitHub token', re: /\bgh[posru]_[0-9A-Za-z]{36,}\b/ },
  { name: 'Hardcoded credential', re: /(?:password|passwd|secret|api[_-]?key|token)\s*[=:]\s*['"][^'"\s]{12,}['"]/i },
];

// Skip anything that is obviously a placeholder / example, not a real secret.
const PLACEHOLDER = /(EXAMPLE|PLACEHOLDER|CHANGEME|CHANGE_ME|YOUR[_-]|XXXX|\.\.\.|\$\{|<[a-z-]+>|redacted|dummy|sample|test)/i;

const input = await readStdin();
const filePath = input?.tool_input?.file_path ?? '';

// 1) Protected files must never be written by the agent.
const blocked = blockedTargetPath(filePath);
if (blocked) {
  process.stderr.write(
    `Blocked write to protected file: ${filePath}\n` +
      `Reason: ${blocked}. Production config and key material are managed outside the repo.\n`,
  );
  process.exit(2);
}

// 2) Scan the content being written.
const text = textBeingWritten(input);
if (text) {
  for (const line of text.split('\n')) {
    if (PLACEHOLDER.test(line)) continue;
    for (const { name, re } of SECRET_PATTERNS) {
      if (re.test(line)) {
        process.stderr.write(
          `Possible secret blocked (${name}) in ${filePath || 'content'}.\n` +
            `If this is a real credential, use an environment variable / Vault reference instead.\n` +
            `If it is a false positive (example value), add a placeholder marker (e.g. EXAMPLE) and retry.\n`,
        );
        process.exit(2);
      }
    }
  }
}

process.exit(0);
