#!/usr/bin/env node
// Fails when the built index.html needs 'unsafe-inline' scripts (US-020 delta review NEW-H1).
// The edge CSP is `script-src 'self'`: an inline <script> or an inline event handler such as the
// `onload` Angular's critical-CSS inlining adds to the stylesheet link would be blocked, leaving the
// app without its global stylesheet. Run on the production build output: `node
// e2e/tools/check-index-csp.mjs dist/nexus-frontend/browser/index.html`.
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const INLINE_SCRIPT = /<script(?![^>]*\ssrc=)[^>]*>/i;
const INLINE_HANDLER = /\son[a-z]+\s*=/i;
const PRINT_SWAP = /media\s*=\s*["']print["']/i;

/** @param {string} html @returns {string[]} one message per violation. */
export function inlineScriptViolations(html) {
  const violations = [];
  if (INLINE_SCRIPT.test(html)) violations.push('inline <script> block');
  if (INLINE_HANDLER.test(html)) violations.push('inline event handler attribute');
  if (PRINT_SWAP.test(html))
    violations.push('media="print" stylesheet swap (critical CSS inlining)');
  return violations;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const file = process.argv[2];
  if (!file) {
    console.error('usage: check-index-csp.mjs <path to built index.html>');
    process.exit(2);
  }
  const violations = inlineScriptViolations(readFileSync(file, 'utf8'));
  if (violations.length > 0) {
    console.error(`${file} would break under script-src 'self': ${violations.join('; ')}`);
    process.exit(1);
  }
  console.log(`${file}: no inline script, handler or print-media swap`);
}
