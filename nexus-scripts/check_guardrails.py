#!/usr/bin/env python3
"""Enforce hard limits on AI-authored pull requests for the Nexus repository.

Runs in GitHub Actions on ai/** branches only. Automated agents cannot edit this
file (CODEOWNERS + .claude/settings.json deny rules), so these limits hold
even if an agent misbehaves or is prompt-injected.

Exit code 1 fails the required 'AI Guardrails' check, which blocks merge.
"""

from __future__ import annotations

import fnmatch
import os
import re
import subprocess
import sys

MAX_FILES = 10
MAX_CHANGED_LINES = 200

# Paths the agent must never touch on an automated PR.
FORBIDDEN_PATTERNS = [
    ".github/**",
    ".githooks/**",
    ".claude/**",
    ".agents/**",
    ".codex/**",
    ".mcp.json",
    "nexus-scripts/**",
    "scripts/**",
    "sonar-project.properties",
    "CODEOWNERS",
    "**/pom.xml",
    "**/package.json",
    "**/package-lock.json",
    "**/*Test.java",
    "**/*Tests.java",
    "**/*IT.java",
    "**/src/test/**",
    "**/*.spec.ts",
    "**/*.test.ts",
    "nexus-backend/src/main/resources/db/**",
    "nexus-database/**",
    "**/generated/**",
    "**/*.generated.ts",
    "**/Dockerfile",
    "**/docker-compose*.yml",
    "**/*.tf",
    "**/security/**",
    "**/config/**",
]

RULE_KEY_RE = re.compile(r"\b(java|typescript|javascript|css|html):S\d+\b")

failures: list[str] = []


def run(*args: str) -> str:
    return subprocess.run(
        args, check=True, capture_output=True, text=True
    ).stdout.strip()


def matches_forbidden(path: str) -> str | None:
    for pattern in FORBIDDEN_PATTERNS:
        if fnmatch.fnmatch(path, pattern) or fnmatch.fnmatch(
            path, pattern.replace("**/", "", 1)
        ):
            return pattern
    return None


def main() -> int:
    base = os.environ.get("BASE_SHA", "")
    head = os.environ.get("HEAD_SHA", "")
    body = os.environ.get("PR_BODY", "") or ""

    if not base or not head:
        print("BASE_SHA and HEAD_SHA environment variables are required.")
        return 1

    # --- 1. Which files changed ------------------------------------------
    changed = [
        f for f in run("git", "diff", "--name-only", base, head).splitlines() if f
    ]

    if not changed:
        failures.append("PR contains no changes.")

    if len(changed) > MAX_FILES:
        failures.append(
            f"Touched {len(changed)} files, limit is {MAX_FILES}. "
            "Split this into smaller PRs - reviewability is the safety mechanism."
        )

    for path in changed:
        pattern = matches_forbidden(path)
        if pattern:
            failures.append(f"Forbidden path modified: {path} (matched {pattern})")

    # --- 2. How much changed ---------------------------------------------
    numstat = run("git", "diff", "--numstat", base, head)
    total = 0
    for line in numstat.splitlines():
        added, removed, _ = (line.split("\t", 2) + ["", "", ""])[:3]
        if added.isdigit():
            total += int(added)
        if removed.isdigit():
            total += int(removed)

    if total > MAX_CHANGED_LINES:
        failures.append(
            f"Changed {total} lines, limit is {MAX_CHANGED_LINES}."
        )

    # --- 3. Provenance ----------------------------------------------------
    if not RULE_KEY_RE.search(body):
        failures.append(
            "PR body must cite at least one Sonar rule key (e.g. java:S1128). "
            "Every automated change needs a traceable justification."
        )

    if "Sonar issue" not in body and "issue key" not in body.lower():
        failures.append("PR body must list the Sonar issue keys that were fixed.")

    # --- Report -----------------------------------------------------------
    print(f"Files changed: {len(changed)} (limit {MAX_FILES})")
    print(f"Lines changed: {total} (limit {MAX_CHANGED_LINES})")
    for path in changed:
        print(f"  {path}")

    if failures:
        print("\n=== GUARDRAIL VIOLATIONS ===")
        for f in failures:
            print(f"  FAIL: {f}")
        print(
            "\nThis PR is blocked. Fix the agent's skill files rather than "
            "loosening these limits."
        )
        return 1

    print("\nAll guardrails passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
