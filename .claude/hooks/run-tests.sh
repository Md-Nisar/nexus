#!/usr/bin/env bash
# Stop hook — runs a fast smoke test when Claude finishes a turn IF code changed.
# Non-blocking: prints output but exits 0.
#
# Heuristic: only run if there are unstaged or staged code changes in nexus-backend or nexus-frontend
# since the last commit.

set -uo pipefail

# Skip if we're not in a git repo
if ! git rev-parse --git-dir >/dev/null 2>&1; then
  exit 0
fi

backend_changed=$(git diff --name-only HEAD -- 'nexus-backend/**/*.java' 2>/dev/null | head -n 1)
frontend_changed=$(git diff --name-only HEAD -- 'nexus-frontend/src/**' 2>/dev/null | head -n 1)

ran_any=0

if [[ -n "$backend_changed" ]] && [[ -d nexus-backend ]]; then
  echo "[run-tests] Backend changes detected — running fast tests..."
  if (cd nexus-backend && timeout 300 ./mvnw -q test -Dtest='*Test' -DfailIfNoTests=false 2>&1 | tail -n 30); then
    echo "[run-tests] Backend tests: OK"
  else
    echo "[run-tests] Backend tests: FAILED — review before continuing." >&2
  fi
  ran_any=1
fi

if [[ -n "$frontend_changed" ]] && [[ -d nexus-frontend ]]; then
  echo "[run-tests] Frontend changes detected — running Vitest..."
  if (cd nexus-frontend && timeout 180 npm test --silent -- --run 2>&1 | tail -n 30); then
    echo "[run-tests] Frontend tests: OK"
  else
    echo "[run-tests] Frontend tests: FAILED — review before continuing." >&2
  fi
  ran_any=1
fi

if [[ "$ran_any" -eq 0 ]]; then
  : # No code changes — nothing to test
fi

exit 0
