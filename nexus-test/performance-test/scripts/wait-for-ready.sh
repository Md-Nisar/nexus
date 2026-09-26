#!/usr/bin/env bash
# Blocks until nexus-backend's readiness probe answers 200, so a test never measures start-up.
#
# Usage: BASE_URL=<url> scripts/wait-for-ready.sh [timeout-seconds]   (default timeout: 120)
set -euo pipefail

: "${BASE_URL:?BASE_URL is required}"
timeout_seconds="${1:-120}"
url="${BASE_URL%/}/actuator/health/readiness"
deadline=$((SECONDS + timeout_seconds))

until curl --silent --fail --max-time 5 "$url" > /dev/null; do
  if (( SECONDS >= deadline )); then
    echo "Not ready after ${timeout_seconds}s: $url" >&2
    exit 1
  fi
  sleep 2
done
echo "Ready: $url"
