#!/usr/bin/env bash
# Statically validates every test (syntax, imports, options, thresholds) with `k6 inspect`,
# without sending any traffic. BASE_URL is a reserved, non-resolvable placeholder (RFC 2606)
# because config/environment.js requires one at init time.
set -euo pipefail

cd "$(dirname "$0")/.."
status=0
for test in tests/*/*.js; do
  if k6 inspect --env BASE_URL=http://inspect.invalid "$test" > /dev/null; then
    echo "ok      $test"
  else
    echo "FAILED  $test" >&2
    status=1
  fi
done
exit "$status"
