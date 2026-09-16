#!/usr/bin/env bash
# Deterministically fetch and filter Sonar issues on main for the Nexus repository.
# Prints a JSON array to stdout. No model involved - the allowlist is enforced
# here in code, not in a prompt.
set -euo pipefail

SONAR_URL="${SONAR_URL:-https://sonarcloud.io}"
PROJECT_KEY="${PROJECT_KEY:-Md-Nisar_nexus}"
BRANCH="${BRANCH:-main}"
MAX_ISSUES="${MAX_ISSUES:-3}"

# Tier 1 allowlist. Keep this in sync with
# .claude/skills/sonar-safe-fix/reference/allowed-rules.md
DEFAULT_RULES="java:S1128,java:S1481,java:S1596,java:S2293,java:S1125,typescript:S1128,typescript:S1481,typescript:S3512,typescript:S1125,typescript:S1116"
RULES="${RULE_FILTER:-}"
[ -z "$RULES" ] && RULES="$DEFAULT_RULES"

: "${SONAR_TOKEN:?SONAR_TOKEN is required}"

curl -sSf -u "${SONAR_TOKEN}:" -G "${SONAR_URL}/api/issues/search" \
  --data-urlencode "componentKeys=${PROJECT_KEY}" \
  --data-urlencode "branch=${BRANCH}" \
  --data-urlencode "rules=${RULES}" \
  --data-urlencode "resolved=false" \
  --data-urlencode "statuses=OPEN,CONFIRMED" \
  --data-urlencode "ps=100" \
| jq --argjson n "${MAX_ISSUES}" '
    [ .issues[]
      # Defence in depth: drop anything under a path the agent must not touch.
      | select(.component
          | test("(test|spec|Test\\.java|IT\\.java|/db/migration/|/nexus-database/|node_modules|/generated/)") | not)
      | { key, rule, severity, message,
          component: (.component | sub("^[^:]+:"; "")),
          line: (.line // 0),
          effort: (.effort // "unknown") }
    ]
    # Cheapest first: small, mechanical fixes build trust fastest.
    | sort_by(.effort)
    | .[0:$n]
  '
