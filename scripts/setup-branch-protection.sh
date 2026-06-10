#!/usr/bin/env bash
# Enables branch protection on `main`. Requires GitHub repo-admin and the `gh` CLI
# (https://cli.github.com), so it cannot be applied from inside the repo — a human
# admin runs this once. Re-running is safe (idempotent PUT).
#
# Usage:  ./scripts/setup-branch-protection.sh [owner/repo]
set -euo pipefail

REPO="${1:-$(gh repo view --json nameWithOwner -q .nameWithOwner)}"
echo "Configuring branch protection for ${REPO}@main ..."

# Required status checks must match the job names produced by the CI workflows:
#   maven.yml  -> "backend-build"
#   node.yml   -> "frontend-build", "e2e"
#   commit-lint.yml -> "pr-title"
gh api -X PUT "repos/${REPO}/branches/main/protection" \
  --input - <<'JSON'
{
  "required_status_checks": {
    "strict": true,
    "contexts": ["backend-build", "frontend-build", "e2e", "pr-title"]
  },
  "enforce_admins": true,
  "required_pull_request_reviews": {
    "required_approving_review_count": 1,
    "require_code_owner_reviews": true,
    "dismiss_stale_reviews": true
  },
  "required_conversation_resolution": true,
  "allow_force_pushes": false,
  "allow_deletions": false,
  "restrictions": null
}
JSON

echo "Done. 'main' now requires: passing CI, 1 code-owner approval, resolved conversations, no force-push."
