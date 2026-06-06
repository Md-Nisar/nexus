#!/usr/bin/env bash
# PreToolUse hook for Bash — blocks dangerous commands.
# Reads JSON from stdin describing the tool call. Exit 0 = allow, 2 = deny (Claude sees stderr).

set -euo pipefail

input=$(cat)
command=$(printf '%s' "$input" | jq -r '.tool_input.command // empty')

if [[ -z "$command" ]]; then
  exit 0
fi

deny() {
  echo "[block-prod-commands] BLOCKED: $1" >&2
  exit 2
}

# Production references — refuse outright. Adjust patterns to your infra.
case "$command" in
  *production*|*prod-db*|*prod.nexus*|*"@prod"*)
    deny "Command references production. Run it yourself from a local terminal." ;;
esac

# Destructive git
case "$command" in
  *"git push --force"*|*"git push -f"*)
    deny "Force-push is not allowed via Claude. Push manually." ;;
  *"git reset --hard"*)
    deny "git reset --hard discards work. Run it yourself if you mean it." ;;
  *"git clean -fd"*)
    deny "git clean -fd discards untracked work. Run it yourself if you mean it." ;;
esac

# rm -rf on suspicious paths
if [[ "$command" =~ rm[[:space:]]+-[a-zA-Z]*r[a-zA-Z]*f? ]]; then
  case "$command" in
    *"rm -rf /"*|*"rm -rf ~"*|*"rm -rf \$HOME"*|*"rm -rf .git"*|*"rm -rf node_modules"*)
      # node_modules is fine in some workflows but require user to do it themselves
      deny "Destructive rm. If intentional, run it from a terminal." ;;
  esac
fi

# Curl-pipe-to-shell
if [[ "$command" =~ (curl|wget).*\|\ *(sh|bash|zsh) ]]; then
  deny "Piping remote scripts to a shell is forbidden. Download, inspect, then execute."
fi

# sudo
case "$command" in
  *"sudo "*) deny "sudo is not allowed via Claude." ;;
esac

# Direct DB mutations on prod-like databases (best effort)
if [[ "$command" =~ mysql.*-h[[:space:]]*(prod|production) ]]; then
  deny "Direct DB connection to production. Use a runbook, not the AI."
fi

exit 0
