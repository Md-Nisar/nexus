#!/usr/bin/env bash
# PostToolUse hook for Write/Edit — auto-format and lint the changed file.
# Non-blocking: prints warnings but exits 0 so it never breaks the flow.

set -uo pipefail

input=$(cat)
path=$(printf '%s' "$input" | jq -r '.tool_input.file_path // .tool_input.path // empty')

if [[ -z "$path" || ! -f "$path" ]]; then
  exit 0
fi

warn() {
  echo "[format-and-lint] $1" >&2
}

case "$path" in
  *.ts|*.tsx|*.js|*.jsx|*.html|*.scss|*.css|*.json|*.md)
    if [[ -d nexus-frontend ]] && [[ "$path" =~ ^nexus-frontend/ ]]; then
      (cd nexus-frontend && npx --no -- prettier --write "../$path" 2>&1 | sed 's/^/[prettier] /') || warn "Prettier failed on $path (non-blocking)."
    fi
    ;;
  *.java)
    # If a formatter is available (spotless via Maven, or google-java-format binary), run it.
    if [[ -d nexus-backend ]] && [[ "$path" =~ ^nexus-backend/ ]]; then
      if [[ -f nexus-backend/pom.xml ]] && grep -q "spotless-maven-plugin" nexus-backend/pom.xml 2>/dev/null; then
        (cd nexus-backend && ./mvnw -q spotless:apply -DspotlessFiles="$(realpath --relative-to=nexus-backend "$path")" 2>&1 | sed 's/^/[spotless] /') || warn "Spotless failed on $path (non-blocking)."
      fi
    fi
    ;;
esac

exit 0
