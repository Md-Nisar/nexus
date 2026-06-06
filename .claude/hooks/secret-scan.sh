#!/usr/bin/env bash
# PreToolUse hook for Write/Edit — scans content for likely secrets.
# Exit 0 = allow, 2 = deny.

set -euo pipefail

input=$(cat)
tool=$(printf '%s' "$input" | jq -r '.tool_name // empty')
path=$(printf '%s' "$input" | jq -r '.tool_input.file_path // .tool_input.path // empty')

# Pull the new content depending on tool
if [[ "$tool" == "Write" ]]; then
  content=$(printf '%s' "$input" | jq -r '.tool_input.content // .tool_input.file_text // empty')
elif [[ "$tool" == "Edit" ]]; then
  content=$(printf '%s' "$input" | jq -r '.tool_input.new_string // .tool_input.new_str // empty')
else
  exit 0
fi

if [[ -z "$content" ]]; then
  exit 0
fi

deny() {
  echo "[secret-scan] BLOCKED writing $path: $1" >&2
  echo "[secret-scan] If this is a placeholder or test fixture, use an obvious dummy value like 'TEST_VALUE'." >&2
  exit 2
}

# Allow obvious test/example markers
if [[ "$path" =~ /test/|/__tests__/|\.spec\.|\.example|README ]]; then
  # Be lenient in test fixtures and docs — only block the most dangerous patterns
  if [[ "$content" =~ -----BEGIN[[:space:]]+(RSA|EC|OPENSSH|PRIVATE)[[:space:]]+KEY----- ]]; then
    deny "Private key material in $path."
  fi
  exit 0
fi

# AWS access key
if [[ "$content" =~ AKIA[0-9A-Z]{16} ]]; then
  deny "AWS access key ID pattern detected."
fi
if [[ "$content" =~ aws_secret_access_key[[:space:]]*=[[:space:]]*[A-Za-z0-9/+=]{40} ]]; then
  deny "AWS secret access key pattern detected."
fi

# GitHub token
if [[ "$content" =~ gh[pousr]_[A-Za-z0-9]{36,} ]]; then
  deny "GitHub token detected."
fi

# Generic high-entropy assignments to suspicious names
if [[ "$content" =~ (password|passwd|pwd|api[_-]?key|apikey|secret|token)[[:space:]]*[:=][[:space:]]*[\"\']?[A-Za-z0-9/+=_-]{16,}[\"\']? ]]; then
  # Allow Spring property placeholders ${VAR}
  if ! [[ "$content" =~ \$\{[A-Z_][A-Z0-9_]*(:[^\}]*)?\} ]]; then
    deny "Possible hardcoded secret (password/api key/token assignment with high-entropy value)."
  fi
fi

# Private key blocks
if [[ "$content" =~ -----BEGIN[[:space:]]+(RSA|EC|OPENSSH|PRIVATE)[[:space:]]+KEY----- ]]; then
  deny "Private key material."
fi

# JWT-looking strings (very loose; only block if assigned to a const named token/jwt/auth)
if [[ "$content" =~ (token|jwt|auth)[[:space:]]*[:=][[:space:]]*[\"\']?eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+[\"\']? ]]; then
  deny "Hardcoded JWT-looking string."
fi

# DB connection strings with embedded credentials
if [[ "$content" =~ (mysql|postgresql|jdbc:mysql)://[^:]+:[^@[:space:]]+@ ]]; then
  deny "DB connection string with embedded credentials. Use env vars or config references."
fi

exit 0
