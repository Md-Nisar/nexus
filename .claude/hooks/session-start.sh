#!/bin/bash
# Installs the graphify CLI and registers its /graphify skill in cloud sessions.
set -euo pipefail

if [ "${CLAUDE_CODE_REMOTE:-}" != "true" ]; then
  exit 0
fi

export PATH="$HOME/.local/bin:$PATH"

if ! command -v uv >/dev/null 2>&1; then
  python3 -m pip install --quiet uv
fi

uv tool install --quiet graphifyy==0.9.94
graphify install --platform claude

echo 'export PATH="$HOME/.local/bin:$PATH"' >> "$CLAUDE_ENV_FILE"
