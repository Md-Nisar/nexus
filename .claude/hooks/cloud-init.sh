#!/bin/bash
# Prepares a Claude Code cloud session so Nexus can be built, tested and run:
# backend Maven deps, frontend npm deps + Playwright browser path, and local infra
# (MySQL/Redis/MailHog via docker compose when a Docker daemon is reachable).
set -uo pipefail

if [ "${CLAUDE_CODE_REMOTE:-}" != "true" ]; then
  exit 0
fi

ROOT="${CLAUDE_PROJECT_DIR:-$(cd "$(dirname "$0")/../.." && pwd)}"
log() { echo "[cloud-init] $*" >&2; }

# --- JDK: pom enforces Java 25, but JAVA_HOME may default to 21 ---
JDK25="$(ls -d /usr/lib/jvm/java-25-openjdk-* 2>/dev/null | head -1)"
if [ -n "$JDK25" ]; then
  export JAVA_HOME="$JDK25"
  export PATH="$JAVA_HOME/bin:$PATH"
  [ -n "${CLAUDE_ENV_FILE:-}" ] && echo "export JAVA_HOME=\"$JDK25\"; export PATH=\"$JDK25/bin:\$PATH\"" >> "$CLAUDE_ENV_FILE"
fi

# --- Backend: resolve dependencies so `./mvnw verify -DskipITs` works offline-fast ---
cd "$ROOT/nexus-backend"
chmod +x mvnw
./mvnw -B -q dependency:go-offline -DskipTests >/dev/null 2>&1 || log "maven go-offline failed (non-fatal)"

# --- Frontend: npm install (not ci) so the cached container layer is reused ---
cd "$ROOT/nexus-frontend"
npm install --no-audit --no-fund --loglevel=error || log "npm install failed"

# Preinstalled Chromium is used for Playwright; never download another.
if [ -n "${CLAUDE_ENV_FILE:-}" ]; then
  {
    echo 'export PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1'
    echo 'export PLAYWRIGHT_BROWSERS_PATH=/opt/pw-browsers'
    echo 'export SPRING_PROFILES_ACTIVE=dev'
  } >> "$CLAUDE_ENV_FILE"
fi

# --- Infra: MySQL :3306, Redis :6379, MailHog :1025/:8025 ---
cd "$ROOT"
if ! docker info >/dev/null 2>&1 && command -v dockerd >/dev/null 2>&1; then
  (dockerd >/tmp/dockerd.log 2>&1 &)
  for _ in $(seq 1 20); do docker info >/dev/null 2>&1 && break; sleep 1; done
fi

if docker info >/dev/null 2>&1; then
  docker compose up -d mysql redis mailhog >/dev/null 2>&1 || log "docker compose up failed"
  for _ in $(seq 1 30); do
    [ "$(docker inspect -f '{{.State.Health.Status}}' nexus-mysql 2>/dev/null)" = "healthy" ] && break
    sleep 2
  done
else
  log "no Docker daemon: skipping MySQL; unit tests (-DskipITs) still work, running the app/ITs does not"
  if command -v redis-server >/dev/null 2>&1 && ! redis-cli ping >/dev/null 2>&1; then
    redis-server --daemonize yes --maxmemory 256mb --maxmemory-policy noeviction >/dev/null
  fi
fi
exit 0
