# Runbook — Cloud environment for Claude Code sessions

A Claude Code cloud session starts from a fresh container. For `/autonomous-feature` (and any
session that must run the full gate), the container needs Java 25, a running Docker daemon for the
Testcontainers `*IT` suite, and frontend dependencies. `/autonomous-feature` refuses to start
without them, so a PR is never opened with integration tests silently skipped.

The setup script lives in the cloud **environment settings** (environment menu → Edit → Setup
script), not in this repo. Paste the script below there; new sessions run it on start.

## Setup script

```bash
#!/usr/bin/env bash
set -euo pipefail

# Java 25 (the Maven enforcer rejects anything else)
apt-get update -q
apt-get install -y -q openjdk-25-jdk-headless

# Docker daemon for Testcontainers (MySQL 8.4, Redis 7.4)
if ! docker info >/dev/null 2>&1; then
  nohup dockerd >/tmp/dockerd.log 2>&1 &
  for _ in $(seq 1 30); do docker info >/dev/null 2>&1 && break; sleep 1; done
fi
docker pull -q mysql:8.4
docker pull -q redis:7.4-alpine

# Frontend dependencies
cd nexus-frontend && npm ci
```

## Environment variables

Set in the same environment settings (the base image points `JAVA_HOME` at Java 21):

```
JAVA_HOME=/usr/lib/jvm/java-25-openjdk-amd64
```

## Verify

In a new session, from the repo root:

```bash
java -version                       # 25.x
docker info --format '{{.ServerVersion}}'
cd nexus-backend && ./mvnw verify   # full suite including *IT
```
