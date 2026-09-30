#!/usr/bin/env bash
# Resets the LOCAL docker-compose database to a freshly migrated, empty state.
#
# Why: the RBAC performance scenarios create roles, and roles cannot be deleted (there is no delete
# endpoint); a tenant holds at most nexus.rbac.max-roles-per-tenant (default 500). When a long-lived
# local database gets near that cap, or you simply want a clean slate, run this.
#
# What it does (destructive - drops the `nexus` schema and flushes Redis):
#   1. drops and recreates the `nexus` database in the compose `mysql` service
#   2. re-runs the compose `flyway-migrate` service (schema, system roles/permissions, grants)
#   3. flushes the compose `redis` service (rate-limit counters, permission cache, token denylist)
# Stop the backend first, then start it again afterwards: in the dev profile DevDataInitializer
# re-seeds the test user on startup.
#
# Only ever touches the compose services of this repository (docker compose exec/run), never a
# remote database. Usage: npm run reset-local-db -- --yes
set -euo pipefail

if [ "${1:-}" != "--yes" ]; then
  echo "This DROPS the local 'nexus' database and flushes local Redis." >&2
  echo "Stop the backend, then re-run with --yes to confirm." >&2
  exit 2
fi

cd "$(dirname "$0")/../../.."
root_password="${MYSQL_ROOT_PASSWORD:-root}"

echo "Recreating the nexus database..."
docker compose exec -T mysql mysql -uroot -p"$root_password" \
  -e 'DROP DATABASE IF EXISTS nexus; CREATE DATABASE nexus;' 2>/dev/null

echo "Applying migrations and grants..."
docker compose --profile full run --rm flyway-migrate

echo "Flushing Redis..."
docker compose exec -T redis redis-cli FLUSHALL

echo "Done. Start the backend again so it re-seeds the dev test user."
