#!/usr/bin/env bash
# Gives the dev-seeded test user the TENANT_ADMIN role so RBAC scenarios can read roles/permissions.
#
# For a throw-away LOCAL or CI database only. It inserts straight into user_roles (root user of the
# repo's docker-compose MySQL), bypassing the application's audit trail and last-admin rules, so
# never point it at a shared or production database. Idempotent: does nothing if already granted.
#
# Usage: BASE_URL=<url> PERF_USER_EMAIL=<email> PERF_USER_PASSWORD=<password> \
#          scripts/grant-test-user-admin.sh
# Run after the app has started (the dev profile seeds the user) and before the RBAC tests.
set -euo pipefail

: "${BASE_URL:?BASE_URL is required}"
: "${PERF_USER_EMAIL:?PERF_USER_EMAIL is required}"
: "${PERF_USER_PASSWORD:?PERF_USER_PASSWORD is required}"
base="${BASE_URL%/}"
compose_file="$(cd "$(dirname "$0")/../../.." && pwd)/docker-compose.yml"
mysql_root_password="${MYSQL_ROOT_PASSWORD:-root}"

json_field() { node -e 'let s="";process.stdin.on("data",d=>s+=d).on("end",()=>console.log(JSON.parse(s)[process.argv[1]]))' "$1"; }

# Prints an access token. Login is rate limited (10/min per IP, 5/min per email), hence the
# explicit failure message.
login() {
  local response
  response="$(curl --silent --show-error --max-time 10 --write-out '\n%{http_code}' \
    -X POST "$base/api/v1/auth/login" -H 'Content-Type: application/json' \
    -d "$(node -e 'console.log(JSON.stringify({email:process.env.PERF_USER_EMAIL,password:process.env.PERF_USER_PASSWORD}))')")"
  if [[ "${response##*$'\n'}" != 200 ]]; then
    echo "Login failed with HTTP ${response##*$'\n'} (401: wrong credentials, 429: rate limited)" >&2
    return 1
  fi
  printf '%s' "${response%$'\n'*}" | json_field accessToken
}

token="$(login)"
user_id="$(curl --silent --fail --max-time 10 -H "Authorization: Bearer $token" "$base/api/v1/users/me" | json_field userId)"

docker compose -f "$compose_file" exec -T mysql mysql -uroot -p"$mysql_root_password" nexus <<SQL
INSERT INTO user_roles (id, user_id, role_id, tenant_id, assigned_by)
SELECT UUID_TO_BIN(UUID()), UUID_TO_BIN('$user_id'), r.id, r.tenant_id, UUID_TO_BIN('$user_id')
FROM roles r
WHERE r.name = 'TENANT_ADMIN' AND r.is_system_role
  AND NOT EXISTS (SELECT 1 FROM user_roles ur
                  WHERE ur.user_id = UUID_TO_BIN('$user_id') AND ur.role_id = r.id
                    AND ur.revoked_at IS NULL);
SQL

# Confirm the assignment is active (a second login would eat into the per-email login limit).
active="$(docker compose -f "$compose_file" exec -T mysql mysql -uroot -p"$mysql_root_password" nexus -N -e \
  "SELECT COUNT(*) FROM user_roles ur JOIN roles r ON r.id = ur.role_id
   WHERE ur.user_id = UUID_TO_BIN('$user_id') AND r.name = 'TENANT_ADMIN' AND ur.revoked_at IS NULL" 2>/dev/null)"
if [[ "$active" != 1 ]]; then
  echo "Expected 1 active TENANT_ADMIN assignment for the test user, found: $active" >&2
  exit 1
fi
echo "Test user holds TENANT_ADMIN"
