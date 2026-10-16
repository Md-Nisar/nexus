# US-018 M2: Runbook

**Scope:** Milestone 2 (A1 to A4, M-1, L-1, L-2, L-5), M7 (sections 7 to 10) and M5 (A7 break-glass CLI, section 11). **Audience:** on-call engineer with no prior context. Companions: [monitoring.md](monitoring.md), [rollback.md](rollback.md), [09-technical.md](09-technical.md), and the US-016 and US-017 runbooks for the legacy gate, the denial throttle and the zero-administrator procedure.
Never paste emails, names or tokens into tickets: use user, role, permission and tenant UUIDs only. SQL below uses `UNHEX(REPLACE(?, '-', ''))` for UUID parameters.

## 1. A legitimate administrator gets 403 `RBAC_001`

**Symptom.** An administrator or delegated assigner gets 403 with `requiredPermission` `user:role:assign` (assign, revoke) or `role:write` (attach). The 403 body never says why; the reason is in the log and the audit row.

**Diagnose in this order.**

1. Find the request in the logs by trace id and read the `reason` on the `RBAC_001` line, or query the denial row (monitoring.md section 6). Match the reason:

   | `reason` | Marker | Most likely cause | Action |
   |---|---|---|---|
   | `PERMISSION_ABSENT` | `RBAC_ENDPOINT_PERMISSION_NOT_HELD` | Right after the V6 deploy: stale permission cache or old JWT without `user:role:assign`. Otherwise the caller's role was revoked and the token is stale (working as intended) | Step 2 |
   | `GRANT_EXCEEDS_CALLER` | `RBAC_GRANT_EXCEEDS_CALLER` (assign, revoke) or `RBAC_ATTACH_EXCEEDS_CALLER` (attach) | The role being assigned, revoked or attached carries a permission the caller does not hold. This is A2, A3 or revoke-subset working as designed | Step 3 |
   | `SELF_ASSIGNMENT` | `RBAC_SELF_ASSIGNMENT_DENIED` | A non-administrator targeted themselves (A4) | Step 4 |
   | `NOT_TENANT_ADMIN` | `RBAC_ADMINISTRATOR_REQUIRED_DENIED` or `RBAC_DENIAL_THROTTLE_ENGAGED` | (M3) The caller revoked an admin-defining role without being an administrator, or the actor is throttled. An administrator is an active holder of one role carrying every catalogue permission; holding the union across roles does not count | Section 3 and section 12 |
   | `CROSS_TENANT_TARGET` | n/a | Target user or role belongs to another tenant | Check ids; do not widen anything |

2. **`PERMISSION_ABSENT`.** Does the caller hold `user:role:assign` (or `role:write`) in the database right now?
   ```sql
   SELECT DISTINCT p.name
   FROM user_roles ur
   JOIN roles r ON r.id = ur.role_id AND r.tenant_id = ur.tenant_id
   JOIN role_permissions rp ON rp.role_id = r.id
   JOIN permissions p ON p.id = rp.permission_id
   WHERE ur.user_id = UNHEX(REPLACE(?, '-', '')) AND ur.tenant_id = UNHEX(REPLACE(?, '-', ''))
     AND ur.revoked_at IS NULL AND p.name IN ('user:role:assign', 'role:write');
   ```
   - **Not returned:** the caller does not hold it. If they should, an administrator attaches `user:role:assign` to a role they hold (or assigns a role that has it). A delegated role created before V6 that carried `user:write` does not get it automatically (no backfill, by design).
   - **Returned** but still 403: the JWT and cache were issued before the change. Flush `{keyPrefix}:rbac:permset:*` if the V6 flush was missed, and ask the user to log in again. If the log shows `RBAC_ENDPOINT_PERMISSION_NOT_HELD`, the token had the permission but the database does not (stale token). If that marker is absent, the token itself lacks the permission (old token or stale cache). The live check passes as soon as the database holds the permission.
3. **`GRANT_EXCEEDS_CALLER`.** Compare the role's permissions with the caller's. Compute the missing set from ids:
   ```sql
   SELECT p.name
   FROM role_permissions rp JOIN permissions p ON p.id = rp.permission_id
   WHERE rp.role_id = UNHEX(REPLACE(?, '-', ''))
     AND rp.permission_id NOT IN (
       SELECT rp2.permission_id
       FROM user_roles ur
       JOIN roles r ON r.id = ur.role_id AND r.tenant_id = ur.tenant_id
       JOIN role_permissions rp2 ON rp2.role_id = r.id
       WHERE ur.user_id = UNHEX(REPLACE(?, '-', '')) AND ur.tenant_id = UNHEX(REPLACE(?, '-', ''))
         AND ur.revoked_at IS NULL);
   ```
   The audit row's `missingCount` should equal the number of rows returned. Remedy: an actor who holds everything in the role performs the action (an administrator, for example), or the caller is given the missing permissions through a legitimate approval. Do not weaken the check. Note that revoke is also bounded: a delegate cannot revoke a role carrying permissions they lack.
4. **`SELF_ASSIGNMENT`.** The caller is not an administrator, meaning none of their roles carries every permission in the catalogue on its own. Holding the whole catalogue across two roles does not count. Ask an administrator to assign the role instead. If the caller really is an administrator, verify with the query in section 5 that one of their roles holds all 8 permissions (catalogue size after V6; a new permission added later without the B7 footer demotes custom administrator roles).
5. If none of the above explains the 403 and the flags are on, check the audit row for `roleName` null and reason `CROSS_TENANT_TARGET`, and check for `RBAC_GRANT_CHECK_ROLE_NOT_IN_TENANT` (unreachable by design; escalate to Security if present).

**Escalate to Security** if `SELF_ASSIGNMENT` or `GRANT_EXCEEDS_CALLER` repeats for one actor, or the actor's account was created recently (the RES-26 two-account pattern).

## 2. Last-admin 409 (`RBAC_002`)

**Symptom.** `DELETE /api/v1/users/{userId}/roles/{roleId}` returns 409 `RBAC_002` "Cannot revoke the last active TENANT_ADMIN assignment in this tenant".

**What it means.** The revocation would leave the tenant with no distinct active holder of a role able to administer it. The lockout counts distinct active holders of admin-defining roles (a role carrying every catalogue permission), since M3. Authorization is evaluated first, so only a caller allowed to revoke that role ever sees 409.

**Do.**
1. Confirm it is genuine: count active holders of the role (and of other roles that carry every permission) in the tenant.
2. Assign the role to a second, intended administrator first (the caller must be an administrator or hold every permission of that role, A2), then repeat the revoke.
3. Do **not** bypass it with SQL unless a zero-administrator incident is already declared; follow the US-017 runbook for that procedure.

## 3. Throttled actor

**Symptom.** A caller gets 403 on every assign or revoke for up to a minute, even for actions that should be allowed. The audit rows stop appearing for the throttled requests. `nexus_rbac_denial_throttled_total` increases; WARN `RBAC_DENIAL_THROTTLE_ENGAGED` was logged once at the transition.

**Cause.** The actor produced `nexus.rbac.denial-throttle.max-denials` (default 5) gate denials within `window-seconds` (default 60). In M2, A2, A4, revoke-subset and L-1 denials all count. While throttled, requests are rejected before any lock or read, with reason `NOT_TENANT_ADMIN` (a pre-existing label; tidied in M8).

**Diagnose.**
1. Read the preceding durable `ROLE_ASSIGNMENT_DENIED` rows for that actor (monitoring.md section 6) to see which reasons burned the budget. A legitimate operator hitting `GRANT_EXCEEDS_CALLER` five times means they are using the wrong role or lack permissions: fix that, do not raise the limit.
2. Deployments with `nexus.security.rate-limit.store-type: memory` have one counter per replica, so a user may be throttled on one replica and not another (US-016 runbook).
3. Wait for the window to pass. Raising `NEXUS_RBAC_DENIAL_THROTTLE_MAX_DENIALS` is a config-and-restart change and weakens a probe-cost bound; only do it with Security agreement.

## 4. Service-level callers need DB-held permissions

After M2, `RoleAssignmentService` and `RoleManagementService` check the database, not only the token. A caller who has the permission only in a JWT, or whose role was removed after the token was issued, is denied with `PERMISSION_ABSENT`. For operations and tooling:

- **Any script, job or test fixture that creates an actor** must give that actor a real role carrying `user:role:assign` (assign and revoke) or `role:write` (attach) in the `user_roles` and `role_permissions` tables. A claim in a hand-minted token is not enough. This matters for the M7 work (epoch freshness, load and k6 fixtures) and for integration seeds.
- **Break-glass CLI (M5, section 11).** It goes through `BootstrapAdminService`, which never calls `assign()` (an ArchUnit rule enforces this), so A2 and A4 do not apply to it. If a future change makes it call `assign()`, the target-is-self and A2 checks would deny it.
- **Dev seed.** `DevDataInitializer` assigns through `UserRoleAssignmentPort`, not through the services; unaffected.
- A revoked delegate keeps a working token for up to the access-token lifetime for every other endpoint; M2 closes that window only for assign, revoke and attach. M7 is the systemic fix.

## 5. Useful queries

Is a user an administrator (a role carrying every permission)? Returns role ids; ids only.

```sql
SELECT HEX(ur.role_id) AS role_id, COUNT(DISTINCT rp.permission_id) AS permission_count
FROM user_roles ur
JOIN roles r ON r.id = ur.role_id AND r.tenant_id = ur.tenant_id
JOIN role_permissions rp ON rp.role_id = r.id
WHERE ur.user_id = UNHEX(REPLACE(?, '-', '')) AND ur.tenant_id = UNHEX(REPLACE(?, '-', ''))
  AND ur.revoked_at IS NULL
GROUP BY ur.role_id
HAVING COUNT(DISTINCT rp.permission_id) = (SELECT COUNT(*) FROM permissions);
```

Zero-administrator tenants after a deploy: use the `rbacZeroActiveAdmins` health indicator and the US-017 runbook. Restoring an administrator in a tenant with none is done with the break-glass CLI, section 11. Do not use a manual `INSERT`. A tenant whose only administrators are DISABLED is recoverable with the CLI too (O-7, section 11.5).

## 6. Kill switch

Set `feature.nexus-us012-rbac-role-assignment.enabled=false` (assign, list, revoke return 404) or `feature.nexus-us015-rbac-role-management.enabled=false` (role and attach endpoints), then restart. This is an availability lever, not a way back to the old rules; see [rollback.md](rollback.md).

## 7. Redis authentication at startup (M7, T-014)

- [ ] Check that `nexus.rbac.redis.require-auth=true` is resolved in production (the `prod` profile is active and `application-prod.yml` sets it; e.g. `/actuator/env/nexus.rbac.redis.require-auth` where exposed, or the effective config of the deployment). With it false the startup check is inert.

If startup fails with `nexus.rbac.redis.require-auth=true but the "<factory>" Redis connection has no password`, set `spring.data.redis.password`, or put the password in the `spring.data.redis.url` userinfo (with a URL set, Boot ignores the password property). A `Sentinel password` message means `spring.data.redis.sentinel.password` is missing.

## 8. Permission removed outside the API (Flyway or SQL) (M7, T-010)

Revoke and detach make holders' tokens stale and drop their cached permission sets automatically. A permission or role assignment removed by a migration or a direct SQL change does neither: holders keep the permission in their access token (up to 900 s) and in their cached set (up to `NEXUS_RBAC_PERMISSION_CACHE_TTL_SECONDS`, 900 s by default). After such a change, in this order:

- [ ] **Bump the epoch of every affected holder.** List the user ids (for a permission removed from a role, the active holders of that role):
   ```sql
   SELECT BIN_TO_UUID(ur.tenant_id) AS tenant_id, BIN_TO_UUID(ur.user_id) AS user_id
   FROM user_roles ur
   WHERE ur.role_id = UUID_TO_BIN(?) AND ur.revoked_at IS NULL;
   ```
   `BIN_TO_UUID` prints the dashed lower-case form that the Redis keys use; `HEX` would print upper-case ids without dashes, and the script below would then bump keys that nothing reads. Run the same monotonic bump the application runs, for up to 500 keys `{keyPrefix}:rbac:epoch:{tenantId}:{userId}` per call (the last argument is `nexus.rbac.epoch.key-ttl-seconds`, 960 by default):
   ```
   redis-cli EVAL "local t=redis.call('TIME') local now=tonumber(t[1])*1000+math.floor(tonumber(t[2])/1000) local max=9007199254740990 for _,k in ipairs(KEYS) do local r=redis.call('GET',k) local o=0 if r and #r<=16 and string.find(r,'^%d+$') and tonumber(r)<=max then o=tonumber(r) end redis.call('SET',k,string.format('%.0f',math.min(math.max(o+1,now),max)),'EX',ARGV[1]) end return #KEYS" <numkeys> <epoch keys...> 960
   ```
   Each holder's next request then gets 401 `AUTH_003` and the client refreshes. The script applies the application's valid-epoch rule (1 to 16 digits, at most 2^53 - 2; anything else counts as 0, so a corrupt key is replaced by the current time). It does not delete the cached permission sets, hence the flush below.
- [ ] **Flush the permission cache:** `SCAN` with `MATCH {keyPrefix}:rbac:permset:*` and `MATCH {keyPrefix}:rbac:roleset:*`, and `UNLINK` the keys found. The cache is never authoritative; the only cost is one extra database read per next login or refresh.

Not needed after the T-010 deploy itself: cache keys without an epoch suffix are no longer read and expire within the cache TTL.

**Page `nexus.rbac.epoch.bump_failed{operation="detach", reason="holder_read"}`.** A detach committed, but the instance could not read the role's holders after commit, even on a retry (usually pool pressure or a database timeout). The ERROR `RBAC_HOLDER_READ_FAILED` names the tenant and role. Since the M7 part 2 review the instance **queues the role and retries on its 1 s tick**: watch `nexus.rbac.epoch.role_replay_queue_roles` fall to 0 and `nexus.rbac.epoch.role_replayed` rise, and the INFO `RBAC_HOLDER_READ_REPLAYED` for that role. Only act by hand if the queue does not drain within a minute or two (the database is still failing: `bump_failed{operation="role_replay", reason="holder_read"}` keeps rising, with one ERROR `RBAC_HOLDER_READ_FAILED operation=role_replay` per second), or the instance restarted (the queue is in memory), or `bump_failed{reason="role_overflow"}` fired (the role was refused: queue full): then apply the two checklist items above for that role's active holders, within the token TTL (900 s). A role is given up after `key-ttl-seconds` (960 s) without success.

**Ticket on `last_seen_dropped{reason="tenant_cap"}`; page on `reason="capacity"` (pre-PR review L-1).** The per-instance last-seen map (the defence that keeps a revoked token stale while Redis reads fail) shed read-derived users: one tenant reached its share (`nexus.rbac.epoch.last-seen-tenant-percent`, default 10 of 100,000) or the instance reached 100,000. Only users who are revoked during a Redis read failure and not already in the map lose that defence, so it matters if `epoch.check{outcome=skipped_error}` is also rising. Check the tenant's traffic or a very large detach; raise the percentage only with the heap in mind. **Page `reason="bump_dropped"`:** an own bump could not be remembered locally (a tenant over its own-bump ceiling of 4 times its share, or all tenants over the global 200,000). The store has the bump. The instance logs ERROR `RBAC_LAST_SEEN_BUMP_DROPPED {tenantId}` and fails that tenant **closed** for `key-ttl-seconds`: if Redis reads fail or the instance is DegradedOpen meanwhile, all of that tenant's requests get 401 instead of being skipped (a tenant-wide outage, by design, the alternative being an unknown revocation). Nothing to do with a healthy store; with a degraded one, restore Redis first.

**Ticket on any increase of `nexus.rbac.epoch.check{outcome="unparseable"}`.** A stored epoch is not a number or is out of range (`0 .. 2^53 - 2`): Redis write access, or a foreign client writing under the same `nexus.redis.key-prefix` (RES-32). That user's tokens are stale and the next bump (any detach or revoke of that user, or the script of section 8) replaces the value. The WARN `RBAC_EPOCH_UNPARSEABLE` is logged once per tenant per minute with a `suppressed` count and never names the user; find the key with `SCAN MATCH {keyPrefix}:rbac:epoch:{tenantId}:*` and check who has write access.

## 9. Page: `nexus.rbac.epoch.store_regressed` (pre-PR security review M-1)

Redis answered a read or a mint below an epoch this instance already knows. A revoke or detach bump was refused, timed out or lost, while reads keep working, so every instance reports Healthy. The instance still enforces the epoch it knows (the old token gets 401, and a refresh mints an unverified token whose permissions come from the database, uncached), but **other instances do not know it** until the replay lands.

- [ ] **Look for the cause.** `INFO memory` on Redis: `used_memory` against `maxmemory`; with `noeviction` Redis refuses the bump script (`-OOM`) but still serves reads. Then `INFO replication` and the Sentinel log for a failover (a key lost to asynchronous replication reads as 0).
- [ ] **Check the replay.** `nexus.rbac.epoch.bump_failed` and the `RBAC_EPOCH_BUMP_FAILED` / `RBAC_EPOCH_BUMP_REPLAYED` log events. The replay retries every second and drops an entry after 960 s.
- [ ] **If the cause is memory,** free or add memory first; the replay then lands by itself.
- [ ] **If the replay overflowed or an instance restarted,** re-apply the revocation by hand (section 8) for the affected holders.

## 10. Metrics return 401 or 403, or a scrape suddenly fails

`/actuator/prometheus` and `/actuator/metrics/**` accept only the operator's scrape token (pre-PR re-review RR-M2): `Authorization: Bearer <NEXUS_MANAGEMENT_SCRAPE_TOKEN>`. A user or administrator JWT is refused with 401, and a tenant credential must never be used for scraping.
- **403 for everyone:** the token is not set on the instance, which closes both endpoints. Set `NEXUS_MANAGEMENT_SCRAPE_TOKEN` (at least 32 random characters, from a secret) and restart; a shorter value fails startup.
- **401 from the scraper:** the scraper's token differs from the backend's, or it sends something else in the header. Rotate by changing the secret on both sides.
- The token is never logged. Treat it like a password: it can read the degraded state, drop counters and tenant ids in the tags.

## 11. Break-glass: grant the first administrator of a zero-administrator tenant (M5, A7)

**What it is.** An operator-run command that grants the tenant's system `TENANT_ADMIN` role to one existing, ACTIVE user in a tenant that has no administrator. It replaces the manual production `INSERT` that step 4 of `docs/features/US-012/runbook.md` described: that step now points here, and no manual SQL remains in the procedure (FR-A7.d). Design: [03-design.md](03-design.md) section 7; decision record: [ADR-0025](../../adr/0025-break-glass-admin-cli.md). Every invocation, granted or refused, writes a `ROLE_BREAK_GLASS_GRANT` row in `auth_events` and emits the paging ERROR `RBAC_BREAK_GLASS_USED`. Owner of the page: Platform Security on-call.

**Status of the drill.** The staging drill (zero-admin tenant recovered, page received from a Job run exactly as below) and the Kubernetes audit-logging sign-off are open merge conditions (STATUS.md). No environment exists yet, so this procedure has not been exercised outside the automated tests.

### 11.1 Before running: verify and approve (all required)

1. **Verify the requester against the tenant's contractual contact of record.** Never verify against the target account: self-registration makes an attacker-held ACTIVE account in a tenant trivial, and the realistic abuse is "our only admin left, make my account admin" (RC-37.1).
2. **A second person from Platform Security approves**, recorded under the change reference. The operator and the approver are two different people.
3. **Create the change reference** (a ticket id) and record the requester check and the approval on it. Format `^[A-Z][A-Z0-9]{1,9}-[1-9][0-9]{0,7}$`: capital-letter prefix of 2 to 10 letters or digits, a hyphen, and a number of 1 to 8 digits with **no leading zero** (`OPS-123` is valid; `ops-123`, `OPS-0123` and free text are not). Use ids only: no names, emails or tokens in the reference or the ticket text.
4. **One reference approves one grant, anywhere.** A reference already on a SUCCESS grant row in **any** tenant is refused with exit 6 (RC-37.2, RC-47). A refusal row does not use up a reference: after a refusal such as exit 3, fix the cause and re-run with the same reference. If the tenant falls to zero administrators again later, it needs a new reference and a new approval.
5. **One invocation per tenant at a time, and one per reference at a time.** Two concurrent runs on one zero-administrator tenant can deadlock (exit 7). Two concurrent runs with the same reference could both pass the replay check if they target two different zero-administrator tenants (accepted risk T-S11), so do not run them in parallel.
6. Know the target user's UUID and confirm the user is ACTIVE and belongs to the intended tenant. The tool takes the tenant from the user's own row; there is no tenant argument.

### 11.2 Run

The command, from the same image as the service, with the service's `nexus_app` database credential and the `break-glass` profile (see [deployment.md](deployment.md) section 11):

```
java -jar nexus-backend.jar --spring.profiles.active=<env>,break-glass --target-user-id=<user-uuid> --change-ref=<TICKET-123>
```

- Run it as a Kubernetes Job (or equivalent) so the pod log is shipped. **Do not use `kubectl run --rm`** or a Job with a short TTL: the pod can vanish before the log shipper reads the page (RC-37.4). The process waits one log-shipper flush interval (default 15 s) before it exits to give the shipper time. Do not kill it during the wait. `--rm` is allowed only if the staging drill has proved capture without it.
- Both options are required, exactly once each. The UUID must be in canonical lower-case dashed form.
- The process exits with a code from the table below. Read it from the Job/pod status, and read the pod log.

### 11.3 Exit codes

The reason below is the `reason` in the audit row and in the page. Exit codes are fixed in `BreakGlassRefusalReason`.

| Exit | Reason | Meaning | Action |
|---|---|---|---|
| 0 | (granted) | The system `TENANT_ADMIN` role was granted to the target. SUCCESS row written in the same transaction; the GRANTED page is sent after commit | Verify (11.4) |
| 1 | `UNEXPECTED_ERROR` | See 11.3.1. Ambiguous | Follow the two lines in 11.3.1 |
| 2 | `INVALID_ARGUMENT` | A missing, repeated or malformed option. The row and the page carry **no argument value**, by design | Correct the options and re-run with the same reference (nothing was used up) |
| 3 | `TARGET_USER_NOT_FOUND` / `TARGET_USER_NOT_ACTIVE` | The user does not exist, or is not ACTIVE. The status is checked again inside the grant transaction, under the lock, so a user disabled while the tool runs is refused, never granted (L-2) | Check the user id and the user's status through the normal process; do not edit the user by SQL |
| 4 | `NO_SYSTEM_ADMIN_ROLE` | The tenant has no seeded system `TENANT_ADMIN` role. The tool does not create roles (per-tenant seeding is Epic 3) | Escalate to the Architect; there is no supported fix with this tool |
| 5 | `TENANT_HAS_ADMIN` | The tenant already has an administrator whose user is not DISABLED: ACTIVE, PENDING or LOCKED (including after a successful earlier run, so a re-run is safe). Holders whose user is DISABLED do not count (11.5). Break-glass is not a general admin-granting path | Recover through that tenant's own administration. A LOCKED administrator recovers when the lockout expires |
| 6 | `CHANGE_REF_REUSED` | The reference is already on a SUCCESS grant row in any tenant | Obtain a new reference and a new second approval. Never reuse an old one |
| 7 | `CONCURRENT_INVOCATION` | The grant transaction lost a lock race (deadlock or lock wait timeout) and rolled back. No grant, no SUCCESS row | Make sure no other run is in progress for the tenant, then re-run with the same reference (it was not used) |

Each non-zero code except the crash case in 11.3.1 is written to `auth_events` as a FAILURE row and paged. Rows for exits 2 and 6 carry a null tenant id (no user has been resolved yet); the other refusal rows carry the target's tenant id once it is known.

If the pod log has an ERROR `RBAC_BREAK_GLASS_ALERT_FAILED` for a refusal, the refusal page was not sent. The exit code and the FAILURE row are unaffected (security review L-1): act on the exit code as above and **page Platform Security manually**.

#### 11.3.1 Exit 1 is ambiguous

Exit 1 is also what Spring Boot and the JVM report for a failed start or an uncaught exception, so it covers two situations. Tell them apart by the pod log:

- **Exit 1 with no `RBAC_BREAK_GLASS_USED` in the pod log: page Platform Security manually.** The process failed before or outside the grant transaction (for example the database was down during the replay lookup). No row was written and no page was sent, and the daily reconciliation looks at SUCCESS rows only, so nothing else will notice.
- **Exit 1 with a `RBAC_BREAK_GLASS_USED` line (reason `UNEXPECTED_ERROR`): verify `user_roles` and `auth_events` before re-running.** The grant transaction failed (a failed SUCCESS audit write, a lost connection, a failed commit) and rolled back, and the refusal was audited and paged. Check, by ids only, whether the target holds an active `TENANT_ADMIN` row and whether a SUCCESS `ROLE_BREAK_GLASS_GRANT` row exists for the reference, before deciding to re-run:
  ```sql
  SELECT HEX(id) AS event_id, created_at, outcome,
         JSON_UNQUOTE(JSON_EXTRACT(metadata, '$.reason')) AS reason
  FROM auth_events
  WHERE event_type = 'ROLE_BREAK_GLASS_GRANT'
    AND JSON_UNQUOTE(JSON_EXTRACT(metadata, '$.changeRef')) = ?
  ORDER BY created_at;
  ```
  A re-run is safe: if the grant did commit, the re-run exits 6 (reference used) or 5 (tenant has an administrator).

If the page was received but the process shows a start failure with reason `WEB_CONTEXT`, the `break-glass` profile was activated where a web server would start. The context refresh fails before any port is bound; do not work around it. Run the CLI in its own Job instead of a serving pod.

### 11.4 After a grant (exit 0)

- [ ] The pod log has `RBAC_BREAK_GLASS_USED` for the run, and the page was received. If the log has an ERROR `RBAC_BREAK_GLASS_ALERT_FAILED`, the grant stands (exit stays 0) but the page was not sent: **page Platform Security manually**.
- [ ] A SUCCESS `ROLE_BREAK_GLASS_GRANT` row exists for the reference (query in 11.3.1).
- [ ] The target holds an active `TENANT_ADMIN` assignment (section 5 query). In `user_roles` the row shows `assigned_by` equal to the target user. That is how a break-glass grant looks (the operator is not written into tenant data); join it to the `ROLE_BREAK_GLASS_GRANT` row before treating it as a self-assignment finding (RC-37.5).
- [ ] Ask the user to log in again. The break-glass grant does not evict the user's cached permission set, so the new administrator may see the old permissions until the cache TTL (900 s by default) passes or the next login. This fails toward fewer privileges.
- [ ] Join the change reference to the infra access log (Kubernetes API audit: pod create and exec with user identity) and record the result on the ticket.
- [ ] The daily reconciliation (monitoring.md section 7) matches this SUCCESS row to its ticket.

### 11.5 A DISABLED sole administrator (O-7, decided 2026-10-15)

**Behaviour.** For break-glass only, an administrator whose user is **DISABLED** does not count. A tenant whose only administrators (holders of `TENANT_ADMIN` or of a role carrying all three dangerous permissions) are all DISABLED is treated as having none: the CLI grants `TENANT_ADMIN` to the target (exit 0), writes the SUCCESS row and pages, like any other grant. Disabling a compromised or departed sole administrator is the most likely reason to need break-glass, so this case is recoverable with the audited tool and needs no manual SQL.

- An administrator whose user is ACTIVE, PENDING or **LOCKED** still counts, so the CLI refuses with exit 5. A LOCKED account is a temporary lockout that recovers by itself.
- One ACTIVE administrator next to DISABLED ones is enough to refuse with exit 5.
- The statuses are read inside the grant transaction, under the lock, so a concurrent re-enable or disable is either seen or waits for the grant to finish.
- The rule applies to break-glass only. The last-administrator guard on revoke, the assign and revoke checks and the `rbacZeroActiveAdmins` health indicator still count every holder whatever the user's status. In particular, the health indicator does **not** report a tenant whose only administrators are DISABLED; the request comes through the normal recovery channel (11.1).

**Before running.** Confirm through the normal process that each existing administrator account is DISABLED (not LOCKED) and should stay so, and record that on the change reference with the approval (11.1). Do not re-enable or disable accounts to steer the outcome.

**After the grant.** The DISABLED holder keeps its `TENANT_ADMIN` assignment; the grant does not touch it. Once the new administrator has logged in, they revoke the DISABLED holder's assignment through the normal API (the last-administrator guard allows it, because the new administrator is now a holder too), so a later re-enable of that account does not silently restore its administrator rights. Record the revoke on the ticket.

Do not add or use any CLI override flag; none exists.

## 12. M3: refusals and signals after the name-based gate was retired

- **409 `RBAC_010` on attach.** The attach would make the role admin-defining while an active holder was assigned by someone who is not an administrator. Look up the holders (`user_roles.assigned_by`) of the role; have an administrator re-assign or revoke those holders, then retry. The response names no holder; the WARN `RBAC_ATTACH_PROVENANCE_REFUSED` carries only the count.
- **403 on detach (`GRANT_EXCEEDS_CALLER`, WARN `RBAC_ROLE_SUBSET_DENIED`).** The caller must hold every permission of the role; for an admin-defining role they must also be an administrator through another role. Ask an administrator to detach.
- **Page: `role_became_admin_defining` with holders.** Check the holders of the role (`holders="unknown"` means the after-commit read failed, so read them by hand). If the attach was not intended, detach the permission with an administrator account and review who attached it (`ROLE_PERMISSION_GRANTED` row).
- **Page: `RBAC_SELF_ASSIGN_ADMIN_DISAGREEMENT`.** The authorization check and the independent statement disagree about the caller. Treat as a defect in the administrator definition or a race on role data; collect the user's roles and each role's permission count versus the catalogue count and escalate to the owning team. The assignment itself was decided by A4.
- **Health component `rbacZeroActiveAdmins` DOWN.** A tenant has an admin-defining role with no active holder. Follow the US-017 zero-administrator procedure, or the break-glass CLI (section 11); the definition now includes custom roles carrying the whole catalogue.
- **Concurrent detach (RES-28) and the attach snapshot (RES-27)** are accepted, detective-only races: a role can lose admin-defining status through two concurrent detaches, and the indicator is what notices.
