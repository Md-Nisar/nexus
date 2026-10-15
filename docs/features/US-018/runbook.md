# US-018: Runbook

**Scope:** Milestone 2 (A1 to A4, M-1, L-1, L-2, L-5) in sections 1 to 10, and Milestone 5 (A7 break-glass first-administrator CLI) in section 11. **Audience:** on-call engineer with no prior context. Companions: [monitoring.md](monitoring.md), [rollback.md](rollback.md), [09-technical.md](09-technical.md), and the US-016 and US-017 runbooks for the legacy gate, the denial throttle and the zero-administrator procedure.
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
   | `NOT_TENANT_ADMIN` | `RBAC_PRIVILEGED_ROLE_CHANGE_BLOCKED` or `RBAC_DENIAL_THROTTLE_ENGAGED` | Legacy gate for privileged roles, or the actor is throttled | Section 3 |
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

**What it means.** The revocation would leave the tenant with no distinct active holder of a role able to administer it. The lockout is intact and unchanged by M2; in M2 it still uses the US-017 admin-equivalent definition (re-scoped to admin-defining roles in M3). Authorization is evaluated first, so only a caller allowed to revoke that role ever sees 409.

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
- **Break-glass CLI (M5, section 11).** It goes through `BootstrapAdminService`, which never calls `assign()`, so A2 and A4 do not apply to it. If a future change makes it call `assign()`, the target-is-self and A2 checks would deny it.
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

Zero-administrator tenants after a deploy: use the `rbacZeroActiveAdmins` health indicator and the US-017 runbook. Restoring an administrator in a tenant with none is done only with the break-glass procedure in section 11. Manual SQL is not a supported path.

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

## 11. Break-glass: restore the first administrator of a zero-administrator tenant (M5, A7)

**Why this section exists.** Self-registration makes it easy to hold an ACTIVE account in a tenant, and the realistic abuse is social ("our only admin left; make my account admin"). The controls that make the tool safe are procedural and live here: who may ask, who must approve, how the Job is run, and how the result is checked. The code only grants when the tenant has zero administrators, the user is ACTIVE and the tenant has a seeded system `TENANT_ADMIN`. References: ADR-0025, threat model RC-37.x, RC-47, RC-54(a), [09-technical.md](09-technical.md) section 13.

**Manual SQL is no longer a supported path.** The `INSERT` in `docs/features/US-012/runbook.md` section 2 step 4 is retired and points here. Do not insert into `user_roles` by hand, even in an incident.

### 11.1 When it applies, and when it does not

Use it only when **all** hold:
- [ ] The tenant has **zero administrators**: `rbacZeroActiveAdmins` is DOWN for it and the confirmation query in the US-012 runbook section 2 step 2 returns no row for the tenant.
- [ ] The tenant has a seeded system `TENANT_ADMIN` role (the CLI never creates roles; per-tenant seeding is Epic 3).
- [ ] The person to be made administrator (the target) has an ACTIVE account in that tenant.
- [ ] A ticket exists, with the approvals in 11.2 recorded on it.

Do **not** use it:
- when the tenant still has an administrator (exit 5). Ask that administrator to assign roles through the API;
- to add a second or later administrator, to repair a role, or to grant any role other than `TENANT_ADMIN`;
- to fix a locked, unverified or forgotten-password account. Use the normal account flows;
- for a tenant with no seeded `TENANT_ADMIN` (exit 4). Escalate to engineering; do not work around it with SQL;
- to re-run a grant that already committed (see exit 1 and exit 6).

### 11.2 Before you run it: verify, approve, record

1. **Verify the requester against the tenant's contractual contact of record**, through the contact details held in the contract system, not the ones in the request and **never the target account's own email or phone**. Record the date and method on the ticket, using user, tenant and role UUIDs only (no emails, names or tokens).
2. **A second person from Platform Security approves**, in writing, on the same ticket, before the Job is created. The operator and the approver are different people. Record the approver's role and the approval time. TODO(owner): name the exact approver group (for example the Platform Security on-call rota).
3. **Change reference.** `--change-ref` is the ticket id, in one canonical form: `[A-Z][A-Z0-9]{1,9}-[1-9][0-9]{0,7}` (for example `OPS-1234`). No leading zero in the number (`OPS-01234` is rejected), ASCII only, no free text. The same ticket id carries the approvals in step 2.
4. **Never reuse a reference.** A reference that already appears on a successful grant is refused (exit 6), in any tenant. A second recovery needs a new ticket and a new approval.
5. **One invocation at a time per reference.** Do not start a second Job for the same reference until the first has finished and its outcome is recorded. The replay check is a non-locking read, so two concurrent runs of one reference can both pass it. Creating the Job with a name derived from the reference (11.3) makes Kubernetes reject a duplicate name.
6. **Confirm the infra audit is on**: Kubernetes API audit logging (pod create and exec, with user identity) retained for at least 1 year. Without it the change reference joins to nothing. TODO(owner): Ops names the audit-log location and confirms retention (RC-37.3, merge checklist).

### 11.3 Run it as a Kubernetes Job

Use a Job in the same namespace as the serving Deployment, with **the same image** and the **same environment and secret references** as the serving pods (database URL and the `nexus_app` credentials, crypto keys and the rest). Do not copy ports or probes; the profile starts no web server and runs no Flyway.

The image's entrypoint is `sh -c "java $JAVA_OPTS -jar app.jar"`, which ignores container `args`, so the Job overrides the command. The arguments follow the script name and reach `java` as `"$@"`.

```yaml
apiVersion: batch/v1
kind: Job
metadata:
  name: break-glass-<ref-lowercase>          # for example break-glass-ops-1234; a duplicate name is rejected
  namespace: <namespace>
  labels: { app: nexus-break-glass, change-ref: <ref-lowercase> }
spec:
  backoffLimit: 0                            # never retry automatically (see exit 1)
  activeDeadlineSeconds: 600
  ttlSecondsAfterFinished: <TTL>             # TODO(owner): long enough for the log shipper and the post-run checks; see below
  template:
    spec:
      restartPolicy: Never
      containers:
        - name: break-glass
          image: <same image as the serving Deployment>
          command: ["sh", "-c", "exec java $JAVA_OPTS -jar app.jar \"$@\"", "break-glass"]
          args:
            - --spring.profiles.active=<env>,break-glass
            - --target-user-id=<uuid>
            - --change-ref=<ref>
          envFrom: [ <same configMapRef and secretRef as the serving Deployment> ]
```

Rules:
- [ ] `--spring.profiles.active=<env>,break-glass`: the environment profile first, then `break-glass`. The profile sets `spring.main.web-application-type=none` and `spring.flyway.enabled=false`. A servlet context, or a lazy-initialisation override, fails the start (exit 1, page `reason=WEB_CONTEXT`).
- [ ] **No `kubectl run --rm`, and no short Job TTL**, unless the staging drill proved the page and logs are captured without it (RC-37.4). Keep the finished Job and pod until the checks in 11.5 are done.
- [ ] The runner waits `nexus.rbac.break-glass.log-flush-interval` (default 15 s) before exiting so the node's log shipper can read the page. It must be at least the shipper's flush interval. TODO(owner): SRE states the shipper's flush interval and confirms the default.

**Confirm the page arrived.** Every invocation, including a refusal, logs an ERROR line beginning `RBAC_BREAK_GLASS_USED outcome=<GRANTED|REFUSED|ERROR>`, with `reason`, `tenantId`, `targetUserId` and `changeRef` where known. Confirm it **in the paging/alerting system**, not only in `kubectl logs`. If it did not arrive, treat the run as unrecorded in the alert channel, tell Platform Security, and rely on the audit row and the daily reconciliation (11.6). TODO(owner): name the alert channel and the on-call rota that receives `RBAC_BREAK_GLASS_USED`, and the log retention for it (RES-6).

### 11.4 Exit codes

Read the exit code with `kubectl get pod -l job-name=<job> -o jsonpath='{.items[0].status.containerStatuses[0].state.terminated.exitCode}'`.

| Exit | Meaning | Page | What to do |
|---|---|---|---|
| 0 | Granted. The target now holds the tenant's `TENANT_ADMIN` | `outcome=GRANTED` | Run 11.5. Close the ticket with the result |
| 1 | Unexpected error. A database or audit failure, a deadlock (two concurrent first grants: one loses and rolls back), a failed context start (including `reason=WEB_CONTEXT`) | `outcome=ERROR reason=UNEXPECTED_ERROR` (carries `targetUserId` and `changeRef` when they passed validation), or no page if the context never started | **Do not re-run yet.** The grant may have committed with its acknowledgement lost. First check the audit table for the reference (query below). A `SUCCESS` row means it worked: go to 11.5. No row, and the tenant still has no administrator: read the pod logs, fix the cause (database reachable, schema version matches the image, profile and arguments right), and only then re-run with a **new reference and a new ticket approval**. Tell Platform Security |
| 2 | Invalid argument: missing, repeated, or not a canonical UUID or reference | `outcome=REFUSED reason=INVALID_ARGUMENT`, with no identifiers by design | Correct the Job. The rejected value is never echoed, so compare with the ticket. The reference was not used, but a refusal row was written |
| 3 | Target user not found, or not ACTIVE (`reason=USER_NOT_FOUND` or `USER_NOT_ACTIVE`) | `outcome=REFUSED` | Check the UUID against the ticket. Do not activate or create the account as part of this procedure; that needs its own approval |
| 4 | No system `TENANT_ADMIN` role in the tenant (`NO_SYSTEM_ADMIN_ROLE`) | `outcome=REFUSED` | Stop. Escalate to engineering. Do not create the role by hand |
| 5 | The tenant already has an administrator (`TENANT_HAS_ADMIN`) | `outcome=REFUSED` | Stop. The tenant is not a zero-admin tenant (or a previous run already succeeded). Tell the requester to use the administrator; check whether an earlier run of this ticket granted (query below) |
| 6 | The change reference was already used on a successful grant (`CHANGE_REF_REUSED`) | `outcome=REFUSED` | Do not re-run with the same reference. Find the earlier grant (query below). If the earlier grant is the one wanted, treat the work as done. If not, this is a possible replay of an old approval: tell Platform Security, and use a new ticket with new approvals only after they agree |

**Look up a reference (ids and counts only, parameters bound, read-only).** A reference is global across tenants:

```sql
SELECT BIN_TO_UUID(ae.id) AS event_id, ae.created_at, ae.outcome,
       BIN_TO_UUID(ae.tenant_id) AS tenant_id, BIN_TO_UUID(ae.user_id) AS target_user_id,
       JSON_UNQUOTE(JSON_EXTRACT(ae.metadata, '$.reason')) AS reason
FROM auth_events ae
WHERE ae.event_type = 'ROLE_BREAK_GLASS_GRANT'
  AND JSON_UNQUOTE(JSON_EXTRACT(ae.metadata, '$.changeRef')) = ?
ORDER BY ae.created_at;
```

A refusal row can be missing even though the Job refused (a lost audit write is logged as `RBAC_AUDIT_WRITE_LOST`); the page and the Job's exit code are the other evidence.

### 11.5 After a successful run (exit 0)

- [ ] **Audit row.** The query above returns one `SUCCESS` row for the reference, with the right `tenant_id` and `target_user_id`. Its `metadata` has `actorType` `BREAK_GLASS_CLI` and `changeRef`.
- [ ] **Assignment.** The target holds an active `TENANT_ADMIN` assignment in the tenant, and `assigned_by` equals the target's own id (by design, ADR-0025 5):
  ```sql
  SELECT BIN_TO_UUID(ur.user_id) AS user_id, BIN_TO_UUID(ur.assigned_by) AS assigned_by, ur.revoked_at
  FROM user_roles ur JOIN roles r ON r.id = ur.role_id AND r.tenant_id = ur.tenant_id
  WHERE ur.tenant_id = UUID_TO_BIN(?) AND ur.user_id = UUID_TO_BIN(?)
    AND r.name = 'TENANT_ADMIN' AND r.is_system_role = TRUE;
  ```
- [ ] **Health.** `rbacZeroActiveAdmins` returns to UP for the tenant.
- [ ] **The new administrator can log in** and perform a `user:write` action. Ask the requester's contact of record to confirm, not the target by an unverified channel. The permission cache is evicted by the grant; if the user still sees 403, ask them to log in again.
- [ ] **Record on the ticket**: Job name, exit code, page received (yes or no), audit `event_id`, approver, verifier, date. Then delete the Job.
- [ ] **Access reviewers** will see this grant as `assigned_by = target` in the assignment list and the holders view. Tell them to join it to `ROLE_BREAK_GLASS_GRANT` before raising a finding (the join is on tenant, user and time; the reference is in the row metadata).

### 11.6 Daily reconciliation (backstop for a lost page)

A daily ticket-level alert fires on any new `ROLE_BREAK_GLASS_GRANT` row (SUCCESS or FAILURE) in the last 24 hours. Each row it reports must match a ticket with the verification and the second approval recorded. Review it the next working day:

```sql
SELECT ae.created_at, ae.outcome, BIN_TO_UUID(ae.tenant_id) AS tenant_id, BIN_TO_UUID(ae.user_id) AS user_id,
       JSON_UNQUOTE(JSON_EXTRACT(ae.metadata, '$.changeRef')) AS change_ref,
       JSON_UNQUOTE(JSON_EXTRACT(ae.metadata, '$.reason')) AS reason
FROM auth_events ae
WHERE ae.event_type = 'ROLE_BREAK_GLASS_GRANT' AND ae.created_at >= NOW(6) - INTERVAL 1 DAY
ORDER BY ae.created_at;
```

A row with no ticket, or a ticket with no second approval, is a security incident: tell Platform Security, and check the Kubernetes audit log for who created the Job (11.2 step 6). A `FAILURE` row with `reason=INVALID_ARGUMENT` has a null tenant and user by design. TODO(owner): the alerting platform, the exact alert rule, and who owns the daily review. This alert is live before merge (merge checklist).

### 11.7 Drill and open items

The staging drill must recover a zero-administrator tenant from a Job run **exactly as written above** and receive the page (RC-37.4); until then 11.3 is unproven, including the command override and the "no `--rm`" rule. TODO(owner): record the drill result and date here.
