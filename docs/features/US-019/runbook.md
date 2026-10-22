# US-019 Runbook

**Audience:** on-call engineer. **Companions:** [monitoring.md](monitoring.md) (names, queries), [deployment.md](deployment.md), [rollback.md](rollback.md). US-018 scenarios (403 `RBAC_001`, last-admin 409 `RBAC_002`, break-glass) are in [../US-018/runbook.md](../US-018/runbook.md) and still apply. Ids only; never paste an email into a ticket.

## 1. 429 on the directory or on assign/revoke

**Symptom.** A response is 429 with `Retry-After` (seconds). The code says which limit:

| Code | Limit | Where it comes from |
|---|---|---|
| `USER_DIR_001` | Email lookup: 30 per 60 s per (tenant, actor) | `nexus.identity.directory.lookup.*` |
| `USER_DIR_002` | Every directory call: 600 per 60 s per (tenant, actor) | `nexus.identity.directory.ceiling.*` |
| `RBAC_011` | The actor was denied `nexus.rbac.denial-throttle.max-denials` times (default 5) within the window (60 s); now blocked on admin-defining and self targets only | `nexus.rbac.denial-throttle.*` |

**Diagnose.**
1. Read `Retry-After`; the client should wait that long. A human at the console does not reach 600 calls a minute, so `USER_DIR_002` points to a loop in a client or to a stolen token.
2. Find the actor: WARN `IDENTITY_DIRECTORY_THROTTLED` (one per window per bucket, fields `tenantId`, `actorUserId`, `bucket`) or, for `RBAC_011`, WARN `RBAC_DENIAL_THROTTLE_ENGAGED`. Counters: `directory.requests{outcome="throttled"}`, `nexus_rbac_denial_throttled_total`.
3. Look at what the actor did: `auth_events` `USER_DIRECTORY_READ` rows (monitoring.md section 2), and for `RBAC_011` the preceding `ROLE_ASSIGNMENT_DENIED` rows (US-018 monitoring.md section 5). Denials after the throttle tripped write no row.
4. Many lookups with mostly `MISS` results from one actor is an enumeration pattern: treat it as a security event and hand over to Security.

**Do.** Wait out the window. Do not raise the limits to make a symptom go away; they are properties in `application.yml` and a change needs a restart and Security agreement. The directory buckets fail open when the rate-limit store is down, so a missing 429 during a Redis outage is expected; `RBAC_011` needs the shared store (`require-shared-store`, P-10).

## 2. 409 `RBAC_012` on assign or attach

**Meaning.** The role changed class (became admin-defining, or the PII rule now denies) while the request waited on a lock. The insert was rolled back and no audit row was written. Nothing is half-done.

**Do.** The client retries **exactly once** with a fresh request. The retry can legitimately end in 403 (the set-lock path now applies the grant-subset rule to the now admin-defining role) or 409 `RBAC_010`. A second `RBAC_012` is shown to the user; the client never loops.

**If it is frequent.** `nexus_rbac_role_classification_changed_total{operation}` and INFO `RBAC_ROLE_CLASSIFICATION_CHANGED` show the role and operation. A burst on one role means two people are editing that admin-defining role at once; ask them to serialise. A sustained rate with no human explanation is worth Security's attention, because the interleaving needs a permission-set change racing an assign.

## 3. 412 or 428 on `PUT /api/v1/roles/{roleId}/permissions`

- **428 `PRECONDITION_REQUIRED`:** the request had no usable `If-Match`. It must carry exactly one strong quoted tag, the `ETag` of a prior `GET /api/v1/roles/{roleId}/permissions`. `*`, a list, a weak tag (`W/`), an empty value and an unparseable value all give 428. The body shows no state. A proxy that strips the header produces the same symptom: compare the client request with what the backend received (the 428 counter is `permission_replace{outcome="precondition_required"}`).
- **412 `PRECONDITION_FAILED`:** the set changed since the client read it (another editor, or this client's own earlier PUT: a replay after success returns 412 because the tag moved). The client re-reads the role, shows the new set and lets the user reapply. Nothing to fix server-side. The check runs again on the locked state, so a 412 can also come from a change that committed during the request.
- **Order:** 403 is decided before 412, so an unauthorised caller never gets a 412. A 412 rate above 20% for 15 minutes is a UX signal (alert in monitoring.md), not an incident.
- **No-op:** a PUT whose set equals the current one is a 200 with no audit row and no change.
- **Browser clients:** CORS allows the `If-Match` request header and exposes `ETag`. A browser that cannot read the `ETag` indicates a CORS configuration problem on that origin.

## 4. Directory audit gaps

**Expected design:** one `USER_DIRECTORY_READ` row per **successful** read; a by-id 404 writes none (P-18); the audit is best-effort and written after the read transaction ends, so a read never fails because its audit row did.

**Check a gap.**
1. Compare the INFO log `IDENTITY_DIRECTORY_READ` count for the window with the `USER_DIRECTORY_READ` row count for the same tenant. The log is written even when the row is not.
2. Search for "Failed to persist auth event" with `type=USER_DIRECTORY_READ`: the database refused the row and it went to the retry buffer.
3. Look at `nexus.audit.buffer.depth`, `...oldest.age.seconds`, `nexus.audit.retry.exhausted` and `nexus.audit.buffer.dropped`. Exhausted or dropped means those rows are permanently missing.
4. WARN `IDENTITY_DIRECTORY_AUDIT_WRITE_FAILED` and `directory.audit_write_failed` mean the row could not even be built.

**Note.** On an audit store outage `directory.audit_write_failed` does **not** fire, because writes are buffered. Do not use it to prove the audit is healthy. Rows still in the buffer when an instance restarts are lost (the buffer is in memory).

**Do.** Restore the store; the buffer drains on its own (every 10 s by default). Record the window of any loss in the incident. The read data was served correctly.

## 5. Page: `RBAC_ADMIN_DEFINING_ROLE_HAS_NON_ADMIN_ASSIGNED_HOLDER`

**Meaning.** After a commit, a role that carries every catalogue permission has an active holder whose `assigned_by` is not an administrator. That is the pre-positioned second account pattern (RES-26): the holder is now an administrator. The preventive control (`RBAC_010` on attach and on a promoting replace) failed or was bypassed, for example by SQL or by a path outside the API.

**Do.**
1. From the WARN take `tenantId`, `roleId`, `holderCount`, `nonAdminAssignedCount`. Declare a security incident; the counter has no tenant tag.
2. List the role's active holders and who assigned them (ids only):

```sql
SELECT HEX(ur.user_id) AS holder, HEX(ur.assigned_by) AS assigned_by, ur.assigned_at
FROM user_roles ur
WHERE ur.role_id = UNHEX(REPLACE(?, '-', '')) AND ur.tenant_id = UNHEX(REPLACE(?, '-', ''))
  AND ur.revoked_at IS NULL;
```

3. For each holder whose assigner is not an administrator of that tenant: contact the tenant owner and Security. If the assignment is not legitimate, an authorised administrator revokes it through `DELETE /api/v1/users/{userId}/roles/{roleId}` (the last-administrator guard still applies). Do not edit `user_roles` by SQL (append-only; no `DELETE` grant).
4. Investigate the assigner and the role's recent changes: `ROLE_PERMISSION_GRANTED`/`ROLE_PERMISSION_REVOKED` rows and `RBAC_PERMISSION_SET_REPLACED` logs (`replaceId`, `replacedBy`).
5. A break-glass grant (the target is its own assigner and is an administrator) never trips the detector or the attach rule, so a page is not explained by a break-glass run.

## 6. Lockout and administrator status after V11

- **No administrator left in a tenant.** `rbacZeroActiveAdmins` is red. Recover with the break-glass CLI (US-018 runbook section 11). Revoke of the last administrator is refused with 409 `RBAC_002`, and a B8 demotion of an admin-defining role is refused with 403 unless the caller stays an administrator through another role.
- **An administrator suddenly lacks admin rights after V11.** Admin status means "holds every row of `permissions`", now nine. A custom role that held seven or eight of the old eight did not gain the new permission and was not an administrator role before either. A role created after V11 needs nine. Check with the US-018 runbook section 5 query (it compares against the live catalogue size).
- **An administrator gets 403 `RBAC_001` on the directory right after enabling the flag.** The token predates V11 and lacks `user:directory:read`, or the cache is stale. Follow the deployment ordering: flush `permset`/`roleset`, wait 1,800 s or flush again after 900 s, or verify a freshly refreshed token, then retry. Disabling the directory flag restores the old state; the SPA sends the user to `/access-denied`.
- **A non-administrator cannot grant `user:directory:read`.** By design (`RBAC_PII_PERMISSION_GRANT_DENIED`, 403 with reason `ADMINISTRATOR_REQUIRED` expected). Ask an administrator.
- **Unexpected holders of `user:directory:read`** after V11: footer (a) gave it to every custom role that held all eight earlier permissions (deployment.md section 4). Review those roles.

## 7. A dev persona login works in a shared environment

WARN `DEV_SEED_ACTIVE` means the `dev` profile is active and known-password accounts were created. Stop the instance, disable the profile, and treat the accounts as compromised (rotate or delete them through the normal process). The seeders never run with the `prod` or `break-glass` profiles.
