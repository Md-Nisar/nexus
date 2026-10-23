# US-019 Technical Documentation

**Feature:** US-019, prerequisites for the RBAC access management UI (EPIC-002). 28 tasks, all implemented on `feature/US-019`. The console itself is US-020.
**Design:** [03-design.md](03-design.md) (approved Gate 2, with the dated amendments at its end). **Threat model:** [03b-threat-model.md](03b-threat-model.md). **Tasks:** [04-tasks.md](04-tasks.md). **ADRs:** [0021](../../adr/0021-grant-subset-authorization-model.md) (Rev 3), [0026](../../adr/0026-user-directory-permission-and-pii-transport.md), [0027](../../adr/0027-role-permission-set-optimistic-concurrency.md) (all Proposed).
**Reviews:** [06-code-review.md](06-code-review.md), [07-security-review.md](07-security-review.md), [08-test-audit.md](08-test-audit.md). **Open work:** [14-pending-items.md](14-pending-items.md).
**Operations:** [deployment.md](deployment.md), [rollback.md](rollback.md), [monitoring.md](monitoring.md), [runbook.md](runbook.md).
**API spec:** no `api-spec.json` is committed. It is generated from the running app at release time (`/v3/api-docs`). The OpenAPI annotations (`@ProblemResponse` per operation, `x-nexus-error-codes`) are covered by `OpenApiErrorCatalogueTest`.
No PII: people are referred to by role, identifiers are UUIDs.

---

## 1. Overview

US-019 adds what the access management console needs and nothing the console itself owns.

| Slice | Delivers | Flag |
|---|---|---|
| Directory (B1, B2) | Tenant-scoped user list, batch by ids, get by id, exact-email lookup | `feature.nexus-us019-user-directory.enabled` |
| B4 | `GET /api/v1/users/me/authorization` | same flag |
| B3, B5, B6 | `GET /api/v1/roles/{roleId}`; `isSensitive` on permissions; `memberCount` and `permissionCount` on roles | `feature.nexus-us015-rbac-role-management.enabled` |
| B7 | `reason` on 403 `RBAC_001`; throttled assign/revoke answers 429 `RBAC_011` | none new (assign and revoke ride us012) |
| B8 | `PUT /api/v1/roles/{roleId}/permissions`, atomic, `If-Match` | us015 |
| Platform handlers | 400/405/415 for malformed requests instead of 500 | none |
| V11 | Permission `user:directory:read` (catalogue 8 to 9 rows) | none |
| Frontend | Signed-in shell, guard composition, Not Found, `returnUrl`, contrast tokens, wrappers, labels | none |
| Environments | Seven dev personas plus a fixture-only second tenant; full-stack e2e workflow | n/a |

## 2. Key decisions

- **A new permission, not `user:read`.** The directory returns email addresses, so it has its own permission, `user:directory:read`, seeded by V11 (id `019f6839-1808-7000-8000-000000000009`). System MEMBER does not get it.
- **Only an administrator may grant it** (`nexus.rbac.pii-grant-requires-administrator`, default `true`, RC-60.3). A non-administrator grant is refused with `RBAC_PII_PERMISSION_GRANT_DENIED` (WARN). With the key set to `false` the grant is allowed and each one logs `RBAC_PII_PERMISSION_DELEGATED`; startup logs `RBAC_PII_GRANT_RULE_DISABLED`. D5 sign-off: 2026-10-20, Md Nisar Ahmed.
- **The administrator definition did not change** (ADR-0021 D3): a role is admin-defining iff it carries every row of `permissions`. V11 grew the catalogue to nine, so V11's footer (a) completes every live role that held all eight, and (b) re-syncs system `TENANT_ADMIN`.
- **Lookup is a POST** so the email stays out of URLs and access logs. The body is capped at 1024 bytes (`LookupBodySizeLimit`), the email at 320 characters, and the blind index never reaches a log, metric or audit row.
- **Existence is not leaked.** By-id read of a missing and a foreign id give byte-identical 404 `USER_NOT_FOUND`; a batch silently omits foreign ids. Only a WARN and a counter record the foreign case.
- **Directory audit is best-effort**, one `USER_DIRECTORY_READ` row per successful read, metadata is counts, status filter and ids only. It is written after the read transaction ends (review R2-1).
- **B8 uses a content ETag**, not a column version: `RolePermissionSetVersion` is SHA-256 over the role id and the sorted distinct permission ids, so it is order-independent and role-bound.

## 3. Endpoints and error codes

All errors are RFC 9457 `ProblemDetail` from `GlobalExceptionHandler`, with `code` and `traceId`. Directory routes, B4 return the generic 404 `RESOURCE_NOT_FOUND` when the flag is off (the controller bean is absent).

### 3.1 Directory (`UserDirectoryController`, permission `user:directory:read`)

| Call | Behaviour | Errors |
|---|---|---|
| `GET /api/v1/users?status=&page=&size=` | One page ordered by id. Default size 20, max 100, `page x size` at most 10,000 | 400 `VALIDATION_FAILED` (incl. `email` present: use the lookup), 403, 429 `USER_DIR_002` |
| `GET /api/v1/users?ids=a,b,...` | 1 to 100 ids, foreign ids omitted. Cannot combine with `status`, `page`, `size` | as above |
| `GET /api/v1/users/{userId}` | One user of the tenant | 404 `USER_NOT_FOUND` (missing or foreign alike), 400 for a non-canonical UUID |
| `POST /api/v1/users/lookup` `{ "email": ... }` | `data` holds zero or one user; a miss and another tenant's user alike | 400, 403, 415 `UNSUPPORTED_MEDIA_TYPE`, 429 `USER_DIR_001` (lookup bucket) or `USER_DIR_002` (ceiling) |

Each entry has five fields: `userId`, `email`, `status` (`PENDING`, `ACTIVE`, `LOCKED`, `DISABLED`, as stored), `emailVerified`, `createdAt`. Every 429 carries `Retry-After`. Limits: lookup 30 per 60 s and ceiling 600 per 60 s, per (tenant, actor), `nexus.identity.directory.*` ([deployment.md](deployment.md) section 3). Both buckets fail open with the rate-limit store (`application.yml` comment, ADR-0016).

**Authorization first on lookup.** `@RequiresPermission` is method security and runs after body binding, so `LookupAuthorizationFirst` (a `HandlerInterceptor` on `/api/v1/users/lookup`) runs the same evaluator ahead of argument resolution: a caller without the permission gets 403 for a bad body, never 400/415. The mapping therefore declares no `consumes` (see design amendments).

### 3.2 B4, B3, B5, B6

- `GET /api/v1/users/me/authorization` (authenticated, no path variable, own data only, us019 flag): `{ userId, roles: [{roleId, name}], permissions, isAdministrator }`, read live from the database in one read-only transaction. 401 `AUTH_003` without a token.
- `GET /api/v1/roles/{roleId}` (`role:read`, us015): one role with `memberCount` and `permissionCount`; missing, deleted and other-tenant are one 404 `ROLE_NOT_FOUND`. No ETag.
- `PermissionResponse` carries `isSensitive`, a display hint only; no server rule reads it.
- `GET /api/v1/roles/{roleId}/permissions` returns the set with its `ETag`.

### 3.3 B8: `PUT /api/v1/roles/{roleId}/permissions` (`role:write`, us015)

Body `{ "permissionIds": [...] }`: at most 100 ids, canonical UUIDs, no repeats. `If-Match` must be exactly one strong entity tag (the `ETag` of the GET). Response 200 with the new set and its `ETag`; an unchanged set is an authorised no-op 200.

| Status | Code | When |
|---|---|---|
| 400 | `VALIDATION_FAILED` | Malformed path UUID or body; a repeated or malformed id |
| 403 | `RBAC_001` | Missing `role:write` or `role:read` in live holdings; an added permission the caller does not hold; a removal from a role whose permissions the caller does not all hold (for an admin-defining role: or the caller is not an administrator through another role, which is what stops a demotion locking the caller out); the PII rule |
| 404 | `ROLE_NOT_FOUND`, `PERMISSION_NOT_FOUND` | Role missing, deleted or foreign; id not in the catalogue |
| 409 | `RBAC_003`, `RBAC_010`, `RBAC_012` | System role; promotion while a holder was assigned by a non-administrator; classification changed while the request waited (retryable) |
| 412 | `PRECONDITION_FAILED` | `If-Match` is not the current version, checked once on the snapshot and again on the locked state. Body carries no ETag, ids or counts |
| 428 | `PRECONDITION_REQUIRED` | `If-Match` absent, `*`, a list, weak, empty or unparseable. The header is never echoed |

Outcome order is fixed so an unauthorised caller learns nothing about the set: 400, 428, 404 role, 409 system role, 404 permission, 403, 412, no-op 200, then the locks. 403 therefore precedes 412.

### 3.4 B7 and the new conflicts

- **429 `RBAC_011`** (`RoleChangeThrottledException`, with `Retry-After`): a throttled actor's assign or revoke on an admin-defining or self target. It replaces the throttled 403. Window and bound: `nexus.rbac.denial-throttle.*` (5 denials per 60 s by default).
- **409 `RBAC_012`** ("The role changed while your request was waiting. Try again."): assign or attach found after its insert that the role became admin-defining while it waited (or the PII rule now denies). The insert is rolled back before any audit row. The console retries exactly once.
- **`reason` on `RBAC_001`** is one of `GRANT_EXCEEDS_CALLER`, `SELF_ASSIGNMENT`, `ADMINISTRATOR_REQUIRED`, `UNSPECIFIED` (`CallerFacingDenialReason`). Internal reasons such as `PERMISSION_ABSENT` and `CROSS_TENANT_TARGET` collapse to `UNSPECIFIED`. The `nexus.rbac.permission_denied` metric keeps the internal names.

### 3.5 400, 405, 415 instead of 500

`GlobalExceptionHandler` maps an unreadable body to 400 `VALIDATION_FAILED` ("Request body is not valid JSON."), an unsupported content type to 415 `UNSUPPORTED_MEDIA_TYPE`, an unsupported method to 405 `METHOD_NOT_ALLOWED` (with `Allow`), and a missing required header to 400 `VALIDATION_FAILED`. They log `errorType` and the code only, never `getMessage()` or the cause, because a Jackson error quotes request tokens.

## 4. Lock order (RC-46 as extended by B8)

A request on role R takes locks in the order fixed by R's **current** class:

- **Admin-defining R** (including a demotion): set lock (`user_roles`, one ascending `FOR UPDATE` statement) first, then R's row.
- **Any other R:** R's row first, then the set lock only if the operation makes R admin-defining (a promotion).
- B8 ends with `role_permissions` and never requests `user_roles` or `roles` while holding a `role_permissions` lock.
- **Attach** takes R's row; when the attach completes the catalogue it then takes the set lock (the promotion order) and judges the holders from locked reads (review R1-1).
- **Assign and revoke** classify the roles they locked from a `FOR SHARE` read taken under the set lock, never from the pre-lock snapshot (RC-57.2; assign added by review R1-2). The pool runs REPEATABLE READ, so repeating a plain `SELECT` after the lock would still read the first snapshot.
- After commit, a detector (`AdminDefiningRoleProvenanceDetector`) pages if an admin-defining role has a holder assigned by a non-administrator.

Proof table and interleavings: design section 10.4.

## 5. Frontend

- **Routes** (`app.routes.ts`): the home redirect `'' -> dashboard` is first, then the public layout (`auth/**`, `design-system`, `access-denied`), then the signed-in `Shell` (`canActivate: [authGuard]`) with `dashboard` and the `**` Not Found page. `authGuard` sits on the shell ancestor only; it must never share a `canActivate` array with `permissionGuard`, because guards in one array run concurrently. `canActivateChild` is not used.
- **`authGuard`** restores the session with one silent refresh on cold start. A refresh that fails with 503 `AUTH_005` or a network error cancels navigation (`false`) and does not redirect; any other failure redirects to `/auth/login?returnUrl=...`.
- **`safeReturnUrl`** (`core/routing/safe-return-url.ts`) validates the post-login destination and returns `/dashboard` on any doubt: it must start with a single `/`, contain no backslash or control character, no `:` before `?`/`#`, no percent-encoded slash, backslash or control character in the path, not be under `/auth`, and resolve to the current origin. It never decodes.
- **Shell and nav**: `NAV_ITEMS` (`core/layout/nav.config.ts`) is filtered by the signed-in user's permissions; `nav.config.spec.ts` pins each item's `permission` to its route's `data.permission`. Hiding an item is cosmetic.
- **Access Denied** reads an optional support contact from `AppConfig.supportContact` (`null` today); `parseSupportContact` accepts only `mailto:` and `https://`.
- **503 `AUTH_005`**: one toast per `Retry-After` window, capped at 300 s, never a navigation.
- **Contrast tokens**: `--nx-color-{primary,error,success,warning}-text` for text, the base colours for fills (WCAG AA); defined in `src/styles/_tokens.scss` for dark, light and both `data-theme` overrides.
- **`shared/ui` wrappers added**: `NxAnnouncer`, `NxBreadcrumb`, `NxCheckbox` (tri-state), `NxChip`, `NxMenu`, `NxPageHeader`, `NxSearchField`, `NxSkeleton`, `NxTabs` (routable), `NxTooltip`, `NxTable` custom cells, sticky header and caption, and a typed-confirmation dialog. ESLint bans Angular Material and CDK imports outside `src/app/shared/ui` (three feature files are grandfathered) and bans HTML sinks and `bypassSecurityTrust*` in `src/app`.
- **API types** are pinned to recorded backend responses: `contracts/api/*.json`, written and verified by `ApiContractFixturesTest` and checked by `api-contract.spec.ts`.

## 6. Testing strategy

Details and the mutation spot-checks are in [08-test-audit.md](08-test-audit.md).

- **Backend:** unit tests per service; `*IT` classes on Testcontainers MySQL that connect as the least-privilege `nexus_app` user for the concurrency cases (`RolePermissionReplaceConcurrencyIT`, `LastAdminLockoutIT`, `AttachProvenanceRaceIT`, `SelfAssignDemotionRaceIT`, `AttachSerialisationIT`, `AssignRoleContentionIT`); `UserDirectoryIT` (authorization matrix, byte-identical 404, oversize/malformed bodies), `UserDirectoryConnectionPoolIT`, `UserDirectoryAuditFailureIT`, two PII log-scan ITs; ArchUnit containment of the unscoped `countByIdIn` and `existsById` probes; `OpenApiErrorCatalogueTest`; `RbacSchemaMigrationIT` for V11. Final gate (2026-10-22): 2626 unit tests and 693 ITs green, 0 failures.
- **Frontend:** 515 unit tests green; guard-composition contract spec and a real-Router cold-start spec (exactly one refresh); lint-rule spec for the sink and Material bans.
- **E2E:** 31 Playwright tests in 10 files with per-worker persona login and axe, plus `e2e/tools` self-tests (14). In CI the suite runs against the compose backend; it has not yet run end to end there ([14-pending-items.md](14-pending-items.md) P-11).
- **Load:** none, by decision O-1 (no latency budget stated).

## 7. Cross-links

Requirements [01](01-requirements.md) · Impact [02](02-impact.md) · Design [03](03-design.md) sections 3 (V11), 4 (directory), 6 (B4), 9 (B7), 10 (B8), 12 (frontend), 13 (environments), 17 (observability) · Threat model [03b](03b-threat-model.md) (RC-55 to RC-67) · US-018 background: [US-018 technical doc](../US-018/09-technical.md).
