# US-019 code review (single pass over the whole branch)

**Date:** 2026-10-22 · **Diff:** `origin/main...HEAD` at 946d771 (28 tasks) · **Reviewers:** three fresh-context code-reviewer agents, one per slice (R1 RBAC logic and locking, R2 identity/common/config/seeds, R3 frontend/e2e/CI). Reports are reproduced as written; the fix pass and its disposition are recorded in section 4.

**Overall verdict after the fix pass: APPROVE WITH NITS.** The one High (R1-1, attach provenance) and both Mediums of R1/R2 and R3 were fixed in the commits listed in section 4 and re-reviewed by a fresh delta reviewer (see `07-security-review.md` section 4: 0 Blocker, 0 High, 0 Medium). The slice verdicts below are the verdicts at review time, before the fixes.

## 1. Slice R1 — RBAC logic and locking
## US-019 review R1 (rbac logic and locking)

### Summary
High 1, Medium 1, Low 4, Nit 2. Blocker 0.
Verdict: CHANGES REQUESTED (one High: the attach RBAC_010 check can be bypassed by a concurrent assign; fix is small).
Paths: nexus-backend/src/main/java/com/example/nexus/rbac/** (prefix RM = application/RoleManagementService.java, RA = application/RoleAssignmentService.java).

### Findings

#### 1. [High] Attach RBAC_010 provenance check runs before the role-row lock and on a stale snapshot (T-020 gap, confirmed)
File: RM:357-374 (check at 357-362, lock at 369, post-insert check at 373, 1351-1374), RM:1385-1437 (non-locking reads)
Verified in code: `requireNoNonAdministratorAssignedHolder` reads holders (`findActiveHoldersForRole`) and the administrator set (`findRolePermissionIdsForTenantRoles` / `findActiveHolderUserIdsForRoles`) with plain non-locking selects, before `lockRoleRow`. After the lock, `requireAttachKeptItsClassification` returns immediately when `becameAdminDefining` is true (line 1358), so nothing re-judges the holders.
Scenario: R is one permission short of the catalogue and has no holders. Attacker A (role:write plus user:role:assign, not an administrator) and administrator B. B starts attach(R, last permission); holder read sees none, so no 409. Before B takes the role-row lock, A assigns R to account X (non-admin-defining path, commits). B locks the row, inserts, `requireAttachKeptItsClassification` returns early. Result: R is admin-defining and X, assigned by non-administrator A, is an administrator. That is exactly RES-26 / ADR-0021 D8, and only the after-commit detector (RC-56.4) notices.
Caveat for the fix: the pool runs REPEATABLE READ (see CallerAuthorizationService javadoc and JpaUserRoleRepository comments). A plain SELECT repeated after the lock still reads the transaction's first snapshot, so just moving or repeating the existing calls under the lock does NOT fix it. The re-check must use locking reads: after `lockRoleRow`, call `userRoleAssignmentPort.lockActiveAssignmentHolders(tenantId, lockSet)` (the replace promotion path already does this correctly via `requireNoLockedHolderAssignedByNonAdministrator`, RM:759) plus `lockRolePermissionsForRoles` for the administrator classification, when `becameAdminDefining`. That needs the set lock (user_roles) for the attach, so the lock order must follow RC-46 (a promoting attach = role row, then set lock, like the promoting replace).
Cheaper alternative: route attach-that-completes-the-catalogue through the same code as a promoting replace.
Missing test: no IT races assign against a promoting attach (AttachSerialisationIT covers attach vs attach only; AssignRoleContentionIT measures latency/deadlock, not this outcome).

#### 2. [Medium] Assign's set-lock path still classifies from the pre-lock M10' read (T-021 left it)
File: RA:~203-330 (acquireSetLock then `callerIsAdministrator(actor, setLock, ...)` for A4 and the PII rule); contrast revoke, which now calls `classifyLockedRolesNow` (RA ~582-605) and Bootstrap (BootstrapAdminService ~202-218)
Verified in diff: only revoke and break-glass got the RC-57.2 current read; assign does not call `lockRolePermissionsForRoles` on the set-lock path.
Scenario: U's only admin-defining role R_A is demoted by a replace that holds the set lock. U's self-assign (or a PII `user:directory:read` grant) was queued behind it. After the demotion commits, assign still treats R_A as admin-defining, so A4 (self-assign) and the PII administrator answer pass for a user who is no longer an administrator. Window is narrow and needs concurrency, but this is the exact class RC-57.2 exists to close, and the PII rule is the control it feeds.
Fix: after `acquireSetLock` in assign, apply `classifyLockedRolesNow` and use its SetLock for A4 and the PII evaluation (same two lines as revoke).

#### 3. [Low] `attachPermissions` issues one SELECT per id inside the role-row lock
File: infrastructure/persistence/JpaRoleManagementAdapter.java:~212-224, domain/RolePermission.java:27-37
`RolePermission` does not implement `Persistable` and has no `@Version`, with an assigned `@EmbeddedId`, so `saveAllAndFlush` goes through `merge` (SELECT then INSERT) per row. A replace adding 100 permissions runs ~100 extra selects while holding roles X (and possibly the set lock), lengthening the lock hold the design budgets (50 ms p95 add). Fix: make `RolePermission` implement `Persistable<RolePermissionId>` (isNew true until persisted) or use one JDBC batch insert. The dup-key translation must still hold (merge currently hides an already-committed duplicate only when the snapshot sees it, which is correct under the role-row lock, so behaviour is unchanged).

#### 4. [Low] Timing assertion in a Testcontainers IT will flake on shared CI
File: src/test/java/com/example/nexus/rbac/AssignRoleContentionIT.java:75, 205-208
`MAX_ADDED_WAIT_P95_MS = 50` on (p95 contended - p95 alone) with 50 samples. Deadlock-freedom is the real invariant and is asserted deterministically elsewhere; a latency delta on a noisy runner is not a defect signal. Fix: keep the no-deadlock/no-failure assertions, move the p95 check to a tagged perf run or widen to a generous bound with a warning log.

#### 5. [Low] Metric names/tags duplicated in the controller; null counts silently become zero
File: interfaces/rest/RoleController.java (428 branch in `replaceRolePermissions`; `toResponse(view, counts)` null handling)
The controller hard-codes `"nexus.rbac.permission_replace"`, `"precondition_required"`, `"none"` that RM defines as constants, and instruments in the interface layer. `toResponse` maps `counts == null` to 0/0: fine for a just-created role, but in `getRole`/`updateRole` a missing map entry (a bug) would be reported as an empty role. Fix: move the 428 count into a small service method or share the constants; for getRole/updateRole use `Objects.requireNonNull(counts)` and keep the explicit zero only in createRole.

#### 6. [Low] `Math.clamp(retry, 1L, windowSeconds)` throws if windowSeconds < 1
File: RA evaluateThrottle (`Math.clamp(status.retryAfterSeconds(), 1L, (long) windowSeconds)`)
`windowSeconds` is an unvalidated `@Value`; 0 or negative makes `clamp` throw IllegalArgumentException, turning a throttled 429 into a 500 on the admin-defining/self path. Fix: `Math.max(1L, Math.min(retry, windowSeconds))` or validate the property at startup.

#### 7. [Nit] Lock-hold timer for a replace is stopped only in afterCommit
File: RM:670-673
If the commit itself fails (or a later rollback), `lockHold` is never stopped and no outcome=error sample is recorded. Metric gap only. Register `afterCompletion` (status) to stop with replaced/error.

#### 8. [Nit] getRole / updateRole read the role and its counts in two transactions
File: interfaces/rest/RoleController.java (`countsOf`)
Benign (counts may be a few ms newer than the row). A single service method returning role plus counts would remove the second round trip's inconsistency and the controller-side stitching.

### Verified OK
- Authorization order for PUT permissions: tenant 404, immutability 409, catalogue 404, then `authorizeReplace` 403 (live role:write, role:read, adds subset, PII rule, removes subset with administrator-through-other-role), then 412 from If-Match, then no-op 200, then locks (RM:532-592). Read in code.
- Replace lock order (RC-46): demotion = set lock then role row; promotion/other = role row then set lock only on promotion (RM:565-577). Current-state check (`lockPermissionIdsForRole` FOR SHARE, version equality) before steps 10/11; steps 10/11 use locked rows and a FOR SHARE role_permissions read, not the M10' snapshot (RM:628-643, 703-708, 759-789).
- Delete: set lock, UPDATE (role row), locked administrator re-check, then holder re-check (RM:1094-1128); consistent with replace/assign order.
- Revoke and break-glass now classify from `lockRolePermissionsForRoles` under the set lock (diff of RA and BootstrapAdminService); `FOR SHARE OF rp` joins roles without locking it (JpaUserRoleRepository). I reasoned through attach/detach/replace/assign/revoke interleavings for cycles and found none; detach of an admin-defining role without the set lock is the accepted RES-28 detective case.
- Assign's post-insert classification check (RA ~833-870) throws RBAC_012 for both "became admin-defining" and "PII now denied", rolling back the insert before any audit row.
- RolePermissionSetVersion: SHA-256 over role id plus distinct ids sorted unsigned; order-independent, role-bound, duplicates collapse. IfMatchHeader accepts exactly one strong quoted tag, 428 otherwise, never echoes the header.
- PiiPermissionGrantRule: matched by seeded id, administrator supplier consulted only when needed, DENIED vs DELEGATED by switch, logs ids only. ReplaceRolePermissionsRequest: not-null, max 100, canonical UUID per element, controller rejects duplicates; null elements reach bean validation.
- Tenant predicates on the new count queries (join to roles carries tenant for role_permissions), `lockLiveRoleRow` (tenant + deleted_at), `findActiveRoles`; counts are bounded by the page size; CallerAuthorizationService reads in one read-only transaction, DB only, no PII in the log or counter tags.
- Throttle status: PTTL -2/-1/positive handled, fails safe to NOT_THROTTLED; 429 only on admin-defining or self targets.

### Not covered
Frontend and docs; JPA adapters/tests outside the lock statements listed; RoleResolutionService, PermissionFreshnessService, AccessReviewService, RoleReplayQueue and EpochReplayQueue (unchanged logic beyond the diff); migrations and grants (other slices); the bulk of the 85 test files (spot-read AttachSerialisationIT and AssignRoleContentionIT only, no test run); `application-prod.yml` PII switch default and SpotBugs exclusions (brief items, other slice). The REPEATABLE READ assumption in finding 1 comes from code comments and the CallerAuthorizationService javadoc, not from a runtime check.

## 2. Slice R2 — identity, common, config, seeds
## US-019 review R2 (identity directory, shared web layer, config, seeds, contracts, OpenAPI)

### Summary
Blocker 0, High 0, Medium 2, Low 4, Nit 3. Verdict: APPROVE WITH NITS (the two Mediums are worth fixing or consciously accepting before merge).

### Findings

1. [Medium] Audit row written with REQUIRES_NEW from inside an open read-only transaction (two pooled connections per request)
   File: nexus-backend/src/main/java/com/example/nexus/identity/application/UserDirectoryService.java:37 (class `@Transactional(readOnly = true)`), :140 (`audit` -> `auditPort.recordDirectoryRead`), infrastructure/audit/DirectoryReadAuthEventAdapter.java:50, SecureEventService.java:52 (`REQUIRES_NEW`).
   VERIFIED: the call chain is outer readOnly tx -> `SecureEventService.recordEvent` (REQUIRES_NEW), and no Hikari pool size is configured in application.yml (default 10; only break-glass sets 4).
   SUSPECTED (not run): a resource-local JPA transaction holds its connection from begin, so each directory request needs 2 connections at the audit moment. Under 10 concurrent directory reads every thread holds one and waits `connectionTimeout` (30 s) for the second; the audit is then lost (best-effort) after a 30 s stall, and unrelated endpoints starve meanwhile.
   Fix: make the audit happen after the read transaction ends. Either drop class-level `@Transactional` on the service and annotate the query-port adapter methods, or call the audit from a `TransactionSynchronization.afterCompletion`, or have the controller/a thin facade call `auditPort` after the service returns. Add a test with a pool of 1-2 that runs N concurrent reads.

2. [Medium] `POST /users/lookup`: body binding and size cap run before the permission check, so 400/415 can precede 403 and unauthorised callers bypass the ceiling
   File: identity/interfaces/rest/UserDirectoryController.java:185-190 (`@RequiresPermission` + `@Valid @RequestBody`), LookupBodySizeLimit.java:46.
   VERIFIED: `@RequiresPermission` is a method-security (PreAuthorize-style, TenantAwarePermissionEvaluator) check; Spring MVC resolves and validates arguments, and runs the RequestBodyAdvice, before invoking the proxied method. A caller lacking `user:directory:read` sending an oversized or malformed body gets 400 `VALIDATION_FAILED` (or 415) and never 403; it also makes the server read up to 1 KiB and run Jackson/Bean Validation before authorisation. Hit/miss behaviour is not leaked (no lookup runs), so exposure is small.
   Fix: either accept and document, or enforce authorisation ahead of binding (a `HandlerInterceptor`/filter on `/api/v1/users/lookup`, or take `@RequestBody String` + parse after the check). Add a test "no permission + invalid body -> 403" to pin whichever order is chosen (none exists today).

3. [Low] `existsById` on the directory query port is a second unscoped existence probe that ArchUnit does not guard
   File: identity/infrastructure/persistence/JpaUserDirectoryQueryAdapter.java:77, application/port/out/UserDirectoryQueryPort.java (existsById), architecture/ArchitectureRules.java (only `countByIdIn` is contained).
   VERIFIED: RC-61.2 containment rule matches `countByIdIn` only; `TenantIsolationArchitectureTest` states inherited JpaRepository methods are not checked. Any bean can inject the port and call `existsById(anyId)` as a cross-tenant oracle. The service only uses it on a by-id miss and never in the response, but the sign-off conditions (count only, one caller) are enforced for the batch count and not for this path.
   Fix: extend the ArchUnit rule to `UserDirectoryQueryPort.existsById` / `JpaUserRepository.existsById` callers (only `UserDirectoryService` and the adapter), or fold the probe into a `countByIdIn(List.of(id))` so one enforced primitive remains.

4. [Low] Foreign-id reads WARN on every request (log amplification)
   File: UserDirectoryService.java:96-104 and :155-162.
   VERIFIED: each by-id miss on a foreign id and each batch with foreign ids emits a WARN plus counter. Bounded only by the 600/min/actor ceiling, so one holder can emit ~600 WARN/min (and the same for the pager-style `cross_tenant_miss` counter) with no per-window de-duplication, unlike the throttle WARN in `DirectoryAccessGuard`. Probably intended (detection signal), but if alerting keys on the counter an authorised user can trip it at will.
   Fix: none required; consider once-per-window WARN or an alert threshold on rate, not count.

5. [Low] `measured()` outcome metric undercounts `invalid` and never sees 415
   File: UserDirectoryController.java:236-253.
   VERIFIED: lookup body failures (`@Valid`, size cap, wrong media type) occur before the lambda, so `requests{operation=lookup,outcome=invalid}` stays 0 for them; the Javadoc lists `invalid` as an outcome without that caveat. Also authorisation denials never reach it (documented as "error" but in fact absent).
   Fix: note it in the Javadoc, or count in the GlobalExceptionHandler path.

6. [Low] V11 footer (a) silently grants PII read to every tenant's custom role that held all 8 permissions
   File: db/migration/V11__rbac_user_directory_read_permission.sql:30-55.
   VERIFIED by reading: statement (a) completes any non-deleted role holding all 8 pre-V11 permissions (any tenant, custom or system), by design (ADR-0021 D3, comment at lines 12-15) and idempotent; it bypasses the `pii-grant-requires-administrator` rule and writes no audit row. SQL is correct (excludes soft-deleted, no promotion of partial roles; (b) is idempotent; id literal does not collide in other migrations). Only a design-level note: the runbook should say to review roles that gain `user:directory:read` and to keep the feature flag off until done (the file header already sequences the flag after a fresh admin token).

7. [Nit] SpotBugs exclusions are class-wide, not per-field
   File: nexus-backend/spotbugs-exclude.xml:174-232.
   Each addition (UserDirectoryService, UserDirectoryController, DirectoryReadAuthEventAdapter, plus the rbac ones) is justified: EI_EXPOSE_REP2 for constructor-stored singletons (MeterRegistry, ObjectMapper, services), consistent with the existing AccessReviewService/RbacAuthEventAdapter entries, and the comments are accurate. But `UserDirectoryController` stores three Spring singletons and `UserDirectoryService` four; the T-018 comment for RoleController/PermissionController attributes the hit to a "replace..." method name heuristic, which I could not verify. A class-wide EI_EXPOSE_REP2 exclusion also hides any future real exposure in those classes. Acceptable; if you want it tighter use a `<Field>`-level match or `@SuppressFBWarnings` on the constructor with the justification.

8. [Nit] Stale Javadoc: throttle exceptions say `UserDirectoryService` emits the once-per-window WARN
   File: identity/domain/UserDirectoryThrottledException.java:8-12 (and UserDirectoryCeilingExceededException.java:9-12 says `DirectoryAccessGuard`, which is correct).
   VERIFIED: the WARN is in `DirectoryAccessGuard.warnOncePerWindow`. Fix the first Javadoc.

9. [Nit] Dev seed fixture: second-tenant assignment uses `assigned_by` = tenant-1 admin
   File: identity/infrastructure/seed/DevDataInitializer.java:112-115. Already on the record (cross-tenant `assigned_by`); dev-only, profile guard `dev & !break-glass & !prod` is correct. Seed runs in one `@Transactional` run(); idempotent via blind-index lookup / role-name lookup; no email or password logged (checked `log.warn`/`log.info` calls).

### Verified OK
- Tenant isolation of reads: every list/batch/by-id/lookup query is `findByTenantId...` with the tenant from the JWT (`resolveActor`, malformed principal/tenant fails closed with `InsufficientPermissionException`); indexes: `uq_users_tenant_id_email_hmac` (lookup), `idx_users_tenant_id_status` (list/filter, PK appended so ORDER BY id is index-ordered), both in V2. Page offset capped (`page*size <= 10000`, size <= 100, ids <= 100); no unbounded collection reads.
- Cross-tenant parity (NF-S2): by-id miss always runs `existsById`; same 404 `USER_NOT_FOUND`, same message; foreign extra only WARN/counter. Batch always runs `countByIdIn` and its result never changes the response.
- PII: `DirectoryUserView.toString` and `UserLookupRequest.toString` redact; audit metadata holds counts/ids/outcome only (no email, hmac or id list); adapter logs `errorType` only; exception messages are fixed; `DirectoryPageLinks` is built from constants/enums/ints only; GlobalExceptionHandler new handlers (body not readable, media type, method, missing header) log type/code only and return fixed messages; bean-validation details do not echo values.
- `LookupBodySizeLimit`: Content-Length precheck plus `readNBytes(1025)` bounds chunked bodies; boundary 1024 accepted, 1025 rejected, fixed message (unit-tested, plus UserDirectoryIT oversize cases).
- Rate limit guard: two buckets keyed tenant:actor, `Retry-After` from store result, single WARN per window via a 1-slot bucket; throttled requests never reach hashing/query/audit (controller order ceiling -> lookup throttle -> service).
- Status/enum handling: `parseStatus` exact-match against `UserStatus` (4 values, matches OpenAPI `allowableValues`); canonical-UUID regex prevents `UUID.fromString` leniency.
- OpenApiConfig customizer: reads repeatable `@ProblemResponse`, adds `application/problem+json` $ref responses and sorted `x-nexus-error-codes`; operation null-response guard present. CORS change (If-Match allowed, ETag exposed) is minimal and credentials/origin config unchanged.
- ApiContractFixturesTest: round-trips real records through the app ObjectMapper, fails on missing/extra files, update flag is opt-in; fixtures use `example.test`.
- Seeders: profile guard excludes `prod` and `break-glass`; idempotent; known password confined to dev; lock expiry (100 y) fits `DATETIME(6)`.
- AuthEventType `USER_DIRECTORY_READ` fits `VARCHAR(64)` event_type (no DDL needed); not PRIORITY, with reasoning.

### Not covered
rbac/** (other reviewers); frontend; compose/CI; whether the HikariCP connection is really held for the whole read-only transaction (finding 1 is from code reading, not run); Docker/IT execution; the full contents of every test class (spot-read LookupBodySizeLimitTest, test names of UserDirectoryServiceTest/GuardTest/ControllerTest, DirectoryUserCountContainmentRuleTest, ApiContractFixturesTest); RateLimitRoleChangeThrottleAdapter and RbacAuthEventAdapter changes only skimmed (small, mechanical rename and two metadata fields).

## 3. Slice R3 — frontend, e2e, CI
## US-019 review R3 (frontend, e2e, CI)

### Summary
Blocker 0, High 0, Medium 3, Low 5, Nit 2. Verdict: APPROVE WITH NITS (fix M1 before merge if cheap).

### Findings

1. MEDIUM - Route focus is a no-op for the Dashboard (and design-system) h1.
   File: nexus-frontend/src/app/core/routing/route-focus.ts:25-30; nexus-frontend/src/app/features/dashboard/dashboard.component.ts:15.
   Verified: route-focus selects `#main-content h1` and calls `.focus()`, but `<h1>Dashboard</h1>` has no `tabindex="-1"`, so focus() does nothing. Because the h1 is found (non-null), the `?? #main-content` fallback never runs. Only NxPageHeader (tabindex=-1) and AccessDenied (self-managed) work. route-focus.spec uses an h1 that already has tabindex, so it cannot catch this. No e2e asserts focus after navigation.
   Scenario: keyboard/SR user navigates login -> dashboard or any link to /dashboard; focus stays on the old (removed) element / body.
   Fix: in route-focus, if the h1 has no tabindex attribute set `tabindex=-1` before focus (or fall back to main when `document.activeElement` did not change); add a spec case with a bare h1. Also give dashboard h1 tabindex="-1" or use NxPageHeader.

2. MEDIUM - authGuard turns every refresh failure into a login redirect, including 503 AUTH_005 / network errors.
   File: nexus-frontend/src/app/core/guards/auth.guard.ts:30-32.
   Verified in code: catchError has no discrimination. Design 12.10 says AUTH_005 shows a toast and "never navigates"; on cold start the interceptor toasts and the guard then navigates to /auth/login?returnUrl=... A user with a valid refresh cookie during a Redis/DB blip is sent to login (the session itself survives, but the UX contradicts the "stay on the page" intent). Suspect, not exercised: no cold-start spec for 503.
   Fix: on AppError code AUTH_005 / NETWORK_ERROR, either allow the redirect (document it as accepted) or render an unavailable state; at minimum add a cold-start test that pins the chosen behaviour.

3. MEDIUM - E2E suite proves little about permission-filtered nav; unit coverage only.
   File: nexus-frontend/e2e/access-management/shell.spec.ts:5-15,24-37.
   Verified: NAV_ITEMS contains only ungated Dashboard, so every persona expects ['Dashboard']; the "shows exactly its navigation entries" test cannot fail on a filtering bug (story scenario 5 not truly covered e2e). Per-persona axe runs are the same page 5 times. Not vacuous in the skip sense, but weak. Accept if the access console task adds gated items and extends this map; else note it.
   Fix: add a TODO/guard test that fails when NAV_ITEMS gains a gated item without a NAV_LABELS update, or assert against NAV_ITEMS import.

4. LOW - ServiceAvailabilityNotifier trusts Retry-After without an upper bound.
   File: core/http/service-availability-notifier.ts:25-30 (and api-error.interceptor.ts parseRetryAfterSeconds).
   A header of e.g. 99999999 suppresses the toast for years and prints "Try again in 99999999 seconds". Fix: clamp to e.g. 300 in parseRetryAfterSeconds or notifier.

5. LOW - dialog.ts doc comments mis-attached by the NxTypedConfirmShell insertion.
   File: shared/ui/dialog/dialog.ts (~141-155, ~288-300). The big JSDoc of NxDialogShell now sits above `TypedConfirmData`, and NxDialog's JSDoc above `NxTypedConfirmShell`. Misleading API docs. Move the new blocks above/below the existing JSDoc pairs. Also `[aria-disabled]` is a property-style binding with a dashed name; prefer `[attr.aria-disabled]` (verify it renders; gates are green so it compiles).

6. LOW - PII scan makes failure artifacts unavailable exactly when retries happen.
   File: .github/workflows/e2e-full-stack.yml (scan + upload steps); playwright.config.ts trace 'on-first-retry'.
   Traces of login specs (fill(email), API login body) contain the persona address, so any retry fails the scan and artifacts are withheld; it is fail-safe but costs debuggability. Also needles match only raw/lower-case text (no `%40` URL-encoded form), and zip64 archives are silently unparsed. Fix options: set trace to retain-on-failure with `text` redaction not possible, so accept and document, or add `%40`-encoded needle.

7. LOW - assert-executed floor equals the exact current count and is hand-maintained.
   File: .github/workflows/e2e-full-stack.yml:25 (E2E_MIN_TESTS=31); e2e/tools/assert-executed.mjs.
   Verified `npx playwright test --list` = 31 now. A spec deleted and another added passes silently; fine as a floor, but "flaky" counts as executed and only status 'skipped' is rejected (timedOut/interrupted are left to the playwright exit code, acceptable). Nit-level: compute the floor from `--list` in an earlier step.

8. LOW - Third cold-start spec and design-system a11y spec need no backend.
   File: e2e/access-management/cold-start.spec.ts:30-33, e2e/design-system.a11y.spec.ts. Pass with no backend (network error also redirects to login), so the signed-out test cannot detect that the refresh call actually returned 401. Acceptable; add requireBackend() in the former for it to mean what it says.

9. NIT - Contrast retune: dark-mode `--nx-color-success-text` equals `--nx-color-success` and `warning-text` equals `warning`, so those tokens are aliases in dark; fine. `--nx-color-error` (base) darkened #e5484d -> #d03a3f for both themes with `error-surface` unchanged; borders/fills change visibly (outlines on error fields) with no visual review. Light and dark text tokens are defined consistently in all three places (media block, data-theme=light, data-theme=dark); verified by reading the diff.

10. NIT - Material still imported in three feature files (registration-form, verification-landing, design-system-preview). Grandfathered by an explicit eslint override with a removal comment; pre-existing (design-system-preview imported MatIcon before). NxCheckbox now exists, so registration-form could migrate. Not a regression.

### Verified OK
- safeReturnUrl (core/routing/safe-return-url.ts): reads as sound against open-redirect classes: leading `/`, `//`, `/\`, backslash, control chars, `:` in path, /auth prefix, encoded slash/backslash/control, origin check; no decode, returns the validated string. The extra hazard rule is stricter, harmless. Login form uses it via navigateByUrl; authGuard puts state.url into returnUrl (opaque, validated on use).
- parseSupportContact: scheme allow-list (mailto/https), whitespace/control rejection, label non-empty; template uses [href] so Angular sanitizer is a second layer; no bypassSecurityTrust anywhere (grep).
- Route table: home redirect before the two empty-path parents, PublicLayout children limited to auth/design-system/access-denied, authGuard on shell ancestor only (no canActivateChild), permissionGuard doc and contract spec consistent; `**` inside the guarded shell so signed-out unknown URLs go to login.
- apiErrorInterceptor: reason only for RBAC_001, requiredPermission type-checked, Retry-After parsed strictly (digits, >0), redirect navigates with no query params, 429 not retried.
- Material/CDK only in shared/ui (grep) except the three grandfathered files; eslint innerHTML/bypassSecurityTrust/Material rules have a spec (lint-rules.spec.ts) that exercises them.
- New SCSS uses var(--nx-*) tokens; only layout dimensions (52px header, 960px breakpoints, 36px targets) are raw, which is acceptable for non-token geometry.
- Workflow: pull_request (not _target), contents: read, no secrets, SHA-pinned actions matching the other workflows, concurrency group, scan step uses always() and gates the upload on the scan outcome, backend log collected, stack torn down with volumes. docker-compose.e2e.yml raises limits only in the override.
- assert-executed counts skipped as failure and enforces a floor; tools.selftest covers skip, zero tests, low count, log hits, case, zip entries. `playwright --list` = 31 matches E2E_MIN_TESTS.
- requireBackend throws when E2E_REQUIRE_BACKEND=1, so CI cannot skip silently.

### Not covered
Full read of every shared/ui wrapper spec (checkbox, chip, menu, search-field, skeleton, table, tabs), shell.spec/cold-start-routing.spec bodies, SCSS of each of the ~20 retuned style files, actual contrast ratios (not computed), real execution of compose/CI path, package-lock, Angular 22.2.3 upgrade side effects.

## 4. Disposition

**Date:** 2026-10-22. Commit SHAs are from `git log --oneline origin/main..HEAD` on `feature/US-019`. Pending ids (P-n) are in [14-pending-items.md](14-pending-items.md). Verification of the fixes: [08-test-audit.md](08-test-audit.md) (backend 2626 unit and 693 integration tests green, frontend 515 green). The Opus re-check of the locking fixes is queued as P-12.

### R1 (RBAC logic and locking)

| Id | Severity | Status | Disposition |
|---|---|---|---|
| R1-1 | High | Fixed | `2ca17e7`: a catalogue-completing attach takes the set lock after the role-row lock and judges the holders from locked reads; `AttachProvenanceRaceIT`. Opus re-check P-12 |
| R1-2 | Medium | Fixed | `fdb18ae`: assign classifies from a current read under the set lock; `SelfAssignDemotionRaceIT`. Opus re-check P-12 |
| R1-3 | Low | Deferred | P-22 (one `SELECT` per id in `attachPermissions`; no latency budget, so no measured harm) |
| R1-4 | Low | Fixed | `aea67c3`: `AssignRoleContentionIT` logs the p95 numbers instead of asserting 50 ms |
| R1-5 | Low | Fixed (partly) | `aea67c3`: the controller shares the service's metric constants. Accepted: the 428 is still counted in the controller (it occurs before the service is reached), and `getRole`/`updateRole` keep their zero default for a missing count |
| R1-6 | Low | Fixed | `aea67c3`: `Math.max(1, Math.min(retry, window))`; test with windows 0 and -5 |
| R1-7 | Nit | Accepted | Metric gap only (a failed commit records no `error` lock-hold sample); no behaviour impact |
| R1-8 | Nit | Accepted | Counts may be a few milliseconds newer than the role row; benign |

### R2 (identity, common, config, seeds)

| Id | Severity | Status | Disposition |
|---|---|---|---|
| R2-1 | Medium | Fixed | `19b5352`: the transaction moved to the query-port adapter so the audit write needs no second connection; `UserDirectoryConnectionPoolIT` |
| R2-2 | Medium | Fixed | `99d2db2`: `LookupAuthorizationFirst` authorises before the body is read; `UserDirectoryIT` pins 403 for blank, malformed, empty, non-JSON, oversized and text/plain bodies. Opus re-check P-12 |
| R2-3 | Low | Fixed | `aea67c3`: ArchUnit contains `existsById` (port: `UserDirectoryService` only; repository: the adapter only) with negative fixtures |
| R2-4 | Low | Accepted | The WARN per foreign id is the detection signal; bounded by the 600 per minute ceiling. Alert on rate, not count (monitoring.md) |
| R2-5 | Low | Fixed | `aea67c3`: lookup bodies rejected before the handler (400, 415) count as `outcome=invalid`; denied callers are not counted |
| R2-6 | Low | Accepted | By design (ADR-0021 D3). Documented: pre-deploy exposure query and flag sequencing in [deployment.md](deployment.md) section 4, runbook section 6 |
| R2-7 | Nit | Accepted | Class-wide `EI_EXPOSE_REP2` exclusions follow the file's convention for constructor-injected Spring beans, each with a comment |
| R2-8 | Nit | Fixed | `aea67c3`: the throttle exception Javadoc names `DirectoryAccessGuard` |
| R2-9 | Nit | Accepted | Dev-only seed fixture; profile guard `dev & !break-glass & !prod` verified |

### R3 (frontend, e2e, CI)

| Id | Severity | Status | Disposition |
|---|---|---|---|
| R3-1 | Medium | Fixed | `20b9f7b`: route focus sets `tabindex=-1` on the target before focusing; the spec renders the real dashboard markup |
| R3-2 | Medium | Fixed | `eb051f0`: `authGuard` cancels navigation on 503 `AUTH_005` or a network error instead of redirecting; other failures still redirect. What the user then sees is open: P-20 |
| R3-3 | Medium | Fixed (unit); Deferred (e2e) | `5d89de4`: `shell.spec.ts` proves permission-filtered nav per persona with an injected gated item. The e2e map cannot catch a filtering bug until a gated item exists: P-27 |
| R3-4 | Low | Fixed | `10e2d61`: `Retry-After` capped at 300 s in the interceptor and the notifier |
| R3-5 | Low | Fixed | `10e2d61`: the misplaced dialog doc comments moved back to their declarations |
| R3-6 | Low | Fixed | `302d088`: `scan-pii` also matches `%40`, double-encoded, JSON-escaped and entity forms and the registrant pattern, and fails on any image; logout and session-refresh record no trace (P-21) |
| R3-7 | Low | Accepted | The `E2E_MIN_TESTS` floor is hand-maintained on purpose and says so in the workflow comment; a changed count turns the check red |
| R3-8 | Low | Fixed | `10e2d61`: the signed-out cold-start e2e requires the backend. The design-system a11y spec needs none by design |
| R3-9 | Nit | Accepted | Token aliasing in dark mode is intended. The darker `--nx-color-error` has had no visual review: P-25 |
| R3-10 | Nit | Deferred | P-13 (three grandfathered Material imports, exempted in ESLint with a removal comment) |
