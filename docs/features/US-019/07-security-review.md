# US-019 security review (single pass over the whole branch)

**Date:** 2026-10-22 · **Diff:** `origin/main...HEAD` at 946d771 · **Reviewers:** two fresh-context security-reviewer agents (S1 backend vs. threat model 03b, S2 frontend/CI/supply chain). Run on the Sonnet model because the Opus weekly limit was reached; the Opus re-check items are listed in section 3. Reports are reproduced as written.

## 1. Slice S1 — backend
## US-019 security review, slice S1 (backend)

Branch `feature/US-019`, diff base `origin/main...HEAD`. Scope: `nexus-backend/src/main` (rbac, identity, common, config, V11, dev seeds), checked against `03b-threat-model.md` (T-E48/T-E49/T-T22, RC-55..RC-67, section 9.2 and 10.7 merge blockers). Read-only; no Maven, no Docker, no tests run. Everything below is VERIFIED BY READING unless marked SUSPECTED.

### Summary

| Severity | Count |
|---|---|
| Blocker | 0 |
| High | 1 |
| Medium | 1 |
| Low | 2 |
| Nit | 2 |

Verdict: **CHANGES REQUESTED** (one High: the attach `RBAC_010` provenance check is still bypassable by a concurrent assign, so the RC-56 / T-E48 "preventive" control is not closed; fix is small and reuses existing helpers).

OWASP categories touched: A01 (findings 1, 2, 3), A04 (1, 2), A09 (none found), A03 (no SQL string building found), A05 (none).
Auth, tenant isolation and PII-handling code WAS reviewed (directory controller/service/guard, PII grant rule, B8, attach, assign, GlobalExceptionHandler, V11). I approve those only to the extent of the findings and "Verified OK" below.

### Findings

#### 1. [High] Attach `RBAC_010` provenance check reads holders before the role-row lock, so a concurrent assign defeats it (A01, A04)

File: `nexus-backend/src/main/java/com/example/nexus/rbac/application/RoleManagementService.java:358-374` (decision and pre-lock check), `:1385-1408` (`requireNoNonAdministratorAssignedHolder`), `:1351-1374` (`requireAttachKeptItsClassification` returns early when `becameAdminDefining`).

Issue. `attachPermission` classifies from a snapshot (`attachWouldMakeRoleAdminDefining`, line 358) and, if the attach completes the catalogue, runs the holder check (lines 360-362) with plain non-locking reads (`findActiveHoldersForRole`, `findRolePermissionIdsForTenantRoles`, `findActiveHolderUserIdsForRoles`). Only after that does it take R's row `FOR UPDATE` (line 369). The post-insert current read (line 373) judges only the permission set, and returns immediately when the snapshot already said "completes" (line 1358). Nothing re-judges provenance under the lock. The app does not override the isolation level (grep of `src/main` finds none), so MySQL REPEATABLE READ applies and the snapshot dates from the transaction's first read (`resolveRoleInTenant`, line 335). A plain re-read after the lock would still see that old snapshot, so the fix must be a locking or set-lock read, not just a re-run of the same query.

Concrete interleaving (T1 = administrator attaching the 9th permission p to custom role R, R holds the other 8; T2 = attacker holding R's 8 permissions plus `user:role:assign`, who is not an administrator):
1. T1 begins, reads R's set (8 of 9), `becameAdminDefining = true`, reads R's holders: none (or only administrator-assigned ones). `RBAC_010` check passes.
2. T2 `assign(R -> sockPuppet)`: classification says R is not admin-defining, so no set lock. The conditional `INSERT ... SELECT FROM roles` takes S on R's row and inserts the `user_roles` row (assigned_by = attacker, a non-administrator). T2's post-insert `FOR SHARE` read of `role_permissions` sees 8 of 9, so no `RBAC_012`. T2 commits.
3. T1 requests R's row `FOR UPDATE`. If T2's insert came first, T1 simply waits for T2's S lock to clear (T2 commit), then acquires X. (If T1 got X first, T2 would block and then fail with `RBAC_012`; that order is the one the existing ITs cover.)
4. T1 inserts p; `requireAttachKeptItsClassification` returns at line 1358 because `becameAdminDefining` is true; audit; commit.

Result: R is admin-defining with an active holder assigned by a non-administrator, committed with no 409. This is exactly the RES-26 sock-puppet state `RBAC_010` exists to prevent. It is exploitable beyond the post-commit detector: the detector (`detectNonAdministratorAssignedHolder`, line 408) only pages after the fact, and the attach's own after-commit step then evicts the holder cache (line 413-417, holders read after commit include the puppet), so the puppet is an administrator on its next token mint. The window is not microseconds: it spans T1's whole time from first read to lock grant, and once T2's insert precedes T1's lock request the ordering is forced and lasts T2's remaining transaction time. The attacker cannot trigger the administrator's attach, so this needs an unwitting administrator action plus timing (an assign/revoke loop keeps an assign in flight, as T-E48 path 1 already notes), hence High rather than Blocker.

This is a fourth interleaving not listed in T-E48 (assign queued behind B8, attach queued behind B8, two attaches). The RC-56.7 harness cases in `LastAdminLockoutIT.java:843-978` (attach ∥ attach, B8 then attach, B8 then assign) do not include attach-completing ∥ assign, and the unit test at `RoleManagementServiceTest.java:1246` (`should_attachWithoutRbac012_when_theSnapshotAlreadySaidTheAttachCompletesTheCatalogue`) pins the current behaviour of not re-checking.

Risk: a non-administrator promotes a second account to administrator through a role whose completion was done by an administrator, bypassing the control T-E48/RC-56 declare merge-blocking.

Minimal safe fix. After `lockRoleRow` succeeds (line 369-371) and before the insert, when `becameAdminDefining` is true, do what B8's promotion branch already does: `acquireSetLock(actor, role, catalogueIds)` (line 1156) then `adminDefiningNow(...)` (line 703) then `requireNoLockedHolderAssignedByNonAdministrator(...)` (line 759). Both helpers exist and are already exercised by `RolePermissionReplaceConcurrencyIT`. Lock order is roles R X, then `user_roles` X, which is the promotion order RC-46 and the threat model section 10.2(a) already verified. Because attach holds R's X lock, no assign (needs S on R) can add a holder after this point, so the locked read is final. The pre-lock check at lines 360-362 can stay as a cheap fast-fail or be removed. The set lock is taken only on the rare completing branch, so contention is negligible. Smaller alternative (not preferred): a locking read of R's holders after the lock; it still leaves the "assigner is currently an administrator" side on the stale snapshot.
Tests to add: (a) IT with a gate: attach-completing blocked at the role row while an assign commits first, expects 409 `RBAC_010` and no holder row; run as `nexus_app` like the other RC-56.7 cases; (b) flip the unit test at `RoleManagementServiceTest.java:1246` so a completing attach re-checks under the lock.

#### 2. [Medium] Assign's set-lock path decides "caller is an administrator" from the pre-lock M10' read (A01)

File: `nexus-backend/src/main/java/com/example/nexus/rbac/application/RoleAssignmentService.java:235` (`acquireSetLock`), `:247-258` (self-target administrator answer and PII rule), `:578-586`, `:813-822`; contrast revoke at `:378-381` which calls `classifyLockedRolesNow`.

Issue. `SetLock.adminDefiningRoleIds` comes from the M10' read taken before the lock is requested (`acquireSetLock`, line 579). Revoke re-derives it from a `FOR SHARE` read under the lock (RC-57.2, line 381); assign does not. `callerHoldsAdministratorRole` (line 536) therefore uses a possibly stale class.

Interleaving. C holds custom role D (admin-defining) and self-assigns an admin-defining role R. In parallel an administrator runs a B8 demotion of D (set lock, commits). C's assign had already read M10' (D admin-defining) and is queued on the set lock; after the demotion commits the locked rows still show C's active D row, the stale set still lists D, so `callerIsAdministrator` is true, A4 and the PII rule pass, and A2 uses the pre-wait snapshot (accepted RES-27). C ends up holding R, after being demoted. (A concurrent revoke of C's D row is NOT affected: the locked rows already reflect it.)
Risk: privilege persistence for a user whose administrator status was just removed, limited to a request already in flight when the demotion commits. Hence Medium, not High. This is the "known item 2" and also T-E49 class; RC-57.2's list (revoke, softDelete, break-glass) omitted assign.
Fix: in `assign`, replace the `setLock` by `classifyLockedRolesNow(actor, target, setLock)` right after `acquireSetLock` (same as line 378-381 for revoke). One line plus a unit test with a demotion between the M10' read and the lock (the existing `should_denyFromSetLockRows_when_adminDefiningTargetCarriesDirectoryReadAndCallerNotInLock` at `RoleAssignmentServiceTest.java:2846` does not cover a stale class).

#### 3. [Low] `existsById` on `users` is an unscoped cross-tenant existence query with no containment rule (A01, defense in depth)

File: `identity/infrastructure/persistence/JpaUserDirectoryQueryAdapter.java:70-73`, `identity/application/UserDirectoryService.java:171`, `identity/application/port/out/UserDirectoryQueryPort.java:44`.

Issue. The by-id 404 path calls the inherited `JpaRepository.existsById`, which has no tenant predicate. `countByIdIn` got a signed-off allowlist entry with three enforced conditions (RC-61.2); `existsById` is inherited, so `TenantIsolationArchitectureTest` does not see it and no ArchUnit rule restricts who may call it. Today it only feeds a WARN and a counter (verified: the response is identical for missing and foreign ids). A later caller of `UserDirectoryQueryPort.existsById` would be a cross-tenant "does this user id exist" oracle.
Fix: add a rule like `UNSCOPED_USER_COUNT_IS_CALLED_ONLY_BY_THE_DIRECTORY_ADAPTER` for `JpaUserRepository.existsById` (target the adapter only, and the port method only from `UserDirectoryService.notFound`), or rename the port method to say it is cross-tenant (`existsInAnyTenant`). Not a allowlist addition, so no sign-off needed beyond this note.

#### 4. [Low] Body parsing, bean validation and the 1 KiB read run before the permission check (A01 ordering, no state leak)

File: `identity/interfaces/rest/UserDirectoryController.java:220-221` (`@Valid @RequestBody`), `identity/interfaces/rest/LookupBodySizeLimit.java:46-56`, `rbac/interfaces/rest/RoleController.java` (`replaceRolePermissions`, `@Valid @RequestBody`).

Issue. `@RequiresPermission` is method security, which runs after argument resolution. A caller without `user:directory:read` or `role:write` therefore gets 400/415 (and costs a body read up to 1025 bytes) instead of 403 for malformed requests. Verified that the 400 messages never echo values and that no state is revealed, so this is not an oracle; it contradicts the "403 first" posture in the javadoc order lists.
Fix (optional): accept it and fix the javadoc/OpenAPI order text, or move the check to a filter/`HandlerInterceptor`. Not worth code change by itself.

#### 5. [Nit] Known items re-checked, no action needed or already on the record

- `permission_replace` outcome `replaced` versus design `applied`: naming drift only (`RoleManagementService.java:672-673`); alert rules must use `replaced`.
- `AppError.reason` as `string`: out of backend scope.
- SpotBugs `EI_EXPOSE_REP2` exclusions added for `RoleController`, `PermissionController`, `UserDirectoryService`, `CallerAuthorizationService`, `DirectoryReadAuthEventAdapter`, `UserDirectoryController` (`spotbugs-exclude.xml`): consistent with the file's existing convention (constructor-injected Spring beans), each carries a comment; acceptable.
- `UserDirectoryService` has four collaborators (query port, blind index, audit port, meter registry): fine.

#### 6. [Nit] A by-id directory 404 writes no audit row (known item)

`UserDirectoryService.java:105-112`: only successful reads are audited, by design ("every successful read"). The cross-tenant case is covered by WARN plus `cross_tenant_miss`. Design text says one row per request; align the design text or add a `GET/MISS` row. No security impact.

### Verified OK

Merge-blocking mitigations (code present AND a test that would fail without it, spot-checked):
- RC-55 (step 9 compares `v1` to `v0`, one strong tag): `RoleManagementService.java:553, 629-633`, `IfMatchHeader.java:20-32`. Tests: `IfMatchHeaderTest`, `RolePermissionReplaceConcurrencyIT.should_return412AndChangeNothing_when_anAttachCommitsBetweenSnapshotAndLock` (case g), `RolePermissionReplaceIT.should_return428...`. Equality is tested against the snapshot version, not membership.
- RC-58 order (403 before 412 before no-op, live `role:read`): `authorizeReplace` at `:816-872` runs before `:553`. Tests: `RolePermissionReplaceIT` lines 298 and 318 (no-op 403 for lost `role:write` / `role:read`).
- RC-57.1/57.2 (admin-defining set from a `FOR SHARE` read under the set lock) for B8, revoke, softDelete and break-glass: `:703-708`, `RoleAssignmentService.java:381`, `:1110-1115`, `BootstrapAdminService` diff. Assign is the gap (finding 2).
- RC-64 attach serialisation: `lockRoleRow` before the insert (`:369`); `AttachSerialisationIT` covers attach ∥ attach with no 1213.
- RC-56.2/56.3 for the assign branch behind B8 and attach behind B8: `RoleAssignmentService.requireAssignKeptItsClassification` (`:840-873`) and `requireAttachKeptItsClassification`; ITs at `LastAdminLockoutIT.java:853-978`. The attach-completing ∥ assign order is the uncovered one (finding 1).
- RC-60/RC-66 PII grant rule: evaluated after A3/A2 on all three verbs (attach `:346-355`, assign `:252-261`, replace `:834-850`), so `ADMINISTRATOR_REQUIRED` is shown only to a caller who already holds the permission; default `true` (`PiiPermissionGrantRule.java:62`, `application.yml`), startup WARN when off, prod-profile pin `PiiPermissionGrantRuleTest.should_resolveTrue_when_prodProfileActive` (loads the real yml files). Assign denial writes the audit row and a throttle denial (unit test line 2729). Assign's post-insert re-evaluation of the PII rule is present and tested (`RoleAssignmentServiceTest.java:2979-3007`). No bypass found: no other path adds a permission to a role (create role has no permissions; V11 footer (a) only completes roles that already carried all eight, by design).
- RC-61.2 `countByIdIn` allowlist sign-off: all three conditions hold. Count-only return type, adapter-only caller (ArchUnit rule in `ArchitectureRules`), result never reaches the response (`UserDirectoryService.batch`, `:87-102`). I record sign-off for that entry. No other `UNSCOPED_ALLOWLIST` addition in the diff.
- RC-59 handlers: `GlobalExceptionHandler.java:224-262` log `errorType`/`errorCode` only, never `getMessage()` or cause; `UserLookupRequest.toString` redacts; `handleBodyValidation` uses constraint default messages (no rejected value); `ApiRequestLoggingFilter` logs `getRequestURI()` only (no query string). `UserDirectoryLogScanIT` exists for malformed lookups.
- RC-63(c) deep paging: `page * size > 10000` rejected (`DirectoryPageRequest.java:70`); size 1..100; `ids` 1..100 canonical UUIDs, distinct, not combinable.
- Lookup via GET: `GET /api/v1/users?email=` is rejected 400 before any query (`DirectoryPageRequest.java:46-50`); lookup is POST, `consumes = application/json`, body capped at 1024 bytes before Jackson (`LookupBodySizeLimit`); no email in URL, logs, metrics or audit (audit metadata holds operation, counts, status filter, HIT/MISS, resolved user id only).
- Tenant isolation: tenant id comes from the JWT (`UserDirectoryController.resolveActor`, `RbacControllerSupport.resolveActor`), never from path/body; every directory repository method carries `tenantId` (`findByTenantId*`, `findByTenantIdAndIdIn`, `findByTenantIdAndId`, `findByTenantIdAndEmailHmac`); new native queries carry the tenant predicate via the `roles` join (`lockRolePermissionsByRoleIds`, `countPermissionsByRole`, `countActiveHoldersByRole`). Role 404 equivalence: `resolveRoleInTenant` (`:1180-1202`) returns the same `ROLE_NOT_FOUND` for missing, soft-deleted (`@SQLRestriction`) and foreign ids, after the 403 permission gate; foreign adds only a WARN and a counter. User by-id: `findByTenantIdAndId`, then `existsById` for both missing and foreign (same statements, same body).
- Rate limits: `DIR_ALL` ceiling on all four operations plus `DIR_LOOKUP` for lookup, keyed `(tenant, actor)`, consumed after authorization; WARN once per window via a one-slot bucket. Fail-open with the store is the documented ADR-0016 / D5 trade-off (residual, not a finding). RBAC_011 throttle: `Retry-After` computed, Redis failure fails safe to "not throttled" (authorization still decides).
- Mass assignment: all new request bodies are records with only the expected fields (`UserLookupRequest`, `ReplaceRolePermissionsRequest`); no tenant or actor field is bindable.
- Error-code leaks: `RBAC_001` wire `reason` is mapped through `CallerFacingDenialReason` (cross-tenant, absent permission, malformed auth collapse to `UNSPECIFIED`); 412 and 428 bodies carry no state; `RBAC_012` and `RBAC_010` messages are static literals and are raised only after the 403 checks.
- ETag handling: strong tag `rp1-<sha256 of role id + sorted permission ids>`, role-bound, documented as non-secret; `If-Match` accepts exactly one strong tag (list, `*`, weak, empty all 428); GET returns the ETag from the same read as the permissions; CORS allows `If-Match` and exposes `ETag` only.
- SQL string building: none. The new queries are JPQL with bound parameters or native text blocks with bound parameters; the only concatenation is a constant JPQL string split across lines (`JpaRoleManagementAdapter`, `deleteByRoleIdAndPermissionIdIn`).
- PII/blind index in logs, metrics, errors: grep of added lines for `log`/`addKeyValue`/`counter`/`tag` with email, hmac or blind found nothing; new metric tags are bounded (`outcome`, `operation`, `lockPath`, holder bucket); no tenant or user tags.
- V11: data-only append migration, footer (a)/(b) idempotent, soft-deleted roles excluded, system MEMBER gets nothing; `Permissions.SENSITIVE`/`NON_SENSITIVE` partition `ALL` and are barred from server rules by ArchUnit (RC-63(k)).
- Dev seeds: `@Profile("dev & !break-glass & !prod")` on `DevDataInitializer`, `DevUserSeeder`, `DevRbacSeeder`; `DEV_SEED_ACTIVE` WARN logs profile names only; the shared dev password is a constant never logged; `DevSeedProfileGuardTest` exists.
- Auth: every new route is annotated (`@RequiresPermission` on the directory and role routes, `@AuthenticatedEndpoint` on `/users/me/authorization`); feature flag defaults off (`feature.nexus-us019-user-directory.enabled: false`, enabled only in dev/test yml); `/me` literal wins over `/{userId}`.

### Not covered

- Frontend (S2..S5) and everything outside `nexus-backend/src/main`.
- Dependency scans: `./mvnw dependency:tree` and `npm audit` were not run (brief forbids starting Maven); the threat model's section 9.2 "all slices" re-run is still owed. No manifest change was seen in the diff of this slice.
- Not executed: no test, IT, harness or SQL was run; "test that fails without it" is judged by reading the assertions, not by mutation.
- `application-prod.yml` (never edited, hook), `OpenApiConfig`, contract fixtures, `DirectoryPageLinks`/DTO field mapping, and `AuthEventType`/`RbacAuthEventAdapter` additions were skimmed or not read in depth.
- Lock-order reasoning for the proposed fix in finding 1 is from the threat model section 10.2(a) and the code, not from an experiment; the IT in the suggestion should confirm no 1213.
- The Redis throttle adapters (`RedisRoleChangeThrottleAdapter`, `RateLimitRoleChangeThrottleAdapter`) were read only for the `throttleStatus` change.

## 2. Slice S2 — frontend, CI, supply chain
## US-019 security review, slice S2 (frontend, CI, supply chain)

### Summary
Blocker 0, High 0, Medium 2, Low 5, Nit 1. Verdict: APPROVE WITH NITS.
No exploitable open redirect, XSS sink, token leak or workflow injection found.
Reviewed for authentication/token handling, authorization guards, input validation, XSS, open redirect, supply chain (OWASP A01, A03, A05, A06, A08). No crypto and no server-side PII-handling code in this slice.

### Findings

1. [Medium] CI will fail on every run: the registration spec skips at runtime, and the skip guard rejects any skip (A04, availability of the control)
   - Files: nexus-frontend/e2e/auth/registration.spec.ts:97-101 (`test.skip(true, 'MailHog is not reachable')`), .github/workflows/e2e-full-stack.yml:45 and :91, docker-compose.yml:134 (mailhog is neither a `backend` dependency nor started by the workflow).
   - Scenario: the workflow runs `$COMPOSE up -d --build backend`, which starts only mysql, redis, flyway-migrate and backend. The registration happy path polls MailHog, finds nothing, and skips. `assert-executed.mjs` then reports `skipped: ...` and exits 1. The required check is red on all PRs. Teams then tend to lower `E2E_MIN_TESTS` or drop the skip check, which weakens R6. This matches the brief's note that the compose path never ran end to end.
   - Fix: either start `mailhog` in the "Start Backend Stack" step (`up -d --build backend mailhog`), or replace the runtime skip in that spec with an `E2E_REQUIRE_BACKEND`-style hard failure. `logout.spec.ts:45` and `session-refresh.spec.ts:33` use `testInfo.skip()` without honouring `E2E_REQUIRE_BACKEND`. They are caught by assert-executed, but they should throw like `fixtures/backend.ts` does.

2. [Medium] scan-pii.mjs matches only the plain lowercase address and the hex blind index (A09, PII in artifacts)
   - File: nexus-frontend/e2e/tools/scan-pii.mjs:51-58 and :68-80.
   - Gaps: it does not catch URL-encoded forms (`test%40example.com`, which is how an address appears in query strings and access-log URLs), JSON `@` escapes, HTML entities, or UTF-16 content. Failure screenshots (PNG, `screenshot: 'only-on-failure'`) are uploaded unscanned, and the shell header shows the signed-in email. The embedded-report regex takes only the first `data:application/zip;base64,` match (`.exec`, not global).
   - Mitigating: the personas are synthetic dev data, so the actual risk is low. The claim "artifacts are uploaded only if this passes" is stronger than what is enforced.
   - Fix: add needles for `encodeURIComponent(email)` and the `@` form. Use a global regex for embedded zips. Either state that screenshots are out of scope or drop them from the upload (`screenshot: 'off'` in CI). Also scan the generated `e2e-<ts>@example.com` registrants with a `e2e-\d+@example\.com` pattern.

3. [Low] `safeReturnUrl` is sound. Two harmless edge notes, no exploit.
   - File: nexus-frontend/src/app/core/routing/safe-return-url.ts:32.
   - `/auth;x=1/login`, `/%61uth/login` and `/AUTH` pass the `/auth` exclusion check. The router resolves them to the login page, so the worst case is a redirect loop back to login, not an escape.
   - A returnUrl nested inside a returnUrl (`/dashboard?returnUrl=//evil`) is allowed. It stays in-app because `navigateByUrl` only takes in-app URLs, and nothing re-reads it except `login-form.component.ts:251`, which re-validates.
   - Optional fix: reject `;` in the path, or compare case-insensitively after segment parsing.

4. [Low] `Retry-After` is unbounded (A04).
   - Files: nexus-frontend/src/app/core/http/api-error.interceptor.ts:146-153 and service-availability-notifier.ts:29-30.
   - `/^\d+$/` accepts a huge digit string. `Number()` can return `Infinity`, so `suppressUntilMs` becomes Infinity. That suppresses the availability toast until reload, and the message reads "Try again in Infinity seconds". A hostile proxy or a buggy server could cause this.
   - Fix: `Number.isSafeInteger(seconds)` plus a cap, for example 3600.

5. [Low] Fail-open `permissionGuard` on a missing `data.permission` (A01, defence in depth).
   - File: nexus-frontend/src/app/core/guards/permission.guard.ts:57.
   - Documented as UX only; the server enforces authorization. `app.routes.spec.ts` plus `permission-guard-contract.spec.ts` are the compensating controls. The routes currently contain only the dashboard and the wildcard, so the exposure today is nil.
   - Fix (optional): fail closed for a route that has the key but an invalid value.

6. [Low] The HTML-sink lint rule is bypassable by syntax variants (A03).
   - File: nexus-frontend/eslint.config.js:50-55 and :93.
   - Not covered: computed access `el['innerHTML']`, `insertAdjacentHTML`, `document.write`, `Range.createContextualFragment`, `DOMParser`, destructuring `const { bypassSecurityTrustHtml } = san`, and template `[srcdoc]` or `[attr.innerHTML]`. `eslint-disable` comments are not banned.
   - It is a guardrail, not a boundary, and there are currently no uses (grep over `src` is clean).
   - Fix: add selectors for `MemberExpression[computed=true][property.value=/innerHTML|outerHTML/i]`, `insertAdjacentHTML`, `document.write`, `createContextualFragment`, and `Identifier[name=/^bypassSecurityTrust/]`. Enable `reportUnusedDisableDirectives` and ban disabling this rule.

7. [Low] `parseSupportContact` throws on a non-string label (A05).
   - File: nexus-frontend/src/app/core/config/app-config.ts:97-100.
   - `raw.label.trim()` throws a TypeError if the config's label is not a string. The throw happens at render time and would break the access-denied page.
   - Fix: `typeof raw.label !== 'string' || typeof raw.href !== 'string'` returns null.
   - The scheme check itself is correct: `mailto:` or `https://` only, no whitespace or control characters, case-insensitive, and Angular's href sanitiser backs it up.

8. [Low] Unpinned or unscoped CI trust (A08).
   - File: .github/workflows/e2e-full-stack.yml.
   - The workflow comes from the PR head, so a PR can edit `E2E_MIN_TESTS`, the scan step, or the workflow itself. That is inherent to `pull_request`. Mitigation: make the check required via branch protection, with CODEOWNERS on `.github/` and `e2e/tools/`.
   - Action SHAs are shared with the existing workflows on main (same pins), which I could not verify against upstream because GitHub API access was denied. The `# v4.4.0` comment on `actions/checkout` should be confirmed.

9. [Nit] The lockfile diff is large: 3246 additions and 5422 deletions, with about 222 new package entries from the Angular 22.0.4 to 22.2.3 upgrade.
   - Every `resolved` URL points at registry.npmjs.org (checked). The only `hasInstallScript` addition is `lmdb`. CI uses `npm ci --ignore-scripts`.

### Verified OK
- Open redirect (`safe-return-url.ts:24-40`, read in full). Rejected: no leading `/`, `//`, `/\`, any backslash, C0, C1, DEL, U+2028 and U+2029 (tab, newline and CR variants), `:` in the path (`/javascript:`), `%2f`, `%5c` and `%00-%1f` in the path, `/auth` and `/auth/*`, and a final same-origin check via `new URL`. No decoding is done, so there is no validate-one-string, navigate-another gap. Unicode slash look-alikes are not normalised by the URL parser in the path. Consumed only through `Router.navigateByUrl` (`login-form.component.ts:251`), which cannot leave the app.
- Support contact (`app-config.ts:88-100`, `access-denied.component.ts:84`, template). The label is interpolated as text and the href is validated. `rel="noopener noreferrer"` is set. The component never shows `requiredPermission` or `reason`, and the page makes no HTTP call.
- Guards. `authGuard` fails closed: any refresh error leads to a login redirect. `permissionGuard` redirects without query params, and its log strips the query and fragment. Route table: the auth guard sits on the shell ancestor (`app.routes.ts` diff), and `canActivateChild` is used nowhere (grep clean, and `app.routes.spec.ts:123` enforces it). `access-denied` is unguarded and outside the shell.
- Error disclosure. `reason` is parsed only for `RBAC_001` and only if it is a string (`api-error.interceptor.ts:107-109`), and there is no UI consumer in the frontend (grep clean). `retryAfterSeconds` is parsed as an integer.
- Workflow. `on: pull_request` only, never `pull_request_target`. `permissions: contents: read`. No secrets. `persist-credentials: false`. No `${{ }}` expression interpolated into any `run:`; the only expression is `github.ref` in the concurrency group. All actions are pinned by SHA. Artifacts are retained 7 days. Artifact upload is gated on the PII scan outcome. `npm ci --ignore-scripts`. Backend port is bound to 127.0.0.1.
- docker-compose.e2e.yml. It only raises rate limits for the CI backend and sets REDIS_HOST. The base file keeps the least-privilege `nexus_app` user and the `full` profile; naming `backend` activates the profile. It is not referenced by prod files.
- assert-executed.mjs. `skipped` is rejected, `executed < min` is rejected, and arguments are validated. A zero-test report fails, with fixtures and a self-test. `flaky` counts as executed, which is acceptable. Failures are caught by the Playwright exit code of the step before.
- scan-pii.mjs. Recurses into zips, nested zips and the embedded report. A corrupt zip throws, so it fails closed. Missing paths exit 2, so artifacts are not uploaded. Self-tests cover log, case, zip and clean inputs.
- Dependencies. `npm audit --omit=dev` in nexus-frontend returned 0 vulnerabilities. `axe-core` 4.14.0 is a devDependency only. All lockfile `resolved` URLs are registry.npmjs.org.
- No `bypassSecurityTrust*`, `innerHTML` or `outerHTML` use in `src` (grep). Tokens are not placed in URLs or logs in the changed code.

### Not covered
- Backend slices and server-side authorization.
- The visual and contrast changes across about 20 SCSS files.
- Running the workflow, compose and Playwright suite (no Docker or Maven allowed). Whether `permissionGuard`'s lint-rule spec passes was taken from the spec text, not executed.
- Upstream SHA verification of the GitHub Actions (API access denied).
- `npm audit` for dev dependencies, and the `.claude/hooks/agent-usage.mjs` tooling, which is outside this slice's product surface.

## 3. Opus re-check queue (after 2026-10-25 20:00 UTC)

- T-025 `safeReturnUrl` percent-hazard rule and `parseSupportContact`.
- The attach-provenance fix and the assign set-lock fix (lock order RC-46).

## 4. Disposition

**Date:** 2026-10-22. Commit SHAs are from `git log --oneline origin/main..HEAD` on `feature/US-019`. Pending ids (P-n) are in [14-pending-items.md](14-pending-items.md). The Opus re-check of the locking and `safeReturnUrl` fixes is queued as P-12. Findings carry the numbers used in the slice reports above.

### S1 (backend)

| Id | Severity | Status | Disposition |
|---|---|---|---|
| S1-1 | High | Fixed | `2ca17e7`: attach re-judges the `RBAC_010` provenance under the set lock after the role-row lock (same fix as R1-1). Opus re-check P-12 |
| S1-2 | Medium | Fixed | `fdb18ae`: assign classifies from a current read under the set lock (same fix as R1-2). Opus re-check P-12 |
| S1-3 | Low | Fixed | `aea67c3`: ArchUnit containment of the `existsById` probe (same as R2-3) |
| S1-4 | Low | Fixed (lookup); Accepted (PUT) | `99d2db2`: lookup authorises before the body is read. Accepted for `PUT /roles/{roleId}/permissions`: a malformed body gets 400 before 403, no value is echoed and no state is revealed; the controller Javadoc states the order |
| S1-5 | Nit | Accepted | The `replaced` label is recorded in the design amendments (P-19); `AppError.reason` typing is P-17; the SpotBugs exclusions follow the file's convention |
| S1-6 | Nit | Deferred | P-18 (by-id 404 writes no audit row; design text amended, decision pending) |

### S2 (frontend, CI, supply chain)

| Id | Severity | Status | Disposition |
|---|---|---|---|
| S2-1 | Medium | Fixed | `8dd824e`: the workflow starts `mailhog`, the e2e backend's SMTP host points at it, and logout, session-refresh and registration use `requireBackend()` or throw under `E2E_REQUIRE_BACKEND=1`. The path itself has not run end to end: P-11 |
| S2-2 | Medium | Fixed | `302d088`: the PII scan covers encoded forms, every embedded report zip and the registrant pattern; CI takes no screenshots and the scan fails on any image |
| S2-3 | Low | Accepted | Edge notes with no exploit (the worst case is a redirect back to login). Re-check with the Opus queue: P-12 |
| S2-4 | Low | Fixed | `10e2d61`: `Retry-After` capped at 300 s |
| S2-5 | Low | Accepted | `permissionGuard` fail-open on a missing `data.permission` is documented as UX only; `app.routes.spec.ts` and `permission-guard-contract.spec.ts` compensate and no gated route exists yet |
| S2-6 | Low | Fixed | `10e2d61`: the HTML-sink rule also bans bracket access, `insertAdjacentHTML`, `createContextualFragment`, `document.write`, `innerHTML` property keys and aliased or destructured `bypassSecurityTrust*`; `lint-rules.spec.ts` |
| S2-7 | Low | Fixed | `10e2d61`: `parseSupportContact` returns `null` for a non-string label or href |
| S2-8 | Low | Deferred | P-9 (required check, CODEOWNERS entries, upstream SHA verification) |
| S2-9 | Nit | Accepted | Lockfile growth comes from the Angular 22.0.4 to 22.2.3 upgrade; every `resolved` URL is the npm registry and CI uses `npm ci --ignore-scripts` |
