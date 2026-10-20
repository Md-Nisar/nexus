# US-019 — Task Breakdown: Prerequisites for the RBAC Access Management UI

**Phase:** 4 (Task Breakdown), Gate 3

**Gate 3:** approved 2026-10-19 by the story owner (approver name to be recorded). Open item O-2 is resolved as recommended: T-007 (the administrator-only rule for granting `user:directory:read`) may merge ahead of the D5-gated directory tasks, so the permission replace (T-019) does not wait on D5. Open item O-1 stays open: no request-rate or latency budget is stated, so no load test is added.
**Epic:** EPIC-002 (RBAC Foundation)

**Why 28 tasks rather than ≤ 8:** the approved design spans six slices (S0–S5) and about 31 items across backend, frontend and CI. Its estimated production code is about 11,000 lines (backend ≈ 6,500, frontend ≈ 4,000, CI and fixtures ≈ 500), and 11,000 ÷ 400 ≈ 27. One more slice isolates a real risk: the platform-wide body and protocol handlers (T-003) that both the directory slice and B8 depend on, and that must not wait for D5.

**Inputs (all read, binding):**
- `docs/features/US-019/03-design.md`: Revision 1 with RC-55..RC-63 and the delta changes RC-64..RC-67, **approved at Gate 2 on 2026-10-19** (cited as "design §x"). The slices and exit gates are in §1.2, the B8 algorithm and harness in §10.3–§10.9, and the security decisions SD-1..SD-33 in §20.
- `docs/features/US-019/03b-threat-model.md`: §3 threats, §6 RC-55..RC-63, §7 residuals, §9 required changes and the merge-blocking list, §10 delta review with RC-64..RC-67 and the final merge-blocking list in §10.7 (cited as "TM §x").
- `docs/features/US-019/01-requirements.md`: ACs A1–A11, B1–B10, C1–C4, D1–D6; Gate 1 decisions in §13a.
- `docs/features/US-019/02-impact.md` (file inventories; cited as "impact §x"), `00-discovery.md`, ADRs 0021 (Revision 3), 0026 and 0027 (Proposed).
- Skills `spring-boot-standards`, `angular-standards`, `design-system`, `api-design`; `.claude/commands/breakdown.md`.
- Format precedent: `docs/features/US-018/04-tasks.md`.

**Path shorthand.** `BE/` = `nexus-backend/src/main/java/com/example/nexus/`, `BT/` = `nexus-backend/src/test/java/com/example/nexus/`, `RES/` = `nexus-backend/src/main/resources/`, `FE/` = `nexus-frontend/src/app/`, `E2E/` = `nexus-frontend/e2e/`. Every path under "Files impacted" was confirmed to exist with Glob on `feature/US-019` this session, except those marked *(locate)*: for those the design names a role but not a file, and `/implement` finds the file with Grep at planning. Paths under "Files created" do not exist yet. Line numbers are the design's and the impact's citations at `2962b0e`. Re-read them before editing, because T-016 to T-021 each shift `RoleManagementService.java` and `RoleAssignmentService.java`.

**Per-task gate** (CLAUDE.md §4):
- **Backend tasks** run `./mvnw verify -DskipITs` from `nexus-backend/` (`mvnw.cmd` on Windows). A task that touches persistence, a migration or a `*IT` also runs **`./mvnw verify` with Docker up** before its slice merges. This applies to every backend task except T-022.
- **Frontend tasks** run `npm run test:ci`, then `npm run lint && npm run format:check`, from `nexus-frontend/`, and `npm run build` (budgets) before the PR.
- Each task **writes its own** unit tests and `*IT` classes first.

**Per-slice exit** (operating model): `/review` → `/security-review` → `/test-validate` → `/pre-pr-check` → PR. Every slice's `/security-review` re-runs `./mvnw dependency:tree` and `npm audit` (TM §9.2, "all slices").

**Feature flags:** one new flag, `feature.nexus-us019-user-directory.enabled`, introduced in T-004 and also used by T-005, T-006 and T-008. B3, B5, B6 and B8 ride us015. B7, V11 and the frontend have no flag (design §15).

**No PII.** People are referred to by role only. No persona address appears in this file.

---

## Gate 1 gaps (found while slicing; not invented here)

| # | Gap | Handling |
|---|---|---|
| G-1 | **No RPS, latency or SLO budget.** Requirements NF-F1 and G1 state none, and mark the feature "not hot path [CONFIRM]". Design §16 proposes p95 < 200 ms at dev volume for B1, B3 and B4 *for confirmation*, and says that none of these is a hot path. The directory and authorization endpoints are not on every request. | **No load test is added and no budget is invented.** The only latency assertion in this breakdown is the threat model's RC-67(a) bound (added wait < 50 ms p95 at dev volume, in `AssignRoleContentionIT`, T-020), which is a contention check, not an SLO. The proposed p95 target remains a Gate 1 gap for the story owner (open item O-1). |
| G-2 | No acceptance criterion for observability (requirements G12). | Each task's DoD carries the metrics, logs and audit that design §17 names. Alert rules are `monitoring.md` content (Phase 9), not tasks. |

## Ambiguities resolved by judgment (read before the named task)

| # | Where | Ambiguity | Resolution |
|---|---|---|---|
| A-1 | design §12.3 vs §1.2 | The shell's user menu uses `nx-menu`, an S2c wrapper, but the design orders S2a (the shell) before S2c. S2c's directives may not merge before RC-62. | **`nx-menu` is built in the shell task (T-010)**, and T-010 depends on the RC-62 upgrade task (T-009). The S2c merge block is therefore satisfied for every directive, and A1 (T-011) still follows the shell. |
| A-2 | design §9.3 vs §4.5 | `RateLimitException.selfReported()` is introduced for `RBAC_011` (S3b) but is also needed by `USER_DIR_001` and `USER_DIR_002` (S1c, RC-63(c)), and either slice could merge first. | It lands once, in **T-003**, together with the RC-59 handlers, because it is handler logging policy. `RefreshThrottledException` moves from the `instanceof` check to `selfReported() = true` in the same commit. |
| A-3 | TM §9.2 / §10.7 | The RC-59 handlers are listed under both S1c and S3c, and S1c cannot merge before D5. | **T-003 is its own PR**, merged before T-005 and T-018. That way B8 never waits on D5 for the handlers. |
| A-4 | design §4.8, TM §10.7 | The RC-60 PII grant rule (T-007) changes the shipped attach and assign verbs and sits on S1c's D5-gated merge list. T-019 (B8) applies the same rule to B8 adds. | T-019 depends on T-007's helper, so **S3c's merge effectively waits on D5** unless the story owner lets T-007 merge ahead of the directory tasks. That is safe: the rule is default ON and only more restrictive. This is the owner's decision (open item O-2). Until it is made, T-007 stays in the S1c PR. |
| A-5 | design §12.10 | The 503 `AUTH_005` notifier is not assigned to a slice. | It goes with the B7 frontend half (**T-017**), which introduces `AppError.retryAfterSeconds`. That field is also what the S3b exit gate's "no auto-retry of `RBAC_011`" spec needs, which is why the field lands in S3b rather than in A11 (T-028). T-028 later pins the types against the fixtures. |
| A-6 | design §13.2 vs §1.2 | The shell e2e suite includes Not Found and the `returnUrl` round trip (S5a), but the design draws C2 from S2a and C1 only. | **T-026 (C2) depends on T-024 and T-025**, so the suite is written once, against final routes. T-024 and T-025 carry unit and real-Router tests only. |
| A-7 | design §1.2 S3c | Concurrency cases (a)–(g) span B8's role-row path and its set-lock path. | Cases (a), (b), (c) and (g) belong to T-018 (role-row path, no promotion). Cases (d), (e) and (f) and the harness C B8 threads belong to T-019. The RC-56.7, RC-64 and RC-67(a) cases belong to T-020. The RC-57.4 "B8 demotion ∥ revoke" case belongs to T-021. |
| A-8 | design §3.5 | "Migrate the 20 literal-id test files" could look like test-only work. | It stays in T-001 (V11). It is what keeps the build green when the catalogue grows to nine. |

---

## Slice map and PR boundaries

```
US-019
├─ PR S1a  V11 ...................................... T-001
├─ PR S1b  B3 + B5 .................................. T-002
├─ PR H    protocol/body handlers (RC-59.1) ......... T-003                (before S1c and S3c)
├─ PR S1c  directory + PII rule ..................... T-004 T-005 T-006 T-007   (merge: D5, Ops)
├─ PR S1d  B4 ....................................... T-008
├─ PR S2   frontend foundations ..................... T-009 T-010 T-011 T-012 T-013 T-014 T-015
├─ PR S3a  B6 ....................................... T-016
├─ PR S3b  B7 (+ SPA Retry-After handling) .......... T-017
├─ PR S3c  B8 + US-018 verb changes ................. T-018 T-019 T-020 T-021
├─ PR S3d  B10 ...................................... T-022
├─ PR S4a  C1 personas .............................. T-023
├─ PR S5a  A7–A10 ................................... T-024 T-025
├─ PR S4b–c C2 fixtures + C4 CI ..................... T-026 T-027
└─ PR S5b  A11 contracts ............................ T-028
   S0 (human) and S5c (D6, B9, release note, flag plan text) ... no tasks (Phase 9 /docs, human tracks)
```

**Totals:** S1a 1 · S1b 1 · H 1 · S1c 4 · S1d 1 · S2 7 · S3a 1 · S3b 1 · S3c 4 · S3d 1 · S4a 1 · S5a 2 · S4b–c 2 · S5b 1 = **28 tasks**. S2 may be split into two PRs (T-009 to T-011, then T-012 to T-015) at the reviewer's choice. Its merge rule does not change.

### Merge checklists (from TM §9.2 and §10.7, plus design §1.2)

- **S1a (T-001):** the RC-63(d) runbook ordering is written, in the S1a docs pass before merge. The V11 semantic IT and `PermissionMigrationFooterScannerTest`, **unmodified**, are green. The V11 version number is confirmed at merge.
- **H (T-003):** release-note line for the platform-wide status changes from 500 to 400, 405 and 415 (RC-67(c)), written in the docs pass.
- **S1c (T-004 to T-007):**
  - D5 signed (POST lookup, fail-open throttle, best-effort audit, RES-49, RES-51 and the RC-60 default);
  - Ops sign-off of RES-6 retention for `IDENTITY_DIRECTORY_CROSS_TENANT_TARGET` and `RBAC_PII_PERMISSION_DELEGATED`;
  - Ops thresholds for the RC-61.1 alerts;
  - RC-59 in (T-003 merged); RC-60.2, RC-61.2, RC-66.1, RC-66.2 and RC-66.4 in;
  - `UserDirectoryIT`, with `traceId` and `instance` normalised, and the log-scan IT green.
- **S2 (T-012 to T-014, and T-010's `nx-menu`):** `@angular/*` ≥ 22.2.0, `npm audit --omit=dev` with no high or critical finding, and the HTML-sink ESLint ban, all in T-009. The RC-62.2 toolchain criticals are recorded by the Frontend Tech Lead.
- **S3b (T-017):** RC-63(l) in. RES-47 acceptance is already recorded at Gate 2.
- **S3c (T-018 to T-021):**
  - RC-55 (all items), RC-56.2–56.4, RC-57.1–57.2, RC-58.1–58.4, RC-64, RC-66.3 and RC-67(a) in, with their tests;
  - `RolesPrivilegeIT` and `RolePermissionsPrivilegeIT` green **as `nexus_app`**, with `SHOW GRANTS` unchanged;
  - concurrency cases (a)–(g), the RC-64 harness, `AssignRoleContentionIT` and harness C (in `LastAdminLockoutIT`, including the B8 threads and the RC-56.7 and RC-57.4 cases) green, with no 1213 outside RES-45;
  - `LastAdminLockoutIT` outcomes unchanged;
  - T-003 merged (RC-59.1);
  - Ops sign-off of RES-6 for `RBAC_ADMIN_DEFINING_ROLE_HAS_NON_ADMIN_ASSIGNED_HOLDER`.
- **S5a (T-024, T-025):** RC-65 is satisfied by the design's choice, which drops `canActivateChild`. A spec pins it (T-025).
- **S4a, S4c (T-023, T-027):** RC-63(g) and RC-63(h) in.

---

# S1a — V11 and `user:directory:read`

### T-001 — The catalogue gains `user:directory:read` without changing who is an administrator, and test fixtures cannot silently stop building one

**Description.**
- **(a) Migration.** `V11__rbac_user_directory_read_permission.sql` inserts `user:directory:read` (id `019f6839-1808-7000-8000-000000000009`). It then applies footer (a), A-V9 variant, bound to exactly that id with `r.deleted_at IS NULL`, and footer (b), verbatim. Data only: no DDL, no grant (design §3.1, §3.2).
- **(b) Constants.**
  - `Permissions.USER_DIRECTORY_READ`, added to `ALL`, with the Javadoc corrected.
  - `RbacSeededPermissionIds.USER_DIRECTORY_READ`; the RC-60 rule in T-007 keys on this id.
  - Frontend `permission.ts`: union member and `PERMISSIONS` entry. The label lands in T-015.
- **(c) Fixture controls** (design §3.5):
  - `RbacTestCatalogue` with `allPermissionIds(JdbcTemplate)` and `createAdministratorRole(...)`, which reads every `permissions` row at call time;
  - `SeededPermissionLiteralScanTest`, with its allow-list;
  - an `assertAdministrator(userId, tenantId)` fixture check;
  - migration of the 20 test files (44 literals) in the same commit.

**ACs covered:** prerequisite of B1, B2, C1 and A5. Gate 1 Q1, which closes R1 by design.
**Dependencies:** none.
**Files impacted:**
- `BE/common/security/Permissions.java`, `BE/rbac/domain/RbacSeededPermissionIds.java`
- `FE/shared/types/permission.ts`
- `BT/rbac/RbacSchemaMigrationIT.java`, `BT/rbac/PermissionsCatalogueIT.java`
- the 20 test files found by `grep -rl '019f6839-180[0-7]' nexus-backend/src/test` *(locate)*

**Files created:**
- `RES/db/migration/V11__rbac_user_directory_read_permission.sql`
- `BT/rbac/RbacTestCatalogue.java`, `BT/rbac/SeededPermissionLiteralScanTest.java`
- `BT/rbac/V11AdministratorPreservationIT.java` (the semantic IT)

**Complexity:** M (≈ 120 production lines plus heavy fixture churn).
**Risks:**
- **Authorization:** the administrator definition moves from 8 to 9 permissions for every running instance at commit (design §2.1). A footer bound to the wrong id, or a missing `deleted_at` filter, demotes administrators or promotes a 7-of-8 role.
- **Fixture churn:** no assertion may be weakened. A fixture that intends a non-administrator keeps its literals only through `RbacSeededPermissionIds`.
- **Transactionality:** AS-3 is unverified in this repo.

**Tests (written first):**
- `RbacSchemaMigrationIT`: permission count 8 → 9; system-role pairs 9 → 10; the names list; a footer re-execution test copied from V6's.
- Semantic IT (RC-48.2): seed (i) a full-catalogue custom role with a holder, (ii) a 7-of-8 role and (iii) a soft-deleted full-catalogue role. After V11: (i) gains the permission and its holder is still an administrator; (ii) and (iii) gain nothing; `RbacZeroActiveAdminsHealthIndicator` is green before and after.
- `PermissionMigrationFooterScannerTest` passes **unmodified**. `PermissionsCatalogueIT`: `ALL` equals the table (9).
- `SeededPermissionLiteralScanTest` fails on a fixture file outside the allow-list (negative fixture).

**DoD:**
- V11 present and every case above green under `./mvnw verify` (Docker).
- `./mvnw verify -DskipITs` green. Frontend gates green for `permission.ts`.
- S1a merge checklist above. No new flag. One commit.

---

# S1b — B3 single role, B5 `isSensitive`

### T-002 — A role reader can fetch one role, and every permission says whether it is sensitive

**Description.**
- **B3** (design §5): `GET /api/v1/roles/{roleId}`, `@RequiresPermission(ROLE_READ)`, us015. It calls `RoleManagementService.getRole(actor, roleId)`, which is `@Transactional(readOnly = true)` and goes through the existing private `resolveRoleInTenant`. Missing, deleted and other-tenant roles give 404 `ROLE_NOT_FOUND`, with the existing cross-tenant WARN and counter. There is no ETag.
- **B5** (design §7):
  - `PermissionResponse` gains `boolean isSensitive`, set by the one mapper `PermissionController.toResponse`, so the catalogue, role-permission and attach responses all carry it.
  - `Permissions.SENSITIVE` and `NON_SENSITIVE` partition `ALL`, using the proposed default set (Q-D1, Security confirms at D5).
  - ArchUnit (RC-63(k)): in `src/main`, `SENSITIVE` and `NON_SENSITIVE` are referenced only by that mapper.
- One task because both are small additive us015 reads on the same controllers (≈ 150 production lines).

**ACs covered:** B3; B5.
**Dependencies:** T-001 (`ALL` contains nine names).
**Files impacted:**
- `BE/rbac/interfaces/rest/RoleController.java`, `BE/rbac/application/RoleManagementService.java`
- `BE/rbac/interfaces/rest/PermissionController.java`, `BE/rbac/interfaces/rest/dto/PermissionResponse.java`, `BE/common/security/Permissions.java`
- `BT/rbac/interfaces/rest/RoleControllerTest.java`, `BT/rbac/interfaces/rest/PermissionControllerTest.java`, `BT/rbac/interfaces/rest/RbacRoleManagementFeatureFlagTest.java`
- `BT/rbac/security/CrossTenantNotFoundEquivalenceIT.java`, `BT/common/security/PermissionsCatalogueTest.java`, `BT/rbac/PermissionsCatalogueIT.java`, `BT/architecture/HexagonalArchitectureTest.java`

**Files created:** none.
**Complexity:** S.
**Risks:**
- **Authorization:** a server rule must never read `isSensitive`; the ArchUnit rule enforces this.
- **Tenant isolation:** the B3 404 must be byte-identical across missing, deleted and other-tenant roles (NF-S2).

**Tests (written first):**
- `RoleControllerTest`: 200 shape; 400 for a malformed UUID; 403.
- `CrossTenantNotFoundEquivalenceIT` extended with B3: missing, deleted and other-tenant give equal bytes once `traceId` and `instance` are normalised (RC-63(j)).
- Flag test: B3 gives 404 `RESOURCE_NOT_FOUND` with us015 off.
- `PermissionsCatalogueTest`: union = `ALL` and intersection = ∅.
- `PermissionControllerTest`: `isSensitive == SENSITIVE.contains(name)` for every row, and the key is serialised as `isSensitive`.
- ArchUnit containment rule, with a negative fixture.

**DoD:** gates green, `./mvnw verify` with Docker for the IT. No new flag. One commit.

---

# H — Platform protocol and body handlers (own PR; before S1c and S3c)

### T-003 — Malformed bodies, wrong media types, wrong methods and missing headers get 400/415/405, and their exception text never reaches a log

**Description** (design §10.7, RC-59.1, A-2, A-3):
- `GlobalExceptionHandler` gains four handlers, each built with `problem(...)` and each logging `errorType` and `errorCode` only, **never `getMessage()` or the cause**:
  - `HttpMessageNotReadableException` → 400 `VALIDATION_FAILED`, detail "Request body is not valid JSON.";
  - `HttpMediaTypeNotSupportedException` → 415 `UNSUPPORTED_MEDIA_TYPE`;
  - `HttpRequestMethodNotSupportedException` → 405 `METHOD_NOT_ALLOWED`, with the `Allow` header;
  - `MissingRequestHeaderException` → 400 `VALIDATION_FAILED`, where the field is the header name and never its value.
- `RateLimitException.selfReported()` (default `false`). `RefreshThrottledException` returns `true`, and `handleRateLimit` logs self-reported exceptions at DEBUG instead of using its `instanceof` check.

**ACs covered:** B1 and B8 error rows (NF-P1: no email in logs); supports B10.
**Dependencies:** none. Serialise the merge with T-017 and T-018, which also edit `GlobalExceptionHandler` (impact §9.3).
**Files impacted:** `BE/common/web/GlobalExceptionHandler.java`, `BE/common/domain/RateLimitException.java`, `BE/common/domain/RefreshThrottledException.java`, `BT/common/web/GlobalExceptionHandlerTest.java`.
**Files created:** none.
**Complexity:** S (≈ 90 production lines; isolated so that neither S1c's D5 gate nor S3c blocks it).
**Risks:**
- **PII:** a Jackson parse error quotes request tokens, which can be an email's local part (T-I21).
- **Behaviour change:** malformed attach and assign bodies go platform-wide from 500 to 400. This is benign and needs a release-note line (RC-67(c)).

**Tests (written first):** `GlobalExceptionHandlerTest`:
- each status and code;
- `Allow` present on 405;
- with `OutputCaptureExtension`, a parse error carrying a sentinel token never appears in the captured log;
- a `RefreshThrottledException` logs at DEBUG and not at WARN;
- a plain `RateLimitException` still WARNs.

**DoD:** `./mvnw verify -DskipITs` green. Release-note line in the docs pass. No new flag. One commit.

---

# S1c — B1/B2 user directory, lookup, PII grant rule

### T-004 — A directory reader can list, batch-fetch and fetch users of their own tenant only, with exactly five fields

**Description** (design §4.1, §4.2, §4.6):
- **Controller and request parsing.** `UserDirectoryController` is `@ConditionalOnProperty(us019)`, with `@RequiresPermission(USER_DIRECTORY_READ)` on public, non-final handlers. It serves `GET /users` (list), `GET /users?ids=` (batch) and `GET /users/{userId}`. `DirectoryPageRequest` handles paging (default 20, max 100, 400 rather than clamp) and rejects with 400 when `page × size > 10,000`, when `status` is not an enum value, when `ids` has 1–100 canonical UUIDs combined with another filter, and when `email` is present ("use POST /api/v1/users/lookup").
- **Service and port.** `UserDirectoryService` uses `@Transactional(readOnly = true)`. `UserDirectoryQueryPort` and `JpaUserDirectoryQueryAdapter` decrypt `email_cipher` and never map the HMAC, the hash, the counters or `locked_until`. Every query is tenant-scoped (TenantIsolation naming).
- **Cross-tenant handling.**
  - By id: `existsById` runs on every miss; a cross-tenant id gives WARN `IDENTITY_DIRECTORY_CROSS_TENANT_TARGET {operation=GET}` and the counter.
  - Batch (RC-61.2): `countByIdIn` is unscoped and count-only, with an `UNSCOPED_ALLOWLIST` entry and an ArchUnit rule confining its callers to the adapter. A batch that omits foreign ids gives the same WARN with `operation=BATCH, omittedCount`.
- **Envelope.** Identity-local paging types plus `DirectoryPage<T>`. `PagingEnvelopeShapeTest` pins the JSON key structure against the RBAC envelope. Links echo `status` and never an email.
- **Flag wiring.** `true` in `application-dev.yml` and `application-test.yml`; `false` in `application.yml`; the prod file is unchanged.

**ACs covered:** B1 (list, by-id, field set, isolation, flag-off); B2.
**Dependencies:** T-001.
**Files impacted:**
- `BE/identity/infrastructure/persistence/JpaUserRepository.java`
- `RES/application.yml`, `RES/application-dev.yml`, `RES/application-test.yml`
- `BT/architecture/TenantIsolationArchitectureTest.java`, `BT/architecture/HexagonalArchitectureTest.java`, `BT/config/EndpointClassificationWebTest.java`

**Files created:**
- `BE/identity/interfaces/rest/UserDirectoryController.java`, `DirectoryPageRequest.java`, `DirectoryPageMetadata.java`, `DirectoryPageLinks.java`
- `BE/identity/interfaces/rest/dto/UserDirectoryEntryResponse.java`, `UserDirectoryPageResponse.java`
- `BE/identity/application/UserDirectoryService.java`, `BE/identity/application/port/out/UserDirectoryQueryPort.java`
- `BE/identity/domain/DirectoryUserView.java`, `BE/identity/domain/DirectoryPage.java`
- `BE/identity/infrastructure/persistence/JpaUserDirectoryQueryAdapter.java`
- tests `UserDirectoryIT`, `UserDirectoryFeatureFlagTest`, `DirectoryPageRequestTest`, `PagingEnvelopeShapeTest`, `UserDirectoryServiceTest`

**Complexity:** L.
**Risks:**
- **Authorization / tenant isolation:** an inherited unscoped `findById` used for a user-facing read is a cross-tenant leak. The unscoped `countByIdIn` must never feed the response; Security's sign-off depends on all three conditions.
- **Cryptography:** decryption failures must give 500 with no partial page. The HMAC must never leave the adapter.
- **Routing:** `/users/me` precedence over `/{userId}` (AS-4).

**Tests (written first):**
- `UserDirectoryIT` (two tenants):
  - the list returns only the caller's tenant, and DISABLED users are listed;
  - the JSON key set equals exactly the five names;
  - by id, cross-tenant equals missing (bytes, with `traceId` and `instance` normalised);
  - `size=101`, 101 ids, `?email=` and `page × size > 10,000` give 400;
  - a batch with a foreign id gives the BATCH WARN and an unchanged response;
  - a tampered cipher gives 500;
  - `EXPLAIN` uses `idx_users_tenant_id_status` for a status filter;
  - `Cache-Control: no-store` is not overridden.
- `UserDirectoryFeatureFlagTest`: 404 `RESOURCE_NOT_FOUND` on every route with the flag off.
- `EndpointClassificationWebTest`: us019 on; the handlers are classified; `GET /users/me` still reaches `UserProfileController`.
- ArchUnit: the containment rule for `countByIdIn`, with a negative fixture.
- Units: `DirectoryPageRequestTest` (bounds, `ids` parsing, combination rules) and `PagingEnvelopeShapeTest`.

**DoD:** gates green, including `./mvnw verify` with Docker. S1c merge checklist. One commit.

### T-005 — A directory reader can look up one user by exact email in a POST body, throttled per actor, and a miss looks exactly like a foreign hit

**Description** (design §4.3, §4.4, §4.5):
- `POST /users/lookup` takes `UserLookupRequest {email}` (`@NotBlank`, `@Size(max = 320)`, well-formed) and requires `application/json`.
- The body is capped at **1 KiB** from `Content-Length`, or by a bounded read, before parsing (RC-59.3).
- The email is normalised and hashed only through `EmailBlindIndexService.blindIndex`. The query is `findByTenantAndEmailHmac`. The response is `{data: [entry]}` or `{data: []}`.
- Throttle: bucket `DIR_LOOKUP:{tenantId}:{actorUserId}`, 30 per 60 s, on `RateLimitStore`, failing open. A rejection is `UserDirectoryThrottledException` (`USER_DIR_001`, `selfReported`), giving 429 with `Retry-After`. The service emits at most one WARN `IDENTITY_DIRECTORY_THROTTLED` per window.
- Config keys `nexus.identity.directory.lookup.*`.

**ACs covered:** B1 (exact-email lookup, indistinguishable miss, no prefix search; the transport departs from the story by Gate 2 decision 4); NF-S5 throttle.
**Dependencies:** T-003 (body handlers, `selfReported`), T-004.
**Files impacted:** `BE/identity/application/UserDirectoryService.java`, `BE/identity/interfaces/rest/UserDirectoryController.java`, `RES/application.yml`.
**Files created:**
- `BE/identity/interfaces/rest/dto/UserLookupRequest.java`, `UserLookupResponse.java`
- `BE/identity/domain/UserDirectoryThrottledException.java`
- tests `UserDirectoryLookupThrottleIT`, lookup cases in `UserDirectoryIT` and `UserDirectoryServiceTest`

**Complexity:** M.
**Risks:**
- **Cryptography/PII:** the blind index must never be re-implemented, logged or stored (ADR-0006). The email must never enter a URL, a validation message or a log.
- **Timing:** both branches run the same HMAC, the same probe and the same audit. The hit branch adds one decryption, which is stated, not hidden.

**Tests (written first):**
- `UserDirectoryIT`: hit, miss and other-tenant hit (the last two byte-identical); case, whitespace and NFC variants all hit; blank, 321 characters, malformed and a body over 1 KiB give 400; `text/plain` gives 415.
- `UserDirectoryLookupThrottleIT`: the 31st lookup gives 429 with `Retry-After` ≥ 1; one WARN per window.
- Unit: the throttle is consulted before the blind index.

**DoD:** gates green, including Docker. One commit.

### T-006 — Every directory read is audited without PII, bounded by a per-actor ceiling, measured, and proven absent from logs

**Description** (design §4.5, §4.7, §17; RC-61.1 data, RC-61.3, RC-63(c)):
- **Audit.** New `AuthEventType.USER_DIRECTORY_READ`, written through the existing best-effort `SecureEventService.recordEvent` (`REQUIRES_NEW`) on all four operations. Metadata: `operation`, `resultCount`, `statusFilter`, and for lookups `outcome` plus `resolvedUserId` on a hit. Never the email, the blind index or the id list. A write failure increments `nexus.identity.directory.audit_write_failed` and does not fail the read. A throttled lookup writes no row.
- **Ceiling.** Bucket `DIR_ALL:{tenantId}:{actorUserId}`, 600 per 60 s, on all four operations. A rejection is `USER_DIR_002` (429, `Retry-After`, `selfReported`), with one WARN per window.
- **Metrics and logs.** The `nexus.identity.directory.*` metrics (no tenant, user or email tags). INFO `IDENTITY_DIRECTORY_READ` carries `resultCount`, and `requestedCount`/`returnedCount` for batches. These are the inputs to the row-volume alert (the alert rule itself is `monitoring.md`).
- To stay within four collaborators, metrics are recorded on the controller side, or a small `DirectoryAccessGuard` holds the two buckets.

**ACs covered:** B1 ("logs carry actor id and tenant id, never the email"); NF-S5 and NF-O1–NF-O3; NF-P1.
**Dependencies:** T-005.
**Files impacted:** `BE/identity/domain/AuthEventType.java`, `BE/identity/application/UserDirectoryService.java`, `BE/identity/interfaces/rest/UserDirectoryController.java`, `RES/application.yml`.
**Files created:** the audit adapter or port for directory reads in `BE/identity/application/port/out/` *(name at planning)*; tests `UserDirectoryCeilingIT`, `UserDirectoryLogScanIT`.
**Complexity:** M.
**Risks:**
- **PII:** audit metadata is a long-lived store, so the email or HMAC must never appear in it.
- **Capacity:** each request holds two pooled connections (`REQUIRES_NEW`), bounded by the ceiling.

**Tests (written first):**
- `UserDirectoryServiceTest`: an `ArgumentCaptor` asserts the exact metadata key set, with no email.
- `UserDirectoryCeilingIT`: the 601st request gives 429 `USER_DIR_002`; one WARN per window.
- **`UserDirectoryLogScanIT`** (`OutputCaptureExtension`, Docker):
  - a lookup with a sentinel email, a list and a by-id read;
  - the RC-59.2 bodies `{"email": <unquoted sentinel>}`, `{"email": ["<sentinel>"]}`, a truncated body, `text/plain`, and a body over 1 KiB, each giving 400 or 415;
  - the captured output contains no sentinel, local part, blind index or seeded email.
- An audit write failure still gives 200 and increments the counter.

**DoD:** gates green, including Docker. S1c merge checklist. One commit.

### T-007 — Only an administrator can grant `user:directory:read`, and any non-administrator grant that succeeds is flagged

**Description** (design §4.8; RC-60.2, RC-60.3, RC-66.1, RC-66.2, RC-66.4):
- **Scope of the rule.** The rule fires when a request would grant the permission, matched by its seeded id:
  - `attachPermission` of the id;
  - `assign` of a role whose M14 ids contain it.
  It requires `RbacAdministrators.isAdministrator` from M13 and runs **after** A2/A3.
- **Denial posture.** A denial is 403 `RBAC_001` `NOT_TENANT_ADMIN` (wire value `ADMINISTRATOR_REQUIRED` once T-017 lands) with WARN `RBAC_PII_PERMISSION_GRANT_DENIED`. On attach there is no audit row. On assign, the assign posture applies: a `ROLE_ASSIGNMENT_DENIED` row and throttle accounting.
- **Switch.** `nexus.rbac.pii-grant-requires-administrator` (default `true`). With `false`, startup logs WARN `RBAC_PII_GRANT_RULE_DISABLED`, and a prod-profile test pins `true`.
- **Detective, always on.** After commit, a grant by a non-administrator gives WARN `RBAC_PII_PERMISSION_DELEGATED {tenantId, actorUserId, roleId, targetUserId|null}` and `nexus.rbac.pii_permission_delegated`.
- The rule is exposed as one package-private helper that T-019 reuses for B8.

**ACs covered:** D5 input (RES-51); A2/A3 semantics preserved.
**Dependencies:** T-001.
**Files impacted:**
- `BE/rbac/application/RoleManagementService.java`, `BE/rbac/application/RoleAssignmentService.java`
- `RES/application.yml`, `RES/application-prod.yml`
- `BT/rbac/application/RoleManagementServiceTest.java`, `BT/rbac/application/RoleAssignmentServiceTest.java`

**Files created:** `BT/rbac/PiiPermissionGrantIT.java`.
**Complexity:** M.
**Risks:**
- **Authorization:** evaluating the rule before A2/A3 leaks a named-permission composition bit (T-E54). Mockito's unstubbed M13 must mean deny. This changes shipped, unflagged us012/us015 verbs.
- **Audit posture:** assign must write exactly one denial row.

**Tests (written first):**
- A non-administrator holder attaching the permission, or assigning a role that carries it, gets 403 `ADMINISTRATOR_REQUIRED`.
- A non-holder gets `GRANT_EXCEEDS_CALLER`, never `ADMINISTRATOR_REQUIRED`.
- An assign denial writes one `ROLE_ASSIGNMENT_DENIED` row and counts towards the throttle.
- With the switch `false`: the startup WARN is logged, the grants succeed, and the delegated WARN and counter fire exactly once.
- The `prod` profile resolves `true`.
- An administrator's grant emits nothing.

**DoD:** gates green, including Docker. S1c merge checklist (D5 rules on the default; see A-4). One commit.

---

# S1d — B4

### T-008 — A signed-in user can read their own live roles, permissions and administrator status

**Description** (design §6):
- `CallerAuthorizationController` (`rbac`, us019, `@AuthenticatedEndpoint`). Its only parameter is `Authentication`, and it uses `RbacControllerSupport.resolveActor`.
- `CallerAuthorizationService` is `@Transactional(readOnly = true)` and makes four live reads in one snapshot:
  - a new `UserRoleQueryPort.findActiveRoles(userId, tenantId)` returning `RoleRef(roleId, name)`;
  - the existing `findActivePermissionNames`;
  - `RoleAssignmentService.isCallerAdministrator`, which is reused and not copied.
- No cache, no JWT claims, no audit, no throttle. Metric `nexus.rbac.caller_authorization.reads{isAdministrator}`.

**ACs covered:** B4.
**Dependencies:** T-004 (introduces the us019 flag keys).
**Files impacted:**
- `BE/rbac/application/port/out/UserRoleQueryPort.java`, `BE/rbac/infrastructure/persistence/JpaUserRoleRepository.java`, the `UserRoleQueryPort` adapter *(locate)*
- `BT/config/EndpointClassificationWebTest.java`, `BT/architecture/HexagonalArchitectureTest.java`

**Files created:**
- `BE/rbac/interfaces/rest/CallerAuthorizationController.java`, `BE/rbac/application/CallerAuthorizationService.java`
- `BE/rbac/interfaces/rest/dto/CallerAuthorizationResponse.java`, `BE/rbac/domain/RoleRef.java`
- tests `CallerAuthorizationIT`, `CallerAuthorizationServiceTest`, `CallerAuthorizationFeatureFlagTest`

**Complexity:** M.
**Risks:**
- **Authorization:** re-implementing the administrator predicate, or reading the cache or JWT, misguides every UI affordance (R7). Any bindable identifier is an IDOR (T-S13).

**Tests (written first):**
- `CallerAuthorizationIT`:
  - revoke a role, then call with the old token: the role and its permissions are gone;
  - a full-catalogue custom role gives `true`;
  - a union-holder (two partial roles) gives `false`;
  - a soft-deleted role is absent;
  - another tenant's data never appears;
  - zero roles give the empty shape.
- `CallerAuthorizationServiceTest`: the predicate is called with M13 and M15, and no cache port is a collaborator.
- ArchUnit rules green.
- Flag test: 404 `RESOURCE_NOT_FOUND` with the flag off.

**DoD:** gates green, including Docker. One commit.

---

# S2 — Frontend foundations

### T-009 — The production Angular graph is free of known high/critical advisories, and lint forbids HTML sinks and Material imports outside `shared/ui`

**Description** (design §12.4; RC-62.1, RC-62.3; Q-D24):
- Upgrade `@angular/*` to ≥ 22.2.0. `npm audit --omit=dev` must report no high or critical finding.
- ESLint `no-restricted-syntax` bans `[innerHTML]`, `[outerHTML]`, `bypassSecurityTrust*` and `nativeElement.innerHTML` in `src/app/**`, with an empty allow-list.
- ESLint `no-restricted-imports` forbids `@angular/material/*` and `@angular/cdk/*` outside `src/app/shared/ui/**` (ADR-0004).
- `axe-core` becomes an explicit devDependency, pinned to the version `@axe-core/playwright` resolves. A new helper `shared/testing/axe.ts` exports `expectNoAxeViolations`, which uses the WCAG 2.0, 2.1 and 2.2 A/AA tags, fails on critical or serious violations, and disables `color-contrast` in jsdom.

**ACs covered:** A3 (Material import boundary; the axe mechanism, closing G8); NF-X1.
**Dependencies:** none.
**Files impacted:** `nexus-frontend/package.json`, `package-lock.json`, the ESLint flat config *(locate)*, and any spec that breaks on the upgrade.
**Files created:** `FE/shared/testing/axe.ts` plus its spec, and lint fixture files that prove each rule fires.
**Complexity:** M (a risk-isolating slice: an upgrade touches the whole SPA).
**Risks:**
- **Supply chain (A06):** this is the merge precondition for every directive (TM §9.2 S2c).
- **Licence:** `axe-core` is MPL-2.0 (AS-9); verify at the licence check.

**Tests (written first):** a lint fixture with `[innerHTML]` and one importing Material from a feature both fail `npm run lint`; the axe helper fails a fixture with an unlabelled button.

**DoD:** frontend gates and `npm run build` green; `npm audit --omit=dev` output attached to the PR. RC-62.2 recorded by the Frontend Tech Lead (human). One commit.

### T-010 — Signed-in pages render inside a shell with header, permission-filtered nav, user menu, skip link and landmarks; public pages keep today's header

**Description** (design §12.1, §12.3; A-1):
- **Routing.** `app.html` becomes an outlet only. `PublicLayout` wraps `auth`, `access-denied` and `design-system`. A lazy `Shell` at `''` carries `authGuard` and holds the redirect from `''`, `dashboard` and the future console routes.
- **Shell components.** `ShellHeader`, `PrimaryNav`, `ThemeToggle` (extracted) and `nav.config.ts` (`NavItem`, `NAV_ITEMS`).
- **Responsibilities moved to the shell.** It owns the `/v1/users/me` priming `httpResource` and logout, both moved from the dashboard. The dashboard root becomes a `<section data-testid="dashboard-root">`.
- **Layout behaviour.** Below 960 px the nav collapses through CSS and the menu button. The skip link focuses `#main-content`.
- **`nx-menu` wrapper** (built here; see A-1), with its spec, preview card and axe test.
- **e2e updates in the same commit:** `logout.spec.ts` and `session-refresh.spec.ts` gain an "open user menu" step.

**ACs covered:** A2; supports A1, A7 and RES-39.
**Dependencies:** T-009.
**Files impacted:**
- `FE/app.html`, `FE/app.ts`, `FE/app.routes.ts`, `FE/app.spec.ts`, `FE/app.routes.spec.ts`
- `FE/features/dashboard/dashboard.component.ts`, `FE/features/dashboard/dashboard.component.spec.ts`
- `FE/shared/ui/index.ts`, the design-system preview *(locate)*
- `E2E/auth/logout.spec.ts`, `E2E/auth/session-refresh.spec.ts`

**Files created:**
- `FE/core/layout/shell/shell.ts`, `FE/core/layout/shell-header/shell-header.ts`, `FE/core/layout/primary-nav/primary-nav.ts`, `FE/core/layout/theme-toggle/theme-toggle.ts`, `FE/core/layout/public-layout/public-layout.ts`, `FE/core/layout/nav.config.ts`, each with its spec
- `FE/shared/ui/menu/menu.ts` with its `.scss` and spec

**Complexity:** L.
**Risks:**
- **Authorization (UX only):** a nav item whose `permission` differs from its route's `data.permission` misleads the user. `nav.config.spec.ts` pins that. The server stays authoritative (NF-S4).
- **Regression:** test ids and the access-denied route must stay outside the shell and unguarded.

**Tests (written first):**
- `shell.spec.ts`: nav filtered by `AuthStore.permissions()`; exactly one `header`, `nav` and `main`; the skip link moves focus without router navigation; the menu button's `aria-expanded`.
- `nav.config.spec.ts`: every path resolves, and every `permission` equals the route's `data.permission`.
- `app.routes.spec.ts`: the public children come before the shell; `/` redirects to `/dashboard`.
- `menu.spec.ts`: inputs, outputs, arrow keys, the icon trigger's `aria-label`, and axe.
- `public-layout.spec.ts`: the header renders on `auth` routes.

**DoD:** frontend gates, `npm run build` within budgets (shell lazy), and the existing `e2e/access-denied.spec.ts` unchanged. One commit.

### T-011 — Deep links and reloads land entitled users on guarded routes after exactly one refresh, and guard composition is enforced by spec

**Description** (design §12.2):
- The `permission.guard.ts` doc comment is rewritten (concurrent within one array, sequential across levels; a real `Permission` in the example). The guard code is unchanged.
- `permission-guard-contract.spec.ts`: `checkGuardArray` rejects any array containing both guards; a new walk requires an `authGuard` ancestor for every `permissionGuard`; cases `:175` and `:267-287` are rewritten to the ancestor shape.
- New real-Router `cold-start-routing.spec.ts`.

**ACs covered:** A1 (constraint R5).
**Dependencies:** T-010.
**Files impacted:** `FE/core/guards/permission.guard.ts`, `FE/core/guards/permission-guard-contract.spec.ts`.
**Files created:** `FE/core/routing/cold-start-routing.spec.ts`.
**Complexity:** S (mostly test; the production change is documentation plus route shape).
**Risks:**
- **Authorization (UX):** the four `permission.guard.spec.ts` fail-open tests (RES-39) must stay unmodified.
- **Session:** a second `POST /refresh` revokes the family (R5).

**Tests (written first):** with `provideRouter`, the real shell route, a `role:read` test child and the refresh answered after 500 ms of fake time:
- an entitled user lands on the route;
- an unentitled user lands on `/access-denied`;
- a failed refresh lands on `/auth/login?returnUrl=…`;
- exactly one `POST /refresh` is sent, including the shell's priming request.

**DoD:** frontend gates. One commit.

### T-012 — Forms and selection wrappers: tri-state checkbox, search field and chip, accessible and token-only

**Description** (design §12.4):
- `nx-checkbox` (CVA, `indeterminate` → `aria-checked="mixed"`, `disabledReason` through `disabledInteractive` and `aria-describedby`).
- `nx-search-field` (CVA, `mode: 'debounced' | 'submit'`, 300 ms, trimmed and distinct `search`, Escape clears, `role="search"`).
- `nx-chip` (removable, `aria-label="Remove {label}"`).
- Each has a barrel export, a preview card, tokens only, and `data-testid`.

**ACs covered:** A3 (three of nine); NF-X3, NF-X4.
**Dependencies:** T-009.
**Files impacted:** `FE/shared/ui/index.ts`, the design-system preview *(locate)*.
**Files created:** `FE/shared/ui/checkbox/*`, `FE/shared/ui/search-field/*`, `FE/shared/ui/chip/*`, each with `.ts`, `.scss` and `.spec.ts`.
**Complexity:** M.
**Risks:** none named (mechanical wrappers); styles must stay within 4 kB.
**Tests (written first):** per component: `writeValue` and `setDisabledState` for the CVAs; all three checkbox states; the search field's debounce and submit modes; clear and Escape; `removed` emitted; `expectNoAxeViolations`.
**DoD:** frontend gates and build. One commit.

### T-013 — Navigation and structure wrappers: routable tabs, breadcrumb, page header, tooltip and skeleton

**Description** (design §12.4):
- `nx-tabs` (`MatTabNav`, `routerLinkActive`, required `ariaLabel`).
- `nx-breadcrumb` (`nav aria-label="Breadcrumb"`, the last item `aria-current="page"`).
- `nx-page-header` (renders the single `h1` with `tabindex="-1"`; slots).
- `[nxTooltip]` (supplementary only; shown on keyboard focus).
- `nx-skeleton` (`aria-hidden`, no shimmer under `prefers-reduced-motion`).

**ACs covered:** A3 (five of nine); NF-X2.
**Dependencies:** T-009.
**Files impacted:** `FE/shared/ui/index.ts`, the preview.
**Files created:** `FE/shared/ui/tabs/*`, `breadcrumb/*`, `page-header/*`, `tooltip/*`, `skeleton/*`.
**Complexity:** M.
**Risks:** none named. The tooltip must never carry a disabled reason on its own (NF-X3).
**Tests (written first):** inputs and outputs per component; the active tab follows the route; reduced motion; axe on each.
**DoD:** frontend gates and build. One commit.

### T-014 — Typed-confirmation dialog, polite announcer, and a table with custom cells, sticky header and caption

**Description** (design §12.4):
- `NxDialog.confirmTyped(TypedConfirmData)`: danger variant, labelled input, confirm `aria-disabled` until the trimmed value equals `expectedText`, initial focus on the input.
- `NxAnnouncer` (CDK `LiveAnnouncer`, polite by default).
- `NxTable` (A4): `stickyHeader`, `caption`, `captionVisuallyHidden`, `CellType 'custom'`, and an `nxTableCell` template directive (`NxTableCellDef`). The sticky header uses `scroll-padding-top` (WCAG 2.4.11).
- `e2e/design-system.a11y.spec.ts`: axe on `/design-system` in light and dark mode for contrast.
- PR template: manual WCAG 2.2 checklist (2.4.11, 2.5.8).

**ACs covered:** A3 (dialog variant, announcer); A4; NF-X1 (contrast in both themes).
**Dependencies:** T-009, T-012, T-013 (the preview page shows every wrapper for the contrast run).
**Files impacted:** `FE/shared/ui/dialog/dialog.ts` and its spec, `FE/shared/ui/table/table.ts` and its spec, `FE/shared/ui/index.ts`, the preview, the PR template *(locate)*.
**Files created:** `FE/shared/ui/announcer/*`, `E2E/design-system.a11y.spec.ts`.
**Complexity:** M.
**Risks:** none named. Existing `NxTable` inputs and outputs are unchanged (its only consumer is the preview).
**Tests (written first):**
- confirm disabled until an exact match, and trimmed;
- the announcer's politeness;
- custom cell templates render; the caption is present; the sticky class applies; existing table specs unchanged;
- the Playwright contrast run in both schemes.

**DoD:** frontend gates and build. One commit.

### T-015 — Every permission has a readable label and group, a backend catalogue change without a label fails a test, and the 403 redirect opt-out is proven both ways

**Description** (design §12.5, §12.6):
- `PERMISSION_LABELS` (`Record<Permission, string>`; the copy uses the backend descriptions as placeholders until D3).
- `PermissionResource`, `permissionResource(p)` (the segment before the first `:`) and `PERMISSION_GROUP_LABELS`.
- A hand-committed `contracts/api/permission-catalogue.json`, which T-028 later takes over.
- `api-error.interceptor.spec.ts` gains whichever A6 branch is missing.

**ACs covered:** A5; A6.
**Dependencies:** T-001 (permission name).
**Files impacted:** `FE/shared/types/permission.ts`, `FE/core/http/api-error.interceptor.spec.ts`.
**Files created:** `contracts/api/permission-catalogue.json`, `FE/shared/types/permission-catalogue.spec.ts`.
**Complexity:** S.
**Risks:** none named.
**Tests (written first):**
- every fixture name is in `PERMISSIONS` with a label and a group, and the reverse;
- `user:role:assign` and `user:directory:read` group under `user`;
- an `RBAC_001` without the token navigates to `/access-denied` with no query params, and with the token it does not navigate.

**DoD:** frontend gates. One commit.

---

# S3a — B6

### T-016 — Role responses carry member and permission counts, computed with two grouped queries per page

**Description** (design §8):
- `RoleResponse` gains `long memberCount` and `int permissionCount`.
- New projection `rbac.domain.RoleCounts`.
- `RoleManagementPort` gains `countActiveHoldersByRole` and `countPermissionsByRole`. Each is one `GROUP BY role_id` statement with `IN (:pageIds)` and a tenant predicate; the second joins `roles`, which is a code-review checklist item.
- The list, B3 and PATCH producers query; create returns 0 and 0 with no statement.

**ACs covered:** B6 (NF-F2).
**Dependencies:** T-002 (B3 producer).
**Files impacted:**
- `BE/rbac/interfaces/rest/dto/RoleResponse.java`, `BE/rbac/interfaces/rest/RoleController.java`, `BE/rbac/application/RoleManagementService.java`
- `BE/rbac/application/port/out/RoleManagementPort.java`, `BE/rbac/infrastructure/persistence/JpaRoleManagementAdapter.java`, `BE/rbac/infrastructure/persistence/JpaRoleRepository.java`, `BE/rbac/infrastructure/persistence/JpaUserRoleRepository.java`
- `BT/rbac/interfaces/rest/RoleControllerTest.java`

**Files created:** `BE/rbac/domain/RoleCounts.java`, `BT/rbac/RoleCountsIT.java`.
**Complexity:** M.
**Risks:**
- **Tenant isolation:** the `role_permissions` count is not policed by ArchUnit (it has no `tenantId`).
- **Disclosure:** single-holder admin-defining roles are visible (RES-48, D5).

**Tests (written first):** `RoleCountsIT`, using Hibernate statistics:
- exactly two count statements for a 100-role page;
- revoked assignments excluded;
- a soft-deleted role's assignments not counted;
- tenant isolation;
- `RoleControllerTest` covers all four producers' shapes.

**DoD:** gates green, including Docker. No new flag. One commit.

---

# S3b — B7

### T-017 — Denials explain allow-listed in-tenant reasons, throttled role changes return 429 with `Retry-After`, and the SPA surfaces both without auto-retry

**Description** (design §9, §12.10; A-5):
- **Wire reason.** `common.security.CallerFacingDenialReason` maps every `DenialReason`. `handleInsufficientPermission` always writes `reason`. Only `RBAC_001` carries it; `ACCESS_DENIED` never does (RC-63(l)).
- **Throttle status.** `RoleChangeThrottlePort.throttleStatus` returns `ThrottleStatus(throttled, retryAfterSeconds)` and replaces `isThrottled`. The Redis adapter reads it with `PTTL` and the memory adapter from its map; both fail safe.
- **429.** `evaluateThrottle` throws `RoleChangeThrottledException` (`RBAC_011`, `selfReported`), giving 429 with `Retry-After`. Still no audit row, and `denial_throttled` still counts.
- **Frontend.** `AppError` gains `reason?` and `retryAfterSeconds?`, filled by `api-error.interceptor`. `RBAC_011` is never auto-retried. A new `ServiceAvailabilityNotifier` shows one toast per `Retry-After` window for 503 `AUTH_005` and never navigates.

**ACs covered:** B7; supports A9 (the page never shows `reason`).
**Dependencies:** T-003 (`selfReported`). Serialise the merge with T-018 (`GlobalExceptionHandler`).
**Files impacted:**
- `BE/common/web/GlobalExceptionHandler.java`, `BE/common/security/DenialReason.java` (read only)
- `BE/rbac/application/port/out/RoleChangeThrottlePort.java`, `BE/rbac/infrastructure/cache/RedisRoleChangeThrottleAdapter.java`, `BE/identity/infrastructure/security/RateLimitRoleChangeThrottleAdapter.java`, `BE/rbac/application/RoleAssignmentService.java`
- `BT/common/web/GlobalExceptionHandlerTest.java`, `BT/rbac/application/RoleAssignmentServiceTest.java`, `BT/rbac/infrastructure/cache/RedisRoleChangeThrottleAdapterIT.java`, the existing throttle ITs (`grep -l isThrottled nexus-backend/src/test`) *(locate)*
- `FE/core/http/api-error.interceptor.ts` and its spec; the `AppError` type *(locate)*

**Files created:**
- `BE/common/security/CallerFacingDenialReason.java`
- `BE/rbac/application/port/out/ThrottleStatus.java`, `BE/rbac/domain/RoleChangeThrottledException.java`
- `BT/common/security/CallerFacingDenialReasonTest.java`
- `FE/core/http/service-availability-notifier.ts` and its spec

**Complexity:** M.
**Risks:**
- **Authorization disclosure:** the `GRANT_EXCEEDS_CALLER` and `ADMINISTRATOR_REQUIRED` bits and the explicit 429 bit (RES-47, accepted at Gate 2). Opaque cases must map to `UNSPECIFIED`.
- **Fail-safe:** the throttle port must never throw, and an unavailable store must never permit.
- **Unflagged:** this is live on deploy.

**Tests (written first):**
- `CallerFacingDenialReasonTest`: exhaustive over `DenialReason.values()`.
- `GlobalExceptionHandlerTest`:
  - `reason` per mapping and always present;
  - `requiredPermission` unchanged;
  - `ACCESS_DENIED` has no `reason` key;
  - a malformed principal and a missing tenant give `UNSPECIFIED`.
- Throttled admin-defining or self target: 429 `RBAC_011` with `Retry-After` in `[1, window]`, no audit row, counter incremented, at most one WARN per window.
- `RedisRoleChangeThrottleAdapterIT`: `PTTL` path, including Redis down (fail safe). Memory adapter unit test.
- Frontend: `RBAC_011` maps to an `AppError` with `retryAfterSeconds` and is not retried. Two 503s within the window give one toast and no navigation.

**DoD:** backend gates including Docker; frontend gates. S3b checklist. One commit.

---

# S3c — B8 and the US-018 verb changes

### T-018 — An editor can atomically replace a role's permission set with `If-Match`; stale writes get 412, and unauthorised callers learn nothing

**Description** (design §10.2, §10.3 steps 1–9 and 12–15 on the **role-row path**, §10.5–§10.7):
- **ETag.** `rbac.domain.RolePermissionSetVersion.of(roleId, ids)` (`"rp1-"` + base64url(SHA-256), unpadded). `ETag` is set on `GET /roles/{roleId}/permissions` (through `RolePermissionSet`) and on the PUT's 200.
- **Endpoint.** `PUT /roles/{roleId}/permissions`, `ReplaceRolePermissionsRequest` (`@NotNull`, `@Size(max = 100)`, canonical UUIDs, no duplicates). `IfMatchHeader.parse` accepts **exactly one strong tag** and raises 428 otherwise.
- **New exceptions.** `PreconditionFailedException` (412) and `PreconditionRequiredException` (428) in `common.domain`, with handlers. Their bodies carry no state.
- **Check order** (RC-58): 400, 428, 404 role, 409 `RBAC_003`, 404 permission, then **403** (L-1 live `role:write` **and** live `role:read`, A3 on adds, role-subset on removes), then 412 against `v0`, then the authorised no-op 200.
- **Locks.** `lockRoleRow` (`SELECT … FOR UPDATE`) and `lockPermissionIdsForRole` (`FOR SHARE`). Step 9 is **`v1 == v0`, otherwise 412** (RC-55.1).
- **Writes.** A bulk detach with an affected-row assertion, then the attaches.
- **Audit.** Inline audit per change with `operation=REPLACE` and a server-generated `replaceId` (UUIDv7).
- **After commit.** Epoch bump or eviction once; INFO `RBAC_PERMISSION_SET_REPLACED`; metrics `nexus.rbac.permission_replace{outcome, lockPath}`; the lock-hold timer gains `operation="replace"`.
- **CORS.** `If-Match` is allowed and `ETag` exposed.
- **Interim scope.** This task implements only the role-row path. Until T-019 lands, a PUT whose `before` or `after` is admin-defining is refused (after authorization, before any lock) by a test-visible guard that T-019 removes. **T-018 and T-019 ship in one PR**, so the guard never reaches `main` (A-7, O-3).

**ACs covered:** B8 (all-or-nothing, grant-subset, no-op, audit, post-commit, ETag/`If-Match` per Gate 1 Q4, empty set, unknown id 404, bounds; closes G9).
**Dependencies:** T-003, T-002 (`isSensitive` in the response). Merge after T-017.
**Files impacted:**
- `BE/rbac/interfaces/rest/RoleController.java`, `BE/rbac/application/RoleManagementService.java`
- `BE/rbac/application/port/out/RoleManagementPort.java`, `BE/rbac/infrastructure/persistence/JpaRoleManagementAdapter.java`, `BE/rbac/infrastructure/persistence/JpaRoleRepository.java`
- `BE/common/web/GlobalExceptionHandler.java`, `BE/config/SecurityConfig.java`
- `BT/rbac/RolesPrivilegeIT.java`, `BT/rbac/RolePermissionsPrivilegeIT.java`, `BT/config/SecurityConfigWebTest.java`, `BT/rbac/application/RoleManagementServiceTest.java`, `BT/rbac/interfaces/rest/RoleControllerTest.java`

**Files created:**
- `BE/rbac/domain/RolePermissionSetVersion.java`, `BE/rbac/domain/RolePermissionSet.java`
- `BE/rbac/interfaces/rest/IfMatchHeader.java`, `BE/rbac/interfaces/rest/dto/ReplaceRolePermissionsRequest.java`
- `BE/common/domain/PreconditionFailedException.java`, `BE/common/domain/PreconditionRequiredException.java`
- tests `RolePermissionSetVersionTest`, `IfMatchHeaderTest`, `RolePermissionReplaceIT`, `RolePermissionReplaceConcurrencyIT`

**Complexity:** L.
**Risks:**
- **Locking/concurrency:** `FOR UPDATE` on `roles` under a column-scoped grant (AS-1), which must be proven **as `nexus_app`**, never as the superuser (the US-016 D5 trap). Lock order follows RC-46.
- **Authorization:** 403 must precede 412 and the no-op (the T-I20 oracle). Locks are taken only after authorization (T-D27).
- **Cryptography:** the hash is a concurrency validator, not a secret. It must be strong, order-independent and role-bound, and step 9 must compare against `v0` and never against the client tag (T-T22, High).

**Tests (written first):**
- Units:
  - `RolePermissionSetVersionTest`: order independence, role id included, stable vectors.
  - `IfMatchHeaderTest`: one strong tag accepted; two tags, `*`, weak-only, empty and garbage give 428.
  - `RoleManagementServiceTest`: a stub where the current version differs but was client-offered gives 412; one denial test per step; unstubbed M13 means deny.
- `RolePermissionReplaceIT`:
  - one item violating grant-subset gives 403 with no row change and no audit;
  - a no-op gives 200 with no audit and the Redis epoch key unchanged;
  - an empty set on a custom role succeeds;
  - an old ETag gives 412 and the body has no ETag, ids or count;
  - each 428 case;
  - **RC-58.3:** a `role:write` holder lacking one of R's permissions gets 403 for every removing combination, and a live-M13 caller without `role:write` or `role:read` gets 403 on a no-op;
  - an unknown id gives 404; a system role gives 409;
  - an audit failure gives 500 with no change;
  - the GET ETag equals the PUT ETag;
  - audit rows carry `replaceId`.
- `RolePermissionReplaceConcurrencyIT` (50 iterations, as `nexus_app`):
  - (a) the same `If-Match` twice gives one 200 and one 412;
  - (b) PUT ∥ attach in **both arrival orders**, with no 1213 outside RES-45 (RC-63(a));
  - (c) PUT ∥ detach;
  - (g) an attach commits between snapshot and lock, giving 412 with no change.
- Privilege ITs as `nexus_app`: `roles … FOR UPDATE` succeeds and a second connection blocks; `role_permissions … FOR SHARE` (single role and `IN (…)`); `SHOW GRANTS` unchanged. Fallback per design §10.4 if the first fails.
- `SecurityConfigWebTest`: both CORS lists.

**DoD:** gates including Docker. S3c checklist. One commit.

### T-019 — Replacing permissions on an admin-defining role, or making one, is serialised by the set lock and judged from current state, so it cannot strand the tenant without an administrator

**Description** (design §10.3 steps 8, 10, 11 and 14 on the **set-lock path**, §10.4; RC-57.1, RC-56 for B8, RC-60 for B8, RC-63(f)):
- **Lock order** by `before`. Admin-defining: set lock, then the role row. Promotion: the role row, then the set lock. `acquireSetLockBeforeRoleRow` is refactored to return the locked holders, and a new `lockRolePermissionsForRoles(lockedRoleIds)` (`FOR SHARE`) is added on `UserRoleAssignmentPort`.
- **Step 10.** Re-derive the currently admin-defining locked roles. On demotion, require a locked row of another role that is admin-defining **now**.
- **Step 11.** `RBAC_010` provenance on promotion, against the current set.
- **PII rule.** The T-007 helper applies when `adds` contains `user:directory:read`, after A3.
- **Demotion signal.** WARN `RBAC_ROLE_CEASED_ADMIN_DEFINING {tenantId, roleId, holderCount}` and its counter.
- Removes T-018's interim guard.

**ACs covered:** B8 (provenance `RBAC_010`, set lock per Gate 1 Q5, the edge case "revoking the last admin concurrently with B8").
**Dependencies:** T-018, T-007.
**Files impacted:**
- `BE/rbac/application/RoleManagementService.java`, `BE/rbac/application/RoleAssignmentService.java` (shared set-lock helpers)
- `BE/rbac/application/port/out/UserRoleAssignmentPort.java`, `BE/rbac/infrastructure/persistence/JpaUserRoleAssignmentAdapter.java`, `BE/rbac/infrastructure/persistence/JpaUserRoleRepository.java`
- `BT/rbac/LastAdminLockoutIT.java` (harness C), `BT/rbac/RolePermissionReplaceConcurrencyIT.java`, `BT/rbac/RolePermissionsPrivilegeIT.java`, `BT/rbac/application/RoleManagementServiceTest.java`

**Files created:** none.
**Complexity:** L.
**Risks:**
- **Locking/concurrency:** deadlock if the order is not RC-46's. MC-A forbids locks on M13–M15 and M10' (new statements are new `lock…` methods).
- **Authorization:** the administrator answer must come from locked rows and a current read (T-E49). One actor sending two demotions must never reach zero administrators.

**Tests (written first):**
- `RolePermissionReplaceConcurrencyIT`:
  - (d) PUT promoting R ∥ softDelete R;
  - (e) PUT demoting R ∥ assign to R;
  - (f) PUT ∥ revoke of a holder of R.
- Harness C (`LastAdminLockoutIT`) re-run with a B8 demotion thread and a B8 promotion thread, plus **RC-57.4 (a):** two B8 demotions by one caller holding R and R2 give exactly one success, and zero administrators is never reached.
- `RolePermissionReplaceIT`:
  - a demotion by an administrator through another role succeeds and bumps holders once;
  - a promotion with a non-administrator-assigned holder gives 409 `RBAC_010`;
  - a B8 add of `user:directory:read` by a non-administrator holder gives 403 `ADMINISTRATOR_REQUIRED`;
  - a demotion emits the ceased WARN and counter.

**DoD:** gates including Docker, with no 1213 outside RES-45. One commit (same PR as T-018).

### T-020 — Attaches on one role queue instead of deadlocking, a queued assign or attach that the role outgrew retries with 409 `RBAC_012`, and a committed violation pages

**Description** (design §10.9; RC-56.2–56.4, RC-64, RC-66.3, RC-67(a)):
- **Attach.** Attach takes `lockRoleRow` **before** its INSERT (RC-64), then runs a post-insert current read of R's `role_permissions` (`FOR SHARE`). If it now completes the catalogue while the snapshot said it did not, it rolls back with `RoleClassificationChangedException` (409 `RBAC_012`, retryable; detail with no ids).
- **Assign** (non-admin-defining path). After the insert, the same current read. If R is now admin-defining, or R now carries `user:directory:read` and the caller is not an administrator while the rule is on (RC-66.3), it throws 409 `RBAC_012`, and the insert rolls back with no audit.
- **Counter.** `nexus.rbac.role_classification_changed{operation}`.
- **Committed-state detector**, in `readAfterCommit` after attach, B8 and assign: an admin-defining R with a holder whose `assigned_by` is not an administrator gives WARN `RBAC_ADMIN_DEFINING_ROLE_HAS_NON_ADMIN_ASSIGNED_HOLDER` and an untagged counter that **pages**.

**ACs covered:** B8 (provenance holds under concurrency; "attach/detach racing a replace").
**Dependencies:** T-018 (`lockRoleRow`), T-019 (the B8 call site for the detector).
**Files impacted:**
- `BE/rbac/application/RoleManagementService.java`, `BE/rbac/application/RoleAssignmentService.java`
- `BE/rbac/application/port/out/UserRoleAssignmentPort.java`, `BE/rbac/infrastructure/persistence/JpaUserRoleAssignmentAdapter.java`
- `BT/rbac/LastAdminLockoutIT.java`, `BT/rbac/application/RoleAssignmentServiceTest.java`, `BT/rbac/application/RoleManagementServiceTest.java`

**Files created:** `BE/rbac/domain/RoleClassificationChangedException.java`, `BT/rbac/AssignRoleContentionIT.java`, `BT/rbac/AttachSerialisationIT.java`.
**Complexity:** L.
**Risks:**
- **Locking/concurrency:** this changes shipped us012/us015 verbs, unflagged. Before RC-64, every attach pair deadlocked (T-D28). Assign holds S locks on the range until commit (T-D29).
- **Authorization:** `RBAC_010` bypass under concurrency (T-E48, RES-26).

**Tests (written first):**
- Units: a stubbed post-insert completion gives 409 `RBAC_012` and no audit call (assign and attach); the PII re-evaluation on assign; the detector fires on a forced state and stays silent for administrator-assigned holders.
- **RC-64 harness** (`AttachSerialisationIT`, as `nexus_app`, 50 iterations): two non-completing attaches both succeed, with no 1213.
- **RC-56.7** in harness C:
  - attach p ∥ attach q on a role two short with a non-administrator-assigned holder: exactly one completes, the other gets `RBAC_010` or `RBAC_012`;
  - B8 (+q) then a queued attach of p gives `RBAC_012`;
  - an assign queued behind a B8 promotion gives `RBAC_012`, and a non-administrator-assigned holder never ends up on an admin-defining R.
- **`AssignRoleContentionIT`** (RC-67(a), as `nexus_app`): assign ∥ attach, assign ∥ detach and assign ∥ B8 on the same R; no 1213; added wait < 50 ms p95 at dev volume.

**DoD:** gates including Docker. Ops RES-6 sign-off for the detector marker. One commit.

### T-021 — Revoke, role deletion and break-glass judge which roles are admin-defining from a current read under the set lock

**Description** (design §10.9, RC-57.2):
- After the set lock, `revoke` takes its administrator requirement (`requireAdministratorFromSetLock`) and its lockout (`wouldLeaveTenantWithoutAdministrator`) from the admin-defining set returned by `lockRolePermissionsForRoles(lockedRoleIds)`.
- `softDeleteRole`'s admin-defining path and the break-glass grant use the same current read.

**ACs covered:** B8 edge case (R4: no zero-administrator path through B8 followed by revoke).
**Dependencies:** T-019 (`lockRolePermissionsForRoles`).
**Files impacted:**
- `BE/rbac/application/RoleAssignmentService.java`, `BE/rbac/application/RoleManagementService.java`
- the break-glass grant service *(locate: grep `BreakGlass` under `BE/rbac`)*
- `BT/rbac/LastAdminLockoutIT.java`, `BT/rbac/application/RoleAssignmentServiceTest.java`

**Files created:** none.
**Complexity:** M.
**Risks:**
- **Locking/concurrency:** the new `FOR SHARE` must come after the requester's `user_roles` and `roles` locks.
- **Authorization:** the last-administrator lockout (RES-28 for these paths).

**Tests (written first):**
- **RC-57.4 (b):** a B8 demotion ∥ a revoke of the last other administrator; the lockout holds.
- `LastAdminLockoutIT` outcome scenarios unchanged.
- `BreakGlassAdminIT` unchanged *(locate)*.
- Unit: the revoke classification uses the locked current read and never M10'.

**DoD:** gates including Docker. One commit.

---

# S3d — B10

### T-022 — Every RBAC and directory operation documents its `ProblemDetail` errors, and an undocumented thrown code fails the build

**Description** (design §11.1):
- `common.web.ProblemResponses` / `ProblemResponse` annotations.
- `OpenApiConfig` registers the `ProblemDetail` schema (including `reason` and `requiredPermission`) and an `OperationCustomizer` that emits `application/problem+json` responses and `x-nexus-error-codes`.
- Prose `@ApiResponse`s on the touched controllers are replaced.
- OpenAPI text for B8's ETag (it validates the set; no 304) and for the lookup ("safe and read-only; POST keeps personal data out of URLs").

**ACs covered:** B10.
**Dependencies:** T-002, T-004 to T-008, T-016 to T-021.
**Files impacted:** `BE/config/OpenApiConfig.java`, `BE/rbac/interfaces/rest/RoleController.java`, `PermissionController.java`, the user-role and access-review controllers *(locate)*, `BE/identity/interfaces/rest/UserDirectoryController.java`, `BE/rbac/interfaces/rest/CallerAuthorizationController.java`.
**Files created:** `BE/common/web/ProblemResponse.java`, `ProblemResponses.java`, `BT/config/OpenApiErrorCatalogueTest.java`.
**Complexity:** M.
**Risks:** none named (documentation surface; springdoc is off in prod).
**Tests (written first):** `OpenApiErrorCatalogueTest` (test profile, all flags on, no Docker):
- every RBAC and directory 4xx/5xx response references `ProblemDetail`;
- every code literal in the `rbac` and directory sources (`RBAC_0\d\d`, `USER_DIR_\d{3}`, `*_NOT_FOUND`, `PRECONDITION_*`) is documented somewhere;
- a fixture with an undocumented code fails.

**DoD:** `./mvnw verify -DskipITs` green. One commit.

---

# S4a — C1

### T-023 — A fresh dev database contains every persona and a fixture-only second tenant, idempotently, and never under `prod`

**Description** (design §13.1, RC-63(g)):
- **Split.** `DevDataInitializer` keeps the all-or-nothing transaction and delegates to `DevUserSeeder` and `DevRbacSeeder` (≤ 4 collaborators each). All three use `@Profile("dev & !break-glass & !prod")`.
- **Personas** (bootstrap tenant): second administrator, member, Role Manager (`role:read`, `role:write`), User Manager (`user:read`, `user:role:assign`, `user:directory:read`), a locked user (`lockAccount(far future)`), and a pending user.
- **Second tenant.** A fixed dev tenant and user id, whose administrator holds a custom role built from `findAllPermissions`.
- **Assignments.** `assigned_by` is the seeded administrator, never self.
- **Logging.** WARN `DEV_SEED_ACTIVE {profiles}`; INFO `DEV_SEED_COMPLETED {created, skipped}`. The INFO that logs the email at `:100` is removed.

**ACs covered:** C1.
**Dependencies:** T-001; T-004 and T-008 (us019 on in `application-dev.yml`; personas exercise them).
**Files impacted:** `BE/identity/infrastructure/seed/DevDataInitializer.java`, `BT/identity/infrastructure/seed/DevDataInitializerTest.java`.
**Files created:** `BE/identity/infrastructure/seed/DevUserSeeder.java`, `DevRbacSeeder.java`, `BT/identity/infrastructure/seed/DevSeedProfileGuardTest.java`, `BT/identity/infrastructure/seed/DevPersonaSeedIT.java`.
**Complexity:** M.
**Risks:**
- **Authorization:** known-password administrators outside dev (T-E52). A self-referencing `assigned_by` mimics break-glass and trips `RBAC_010` in US-020's e2e.
- **PII:** no email or password in any log.

**Tests (written first):**
- `DevDataInitializerTest`: a re-run creates nothing; each persona has its roles; the admin role comes from `findAllPermissions`.
- `DevSeedProfileGuardTest`: `prod`, `dev,break-glass` and `dev,prod` contexts have no seeder beans.
- `DevPersonaSeedIT`:
  - every persona exists;
  - the second-tenant administrator is an administrator per `RbacAdministrators`;
  - the zero-admin indicator is green;
  - `assigned_by` is never self for personas;
  - the captured log has no seeded email.

**DoD:** gates including Docker. S4a checklist. One commit.

---

# S5a — A7–A10

### T-024 — Unknown URLs show Not Found inside the shell, every page sets "{title} · Nexus", and focus moves to the page heading after navigation

**Description** (design §12.7):
- `NotFoundComponent` uses `nx-page-header` and a "Go to dashboard" link, and sits at the shell's `**`.
- `NexusTitleStrategy`, provided in `app.config.ts`. Every route declares `title`.
- `route-focus.ts`, started with `provideAppInitializer`. After the first `NavigationEnd` it focuses the `h1` or `#main-content`, and skips routes with `data.selfManagedFocus` (set on `access-denied`).

**ACs covered:** A7; A8.
**Dependencies:** T-010, T-013 (`nx-page-header`).
**Files impacted:** `FE/app.routes.ts`, `FE/app.config.ts`, `FE/app.routes.spec.ts`.
**Files created:** `FE/shared/pages/not-found/not-found.component.ts` and its spec; `FE/core/routing/nexus-title-strategy.ts` and `route-focus.ts`, each with a spec.
**Complexity:** S.
**Risks:** none named. Access Denied's focus must not be double-handled.
**Tests (written first):**
- title formatting, including a route without a title;
- every route has a `title` (`app.routes.spec.ts`);
- focus moves to the `h1` on the second navigation, not the first;
- the self-managed route is skipped;
- an unknown URL renders Not Found within the shell (real Router).

**DoD:** frontend gates. One commit.

### T-025 — Access Denied shows the user's role names and an optional, scheme-checked contact link, and sign-in returns users only to a safe in-app URL

**Description** (design §12.8, §12.9; RC-63(i), RC-65):
- **Access Denied.** `AppConfig.supportContact` is nullable. A startup check accepts only `mailto:` or `https://`, and both environment files default it to `null`. The `TODO(PM)` mailto is removed. Role names come from `AuthStore` with the caption "as of when you signed in". The page makes no HTTP calls and never shows `requiredPermission` or `reason`.
- **Return URL.** `authGuard` adds `returnUrl` to the login redirect. `safeReturnUrl` is a pure function that does **no second decode**. `LoginFormComponent` navigates with it.
- **Route hygiene.** A spec pins `PublicLayout`'s children to exactly `{auth, access-denied, design-system}`. A spec asserts that no route declares `canActivateChild` with `authGuard` (RC-65 via the design's drop).

**ACs covered:** A9 (the contact value itself is Q-N5, human); A10; NF-S6.
**Dependencies:** T-010.
**Files impacted:**
- `FE/shared/pages/access-denied/access-denied.component.ts` and its spec
- `FE/core/config/app-config.ts`, `nexus-frontend/src/environments/*.ts` *(locate)*
- `FE/core/guards/auth.guard.ts` and its spec
- `FE/features/auth/login-form/login-form.component.ts` and its spec
- `FE/app.routes.spec.ts`

**Files created:** `FE/core/routing/safe-return-url.ts` and its spec.
**Complexity:** S.
**Risks:**
- **Authorization/security:** open redirect (R15, T-T25). A decode mismatch validates one string and navigates another. A `canActivateChild` guard would cause a refresh-reuse logout (T-S14).

**Tests (written first):**
- **Adversarial table**, all falling back to `/dashboard`: `//evil.example`, `/\evil.example`, `\\evil`, `https://evil.example`, `javascript:alert(1)`, `%2F%2Fevil.example`, `/%5Cevil`, `%252F%252Fevil.example`, `/auth/login?returnUrl=…`, `/dashboard\u0000`, `''` and `null`.
- `/dashboard?tab=x#y` is accepted unchanged.
- `supportContact` values `null`, `ftp:` and `javascript:` all hide the link.
- The access-denied component never shows `reason`.
- The `PublicLayout` pin and the no-`canActivateChild` spec.

**DoD:** frontend gates. S5a checklist. One commit.

---

# S4b–c — C2, C4

### T-026 — Playwright tests log in once per worker and persona against a real backend, check accessibility, and cover the shell end to end

**Description** (design §13.2):
- `e2e/fixtures/personas.ts`.
- `test.ts` with a worker-scoped `personaContext(key)`: API login through `context.request`, so the cookie jar follows rotation.
- `axe.ts` (`expectNoSeriousA11yViolations`).
- `backend.ts` (`requireBackend`, which throws when `E2E_REQUIRE_BACKEND=1`).
- `apiBase` from `E2E_API_BASE_URL`.
- New specs under `e2e/access-management/`:
  - nav entries per persona (story scenario 5);
  - skip link and landmarks;
  - axe on each persona's dashboard;
  - cold-start deep link (scenarios 1–3);
  - Not Found;
  - the `returnUrl` round trip.
- One page per persona context at a time.

**ACs covered:** C2 (per-worker API login replaces `storageState`, by Gate 2 decision 27); A1, A2, A7 and A10 end to end.
**Dependencies:** T-023, T-011, T-024, T-025.
**Files impacted:** `nexus-frontend/playwright.config.ts` *(locate)*.
**Files created:** `E2E/fixtures/personas.ts`, `test.ts`, `axe.ts`, `backend.ts`; `E2E/access-management/shell.spec.ts`, `cold-start.spec.ts`, `not-found.spec.ts`, `return-url.spec.ts`.
**Complexity:** M.
**Risks:**
- **Session:** a shared `storageState`, or two pages in one context, revoke the token family (RC-63(h)).
- **PII:** traces record request bodies.

**Tests (written first):** these are the specs above; each one fails on a deliberately broken route.

**DoD:** frontend gates; the suite passes locally against the compose backend with 0 skips. One commit.

### T-027 — CI runs the access-management e2e suite against the compose backend as `nexus_app`, fails on skips or leaked PII, and keeps artifacts ≤ 7 days

**Description** (design §13.4, RC-63(h)):
- **Workflow.** `.github/workflows/e2e-full-stack.yml` runs `on: pull_request` with `permissions: contents: read` and no secrets. Its path filters are `nexus-backend/**`, `nexus-frontend/**`, `contracts/**`, `docker-compose.yml` and the workflow itself.
- **Stack.** `docker-compose.yml` plus a CI-only `docker-compose.e2e.yml` bring up mysql, redis, flyway-migrate and backend, but not nginx. The raised rate limits live only in the override file.
- **Steps.** Health wait (5 minutes); `npm ci`; Playwright through the `webServer` dev server, run with `E2E_REQUIRE_BACKEND=1`.
- **Guards.**
  - `e2e/tools/assert-executed.mjs` fails on any skip or on fewer tests than the expected minimum;
  - a PII scan covers the backend log, the report and the traces, for persona addresses **and their blind indexes**;
  - upload retention is ≤ 7 days.
- **Profile test.** A backend unit test asserts that no `application*.yml` raises the login or refresh limits.

**ACs covered:** C4 (making it a required check is an Ops action, Q9).
**Dependencies:** T-026.
**Files impacted:** `docker-compose.yml` (read; not changed in behaviour).
**Files created:** `.github/workflows/e2e-full-stack.yml`, `docker-compose.e2e.yml`, `nexus-frontend/e2e/tools/assert-executed.mjs`, the PII-scan script *(name at planning)*, `BT/config/RateLimitProfileDefaultsTest.java`.
**Complexity:** M.
**Risks:**
- **Supply chain/CI security:** `pull_request_target` would expose a write token to fork code.
- **PII:** artifacts.
- **False green:** silent skips (R6).

**Tests (written first):**
- `RateLimitProfileDefaultsTest`;
- `assert-executed.mjs` fails on a fixture report with one skip and on a zero-test report;
- the PII scan fails on a fixture log containing a dev address's blind index.

**DoD:** the workflow is green on the PR with executed tests > 0 and 0 skips; `./mvnw verify -DskipITs` green. S4c checklist. One commit.

---

# S5b — A11

### T-028 — Frontend DTO types are pinned to recorded backend responses, so a field change on either side fails a test

**Description** (design §11.2, RC-67(b)):
- **Backend recorder.** `ApiContractFixturesTest` (`@JsonTest`, no Docker) serialises canonical instances of the real response records and of the problem bodies (including a 409 `RBAC_012` and an `RBAC_001` with `reason`) into `contracts/api/*.json`. It compares them with the committed files; `-Dcontracts.update=true` rewrites them. It takes over `permission-catalogue.json`.
- **Frontend types.** `shared/types/api/rbac.ts` and `user-directory.ts`, plus `RbacErrorCode` including `RBAC_012`. The interceptor maps `RBAC_012` to a plain `AppError`, with no redirect and no retry.
- **Frontend check.** `api-contract.spec.ts` compares key sets through `satisfies Record<keyof T, true>`.
- **CI.** Both CI workflows add `contracts/**` to their path filters.

**ACs covered:** A11.
**Dependencies:** T-022 (final DTOs and codes), T-015, T-017.
**Files impacted:** `contracts/api/permission-catalogue.json`, `FE/core/http/api-error.interceptor.ts` and its spec, `.github/workflows/frontend-ci.yml` and the backend CI workflow *(locate)*.
**Files created:** `BT/contracts/ApiContractFixturesTest.java`, `contracts/api/*.json` (one per DTO), `FE/shared/types/api/rbac.ts`, `FE/shared/types/api/user-directory.ts`, `FE/shared/types/api/api-contract.spec.ts`.
**Complexity:** M.
**Risks:** **PII:** fixtures use only `example.test` addresses and fixed UUIDs.
**Tests (written first):**
- the backend test fails on a field added to a record without a fixture update;
- the frontend spec fails on a key mismatch;
- `RBAC_012` yields a plain `AppError` with no navigation and no retry.

**DoD:** backend `-DskipITs` and frontend gates. One commit.

---

## Human-gated, not tasks

| Item | Owner | Blocks |
|---|---|---|
| **D5**: ADR-0006 addendum (from ADR-0026); POST lookup; fail-open throttle; best-effort audit (RES-50); enumeration by holder (RES-49); `memberCount` (RES-48); sensitive set (Q-D1); PII delegation and the administrator-only default (RES-51, RC-60.1/60.3); emails self-asserted (RC-63(e)) | Security/Privacy + DPO | **Merge** of T-004 to T-007 (S1c). Confirms T-002's sensitive set and T-023's User Manager persona. Indirectly S3c via A-4 |
| Ops **RES-6** retention for `IDENTITY_DIRECTORY_CROSS_TENANT_TARGET`, `RBAC_PII_PERMISSION_DELEGATED` and `RBAC_ADMIN_DEFINING_ROLE_HAS_NON_ADMIN_ASSIGNED_HOLDER` | Ops | Merge of S1c (T-004 to T-007) and T-020 |
| Ops **RC-61.1** alert thresholds (1,000/h ticket; 10,000/h or tenant size per day page) | Ops | Merge of S1c |
| **RC-62.2** toolchain-only npm criticals recorded with a review date | Frontend Tech Lead | Merge of T-009 |
| **RC-63(d)** V11 runbook ordering (flush, then one of 1,800 s / second flush / verified token) | Architect (S1a docs pass) + Ops | Merge of T-001; enabling us019 anywhere |
| **D2** UX designs | UX + PM | No US-019 task (US-020) |
| **D3** content deck, including `RBAC_012`, 405 and 415 copy (RC-67(b)) | PM + UX | Final label copy in T-015 (placeholders ship); US-020 |
| **D4** propagation wording | PM + Architect | No task (design §14 gives the number) |
| **C3** flag plan per environment, prod values; e2e as a required check (Q9) | Ops | Rollout steps 7–8; making T-027 required |
| **Q-N5** support contact and live vs JWT role names | PM | T-025 ships `null` (link hidden) |
| **Q-N8** percentage rollout; **Q-N10** legal basis and retention | Ops; Legal/DPO | Prod enablement of us019 |
| **RES-26** acceptance; **RES-47** acceptance | Platform Security Owner | Recorded at Gate 2 (2026-10-19); nothing further |
| **D6**, **B9**, release note (RC-67(c)), `flag-rollout-plan.md` text, `monitoring.md` alerts, US-020 carry-forwards (RC-63(e), RC-67(b) retry-once, §2.4 corrections), flag-cleanup ticket (G10), paging-types refactor ticket (Q-D9) | Phase 9 `/docs` and backlog | None |

---

## Execution order and parallelism

**Dependency spine:** T-001 → T-004 → T-005 → T-006 (S1c, D5-gated merge) and T-001 → T-023 → T-026 → T-027; T-003 → T-018 → T-019 → T-020 / T-021 → T-022 → T-028.

| Lane | Order | Can run in parallel with |
|---|---|---|
| Backend A (V11, directory) | T-001 → T-002 ∥ T-007 ∥ T-004 → T-005 → T-006; T-008 after T-004 | Lanes B and C |
| Backend B (handlers, RBAC) | T-003 → T-017 (merge first) → T-018 → T-019 → T-020 → T-021; T-016 after T-002 | Lanes A and C; T-019 needs T-007 (A-4) |
| Frontend C | T-009 → T-010 → T-011; T-012 ∥ T-013 → T-014; T-015 (after T-001); T-024 ∥ T-025 after T-010 (T-024 needs T-013) | Lanes A and B entirely |
| Integration | T-022 after lanes A and B → T-028 (also needs T-015, T-017); T-023 after T-001, T-004, T-008 → T-026 (also needs T-011, T-024, T-025) → T-027 | — |

**Serialised merges on `GlobalExceptionHandler`:** T-003, then T-017, then T-018. **Same-PR pair:** T-018 and T-019 (A-7, interim guard).

## Per-task model / effort guidance

| Guidance | Tasks | Why |
|---|---|---|
| **Strongest model, high effort** | T-018, T-019, T-020, T-021 | Locking/concurrency **and** authorization (RC-46 lock order, `nexus_app` privileges, zero-admin and provenance races); T-018 also cryptographic hashing |
| **Strongest model** | T-001, T-004, T-005, T-007, T-008, T-017, T-025 | Authorization (admin definition, tenant isolation, PII grant rule, single predicate, reason disclosure, open redirect); T-005 cryptography (blind index) and T-004 decryption |
| Standard model | T-002, T-003, T-006, T-010, T-011, T-016, T-022, T-023, T-026, T-027, T-028 | PII-in-logs, session/refresh, CI security or query-count discipline, but no lock or crypto design |
| Light model (mechanical) | T-009, T-012, T-013, T-014, T-015, T-024 | Upgrade and lint config, design-system wrappers, labels, title/focus |

---

## Traceability 1 — Threat-model required changes and threats → task

"Landed" means the design or ADR text change was folded in at Gate 2; the task listed implements or proves it. "Human" items are in the section above.

| Item | Threat | Requirement (short) | Task(s) |
|---|---|---|---|
| RC-55.1 | T-T22 | Step 9 compares `v1` to `v0` | T-018 |
| RC-55.2 | T-T22 | `If-Match` exactly one strong tag, else 428 | T-018 |
| RC-55.3 | T-T22 | Soundness paragraph rewritten | Landed (design §10.3); T-018 unit test proves the check |
| RC-55.4 | T-T22 | IT case (g); two-tag unit test | T-018 |
| RC-55.5 | T-T22 | ADR-0027: ETag is not a secret | Landed (ADR-0027) |
| RC-56.1 | T-E48 | Queued assign/attach recorded in proof table | Landed (design §10.4); proven by T-020 harness |
| RC-56.2 | T-E48 | Assign post-insert re-classification, 409 `RBAC_012` | T-020 |
| RC-56.3 | T-E48 | Attach post-insert re-classification | T-020 |
| RC-56.4 | T-E48 | Committed-state detector, pages | T-020 (B8 call site after T-019) |
| RC-56.5 ◆ | T-E48 | Land in S3c | T-020 (decision taken) |
| RC-56.6 | T-E48 | ADR-0021 Rev 3 corrects R1-1 | Landed (ADR-0021 R3) |
| RC-56.7 | T-E48 | Harness cases | T-020 |
| RC-57.1 | T-E49 | B8 current classification under the set lock | T-019 |
| RC-57.2 ◆ | T-E49 | Revoke, softDelete, break-glass under the lock | T-021 |
| RC-57.3 | T-E49 | RES-28 text corrected | Landed (design §10.4) |
| RC-57.4 | T-E49 | Harness C: two demotions; demotion ∥ revoke | T-019 (a), T-021 (b) |
| RC-58.1 | T-I20 | 403 before 412 and the no-op | T-018 |
| RC-58.2 | T-I20 | 412/428 bodies carry no state | T-018 |
| RC-58.3 | T-I20 | Tests | T-018 |
| RC-58.4 ◆ | T-I20 | Live `role:read` required | T-018 |
| RC-59.1 | T-I21 | Body/media/method/header handlers, no message logged | T-003 |
| RC-59.2 | T-I21 | Malformed-body log scan | T-006 |
| RC-59.3 | T-I21 | 1 KiB lookup cap | T-005 |
| RC-60.1 | T-E50 | ADR-0026 + D5 record delegation | Landed (ADR-0026 §7); **Human (D5)** |
| RC-60.2 | T-E50 | Delegated WARN + counter | T-007 |
| RC-60.3 ◆ | T-E50 | Administrator-only grant, default ON | T-007 (attach, assign), T-019 (B8); D5 confirms |
| RC-61.1 | T-R16 | Row-volume alert | T-006 (log fields `resultCount` per op); alert rule in `monitoring.md` (Phase 9); thresholds **Human (Ops)** |
| RC-61.2 | T-R16 | Batch cross-tenant count + WARN, contained | T-004 |
| RC-61.3 | T-R16 | Per-actor ceiling `USER_DIR_002` | T-006 |
| RC-62.1 | T-T23 | `@angular/*` ≥ 22.2.0, clean prod audit | T-009 |
| RC-62.2 | T-T23 | Toolchain criticals recorded | **Human (Frontend Tech Lead)**, T-009 merge checklist |
| RC-62.3 | T-T23 | ESLint HTML-sink ban | T-009 |
| RC-63(a) | T-T24 | Attach row corrected; B8 ∥ attach both orders as `nexus_app` | Landed (§10.4); T-018 case (b) |
| RC-63(b) | T-E51 | RES-27 restated for B8; session timeout not adopted | Landed (§10.3); no code by decision |
| RC-63(c) | T-D26 | `page × size > 10,000` → 400; `selfReported`; one WARN per window; capacity note | T-004 (400), T-003 (`selfReported`), T-005/T-006 (one WARN per window); capacity note landed (§16) |
| RC-63(d) | T-I23 | V11 runbook ordering | **Human/docs** (S1a merge checklist, T-001) |
| RC-63(e) | T-S12 | Status/`emailVerified` beside email; CSV; PENDING; D5 note | T-004 (fields exposed); rest **Human (D5)** and US-020 carry-forward |
| RC-63(f) | T-R17 | `replaceId`; ceased-admin WARN | T-018 (`replaceId`), T-019 (WARN, counter) |
| RC-63(g) | T-E52 | `!prod` profile, `assigned_by` not self, `DEV_SEED_ACTIVE` | T-023 |
| RC-63(h) | T-I24 | `pull_request`, read-only; CI-only override + profile test; blind-index scan; retention; one page per context | T-027 (workflow, scan, retention, profile test), T-026 (one page per context, `requireBackend`) |
| RC-63(i) | T-T25 | No second decode; `PublicLayout` pin; no mutation on activation | T-025 (function, pin); "no mutation on activation" is D6 text (Phase 9) |
| RC-63(j) | T-I25 | Normalise `traceId` and `instance`; `existsById` inherited | T-004, T-002 (B3 equivalence) |
| RC-63(k) | B5 | ArchUnit `SENSITIVE` containment | T-002 |
| RC-63(l) | T-I22 | Reason only on `RBAC_001`; SPA no auto-retry `RBAC_011`; RES-33 text | T-017; RES-33 text landed |
| RC-64.1 | T-D28 | Attach takes the role-row lock first | T-020 |
| RC-64.2 | T-D28 | Lock order checked | Landed (§10.4, §10.9); T-020 harness proves it |
| RC-64.3 | T-D28 | Text corrected | Landed |
| RC-64.4 | T-D28 | Attach ∥ attach harness | T-020 |
| RC-64.5 | T-D28 | Alternative if rejected | Not applicable (RC-64.1 adopted) |
| RC-65.1–65.3 | T-S14 | Shared refresh service, or drop `canActivateChild` | Option 3 taken by design (§12.9): T-025 spec asserts no `canActivateChild` with `authGuard`; T-011 proves a single refresh at cold start |
| RC-66.1 | T-E54 | PII rule after A2/A3 | T-007 (attach, assign), T-019 (B8) |
| RC-66.2 | T-E54 | Assign denial posture | T-007 |
| RC-66.3 | T-E54 | Assign post-insert PII re-check | T-020 |
| RC-66.4 | T-E54 | Startup WARN when off; prod pins `true` | T-007 |
| RC-67(a) | T-D29 | `AssignRoleContentionIT` | T-020 |
| RC-67(b) | T-D30 | `RBAC_012` in fixtures, `AppError`, D3, US-020 note | T-028 (fixtures, types, interceptor); D3 **Human**; US-020 note Phase 9 |
| RC-67(c) | T-R18 | Text fixes; release note | Landed (text); release note Phase 9 (T-003 checklist) |
| T-S13 (survived) | — | B4 no identifier, live, predicate reused | T-008 tests keep it |
| T-I26 (survived) | — | Lookup/by-id not cross-tenant oracles | T-004, T-005 byte-equality tests |
| T-D27 (survived) | — | No lock before authorization | T-018 (steps 1–7 lock-free; test) |
| T-E53 (survived) | — | V11 promotes no one | T-001 semantic IT |
| RES-6 | — | Retention of new WARN markers | **Human (Ops)**; S1c and T-020 checklists |
| RES-26 | T-E48 | Provenance under concurrency | T-020 (+ T-019 `RBAC_010` on B8); acceptance recorded at Gate 2 |
| RES-27 | T-E51 | Snapshot TOCTOU | Accepted (Low); no code |
| RES-28 | T-E49 | Zero admins via concurrent demotions | T-019, T-021 (closed except detach ∥ detach; detected by the existing indicator) |
| RES-39 | — | Guard fail-open on missing `data.permission` | T-010 (`nav.config.spec.ts`), T-011 (fail-open tests unmodified) |
| RES-41 | — | No break-glass for tenants without a system admin | Accepted; T-023 documents the second tenant in its Javadoc |
| RES-45 | — | Flip-driven 1213 | Accepted; T-018/T-019/T-020 ITs assert none outside it; `permission_replace{outcome=error}` pages |
| RES-47 | T-I22 | B7 disclosure bits | T-017; accepted at Gate 2 |
| RES-48 | — | `memberCount` single-holder | T-016; **Human (D5)** |
| RES-49 | T-R16 | Enumeration by holder | T-006 (signals); **Human (D5)** |
| RES-50 | — | Best-effort directory audit | T-006 (failure counter); **Human (D5)** |
| RES-51 | T-E50 | PII delegation | T-007, T-019; **Human (D5)** |
| RES-52 | T-I23 | V11 availability window | **Human/docs** (runbook, rollout) |
| RES-53 | T-D30 | Clients retry `RBAC_012` once | T-028 (no auto-retry in US-019); US-020 implements retry-once |

## Traceability 2 — Acceptance criteria → task

| AC | Task(s) |
|---|---|
| A1 | T-010 (shell parent), T-011 (contract spec, real-Router cold start, one refresh), T-026 (e2e scenarios 1–3); D6 guide text: Phase 9 |
| A2 | T-010; T-026 (e2e nav, skip link, landmarks) |
| A3 | T-009 (Material/CDK lint, axe mechanism), T-010 (`nx-menu`), T-012, T-013, T-014 |
| A4 | T-014 |
| A5 | T-001 (union member), T-015 (labels, grouping, catalogue test), T-028 (fixture takeover) |
| A6 | T-015 |
| A7 | T-024; T-026 (e2e) |
| A8 | T-024 |
| A9 | T-025 (contact value Q-N5 is **human-only**) |
| A10 | T-025; T-026 (e2e round trip) |
| A11 | T-028 (with T-015's interim fixture) |
| B1 | T-004 (list, by-id, fields, isolation, flag), T-005 (exact-email lookup), T-006 (logs, audit, throttle), T-003 (no email in parse-error logs); **merge needs D5 (human)** |
| B2 | T-004 |
| B3 | T-002 |
| B4 | T-008 |
| B5 | T-002 (set membership confirmed at D5) |
| B6 | T-016 |
| B7 | T-017 |
| B8 | T-018, T-019, T-020, T-021 |
| B9 | **Docs-only** (Phase 9 `/docs`: `docs/features/US-018/STATUS.md`); no task |
| B10 | T-022 |
| C1 | T-023 |
| C2 | T-026 |
| C3 | **Human-only** (Ops flag plan; `flag-rollout-plan.md` written in Phase 9) |
| C4 | T-027 (required-check setting is **human**, Ops/Q9) |
| D1 | Delivered; verify only, no task |
| D2 | **Human-only** (UX + PM) |
| D3 | **Human-only** (content deck) |
| D4 | **Human-only** + docs (number recomputed in design §14) |
| D5 | **Human-only** (Security/Privacy sign-off; blocks S1c merge) |
| D6 | **Docs-only**, Phase 9 `/docs` (developer guide, dashboard README); no task |

Story scenarios: 1–3 T-011, T-026 · 5 T-010, T-026 · 12 T-008 · 14 T-018.

---

## Open items (not mappable to a task)

| # | Item | Owner |
|---|---|---|
| O-1 | No RPS, p95 or SLO is stated (G-1). The design's proposed p95 < 200 ms for B1, B3 and B4 is unconfirmed, so no load test is added. | Story owner (Gate 1 gap) |
| O-2 | Whether T-007 may merge ahead of the D5-gated directory tasks so that S3c (T-019) does not wait on D5 (A-4). | Story owner + Platform Security Owner |
| O-3 | T-018's interim guard on admin-defining roles exists only if T-018 and T-019 are split across PRs; the recommendation is one PR. | Architect at `/implement` |
