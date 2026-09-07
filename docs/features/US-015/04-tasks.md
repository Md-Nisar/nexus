# US-015 — Task Breakdown: Enable role and role-permission management API

**Phase:** 4 (Task Breakdown) — Gate 3
**Inputs:** `docs/features/US-015/03-design.md` (Gate 2 Step A, revised with RC-1…RC-7), `docs/features/US-015/03b-threat-model.md` (Gate 2 Step B, conditional pass)

**Grain note (per request):** tasks are grouped by cohesive implementation unit, not by file or by AC. Each task is sized to be implemented and validated (unit + integration where applicable) in one pass before moving to the next. Twelve tasks total, plus one pre-existing artifact (`US-016.md`) already filed.

**Outstanding Gate 2 conditions not yet closed (tracked here, not blocking `/breakdown`, but blocking merge):**
- **C2 — named owner.** §10.2's D15 acceptance still names a role ("RBAC bounded-context tech lead"), not a person. Must be a name before this story merges.
- **C3 — verified, not assumed.** `docs/story/2-rbac/US-016.md` exists as a draft stub (not yet through its own Gate 1). The threat model requires it exist "with an id, before this story merges" — the id exists (US-016); Gate 1 for it does not need to complete before *this* story merges, only the filing does.

---

## Epic: US-015

```
├─ Database (migrations / schema)         — none required, see T-000
├─ Backend
│   ├─ Domain                             — T-001
│   ├─ Application                        — T-002, T-005
│   ├─ Infrastructure                     — T-003, T-004
│   └─ Interfaces (controllers)           — T-006
├─ Frontend                               — none, see note below
├─ Cross-cutting                          — T-007, T-008, T-009
├─ Tests                                  — T-010
└─ Documentation                          — T-011, T-012
```

**Frontend: no tasks.** Epic 3's Tenant Admin UI is the consumer of this API and is explicitly out of scope (story Out of Scope; design §8.8 forward notes only). Nothing to implement here.

---

### T-000 — Confirm no database migration is required

**Description:** Not an implementation task — a gate. Confirm `V5__rbac_schema.sql` already covers every table/column/index/constraint this story needs (design §5.1) before any other task starts, so nobody accidentally writes a `V6` migration for something already shipped.

**Dependencies:** none (do first)
**Files impacted:** none · **Files created:** none
**Complexity:** S
**Risks:** None — this is a verification step, not a change.
**Testing requirements:** Run `RbacSchemaMigrationIT` unmodified; confirm it stays green (it uses `containsExactly` for columns — any accidental schema drift fails loudly).
**Definition of Done:** `RbacSchemaMigrationIT` passes with zero modification. No `V6__*.sql` file exists.

---

### T-001 — Domain layer: value types, exceptions, and the reserved-name/dangerous-permission constants

**Description:** All new domain types with no dependencies on ports or Spring. This is the foundation every other task compiles against, so it goes first and alone.

- `RoleView`, `PermissionView` records (design §4.4)
- `RbacDangerousPermissions` (fixed 3-permission set, case-insensitive `contains`)
- `RbacRoleNames` — **extend existing class** (RC-1): add a `RESERVED` set (`TENANT_ADMIN`, `MEMBER`) and case-insensitive `isReserved(String)`, mirroring `RbacDangerousPermissions`' shape
- 5 new exceptions, all `ConflictException` subtypes with **fixed static literal messages** (never built from a caught DB exception's text): `SystemRoleImmutableException` (RBAC_003), `DuplicateRolePermissionException` (RBAC_005), `DuplicateRoleNameException` (RBAC_006), `ReservedRoleNameException` (RBAC_007, RC-1), `RoleLimitExceededException` (RBAC_008, RC-4)

**Dependencies:** T-000
**Files impacted:** `rbac/domain/RbacRoleNames.java`
**Files created:** `rbac/domain/RoleView.java`, `rbac/domain/PermissionView.java`, `rbac/domain/RbacDangerousPermissions.java`, `rbac/domain/SystemRoleImmutableException.java`, `rbac/domain/DuplicateRolePermissionException.java`, `rbac/domain/DuplicateRoleNameException.java`, `rbac/domain/ReservedRoleNameException.java`, `rbac/domain/RoleLimitExceededException.java`
**Complexity:** S
**Risks:** Low. The one real risk is an exception message accidentally interpolating a caught exception's text (design §4.4 explicitly calls this out as the mechanism that would leak MySQL internals through `handleConflict`).
**Testing requirements:** Unit — one test per exception asserting the literal message and code; `RbacRoleNamesTest` for `isReserved` (case variants, non-reserved names); `RbacDangerousPermissionsTest`; `RoleViewTest`/`PermissionViewTest` (records — compact constructor / equality only). Target: `*.domain.*` ≥ 0.90 gate (design §11.3).
**Definition of Done:** All types compile with no dependency outside `rbac.domain` / `common.domain`; `*.domain.*` coverage gate passes for this package; ArchUnit's existing `domain_must_not_depend_on_outer_layers` stays green with zero new exceptions.

---

### T-002 — Application layer: `RoleManagementPort` interface + `RoleManagementService`

**Description:** The security-critical core of the story — the entire AC1–AC12 guard chain in one service, plus its port. This is the single largest task and should not be split further: every AC in it shares the same two guard methods (`resolveRoleInTenant`, `requireMutableRole`), and splitting by AC would mean re-touching the same file repeatedly instead of writing it once, correctly, with its own full test suite.

Covers: AC1 (create + RC-1 reserved-name check + RC-4 per-tenant cap), AC2 (list), AC3 (list role permissions, 404/403), AC4 (attach + AC7 + AC8 + AC11), AC5 (detach + AC7 + AC8), AC6 (list all permissions), AC7 (system-role immutability, single shared guard), AC8 (tenant isolation, single shared guard), AC9 (duplicate name), AC11 (dangerous-permission admin gate — **the fresh, locking `Q3 → Q11` read, never the non-locking shortcut**), AC12 is wired here but implemented in T-004 (audit port).

`RoleManagementPort` methods: `createRole`, `findRole`, `findRolesInTenant`, `findRoleIdByName` (Q3), `countRolesInTenant` (Q12, RC-4), `findPermission`, `findAllPermissions`, `findPermissionsForRole`, `hasPermission`, `attachPermission`, `detachPermission`.

**Dependencies:** T-001
**Files impacted:** none
**Files created:** `rbac/application/port/out/RoleManagementPort.java`, `rbac/application/RoleManagementService.java`, `rbac/application/port/out/RoleAuditEvent.java` (record only — see file-ownership note below), `rbac/application/port/out/RbacAuditPort.java` **(+3 method signatures only, no implementation — reassigned from T-004, see note)**
**Complexity:** L
**File-ownership note (resolved during T-002 planning, updating the original split above):** `RoleManagementService` is `RbacAuditPort`'s only new caller and cannot compile — or be unit-tested with Mockito — against methods that don't exist. T-002 therefore creates `RoleAuditEvent.java` and adds the 3 new method **signatures** to `RbacAuditPort.java` (copied verbatim from design §6.1/§6.2). T-004's scope narrows accordingly: it implements the adapter overload, adds the 3 `AuthEventType` constants, and writes the adversarial-payload tests — it does not recreate the port signatures or the record.
**Risks:**
- **F1 (design §5.2, threat model T-E14) — the single most likely silent failure in this story.** `Q3 → Q11` must be a fresh, locking read inside the write transaction. Copying `RoleAssignmentService.callerHoldsActiveTenantAdmin`'s shape, or calling `UserRoleAssignmentPort#findActiveAssignmentViews` instead of `hasActiveAdminAssignment`, satisfies AC11's letter and destroys its point — with no failing unit test. Only the concurrent-revocation IT (T-010) and T-007's ArchUnit rule catch this.
- AC11's check ordering is pinned (design §8.6): tenant resolution → AC7 → body-derived lookups → AC11. Do not reorder.
- `nexus.rbac.max-roles-per-tenant` (RC-4) must be an externalized config property (default 500), not a hard-coded literal.
**Testing requirements:** Unit — `RoleManagementServiceTest` covering all 11 methods and every error branch (this will be the largest application-layer test class in the codebase per design §11.2; target `*.application.*` ≥ 0.85, the binding coverage constraint). Integration — deferred to T-010 (cross-layer ITs need T-003/T-006 first), but this task is not "done" until those ITs exist and pass.
**Definition of Done:** `RoleManagementServiceTest` green at ≥0.85 branch coverage for the package; every AC1–AC9/AC11 error branch has an explicit test; `rbac_application_methods_must_not_accept_principal_or_map` and `domain_and_application_must_not_depend_on_spring_security` (existing ArchUnit rules) stay green with zero suppressions.

**Known interim state, expected and documented (not a regression to chase):** `RoleManagementService` is a plain `@Service` (design §4.2, no `@ConditionalOnProperty` — the flag is pinned to the two controllers only, §11.1). Until T-003 supplies a `RoleManagementPort` bean, full-`@SpringBootTest`-context tests that boot the whole application context — `NexusSmokeTest`, `SecurityConfigWebTest`, `RequiresPermissionWebTest` — fail on `UnsatisfiedDependencyException: No qualifying bean of type 'RoleManagementPort'`. This is the direct, single-cause consequence of this task's own file boundary (no adapter) meeting this repo's full-context test suite, not a defect in T-002's code. `./mvnw verify -DskipITs` is expected to show exactly these 3 pre-existing test classes failing, with this one root cause, between T-002 landing and T-003 landing. Do not work around it with a flag on the service (deviates from design §4.2/§11.1) or a throwaway stub adapter (T-003's file). Resolve by proceeding to T-003 next; re-run full `verify` after T-003 lands to confirm all 3 pass again.

---

### T-003 — Infrastructure: `JpaRoleManagementAdapter` + repository query additions

**Description:** Implements `RoleManagementPort` over JPA. Owns constraint-violation translation (the only non-mechanical logic here) and the Q1–Q12 query set.

- `JpaRoleManagementAdapter` implementing `RoleManagementPort`
- `JpaRoleRepository`: +Q1 (list by tenant), +Q3 (find id by name — **plain `=`, never `UPPER()`, sargable**), +Q12 (count by tenant, RC-4)
- `JpaRolePermissionRepository`: +Q7 (single projection join), +Q9 (`@Modifying` bulk delete returning affected-row count)
- `UserRoleAssignmentPort`: +1 method — role→users reverse lookup (RC-6: `SELECT user_id FROM user_roles WHERE role_id = :r AND revoked_at IS NULL`), needed for the D16 remediation path, not for this story's own runtime path

**Dependencies:** T-002
**Files impacted:** `rbac/infrastructure/persistence/JpaRoleRepository.java`, `rbac/infrastructure/persistence/JpaRolePermissionRepository.java`, `rbac/application/port/out/UserRoleAssignmentPort.java`, `rbac/infrastructure/persistence/JpaUserRoleAssignmentAdapter.java` (implements the RC-6 method the port interface gains — a required consequence of the port change, missed in the original file list), `rbac/infrastructure/persistence/JpaUserRoleRepository.java` (+1 query backing RC-6)
**Files created:** `rbac/infrastructure/persistence/JpaRoleManagementAdapter.java`
**Complexity:** M
**Risks:**
- Constraint-violation mistranslation is the specific failure mode that turns a clean 409 into a 500 in production only (every `*IT` runs as the Testcontainers superuser, which has no privilege restrictions to trigger the path) — see T-010's `RolePermissionsPrivilegeIT`.
- Q3 must stay sargable — no `UPPER()` wrapper (design §5.2 explicitly forbids copying `findTenantsWithZeroActiveAssignmentsForRole`'s shape).
**Testing requirements:** Unit — `JpaRoleManagementAdapterTest` for both constraint translations (mocked), verified via `./mvnw verify -DskipITs`. Integration — `RbacRepositoryRoundTripIT` extension for `Role`/`RolePermission` round-trips (should already pass unmodified per design §5.4 — confirm via diff that the file is untouched; running it green is T-010's job, not this task's). Optional: an `EXPLAIN`-asserting test pinning Q3's plan to `uq_roles_tenant_name`.
**Definition of Done:** Both constraint-violation branches have a dedicated passing test under `-DskipITs`; `RbacRepositoryRoundTripIT` confirmed unmodified (diff, not a Docker run — its green status is validated once, for real, in T-010); the D10 JaCoCo exclusion removal (T-007) applies cleanly to this package once it exists.

---

### T-004 — Audit path: `RoleAuditEvent`, `RbacAuditPort` extension, `RbacAuthEventAdapter` overload, `AuthEventType` constants

**Description:** AC12 end-to-end. **Narrowed scope per T-002's file-ownership note above:** `RoleAuditEvent` (record) and `RbacAuditPort`'s 3 new method signatures already exist as of T-002. T-004 implements the adapter overload against those existing signatures, adds the 3 new `AuthEventType` enum constants with the PRIORITY-lane admission decided in design (D7: grant/revoke IN, create OUT), and writes the adversarial-payload test coverage.

**Dependencies:** T-002 (both the service and the port/record now exist; can be developed in parallel with T-003)
**Files impacted:** `identity/domain/AuthEventType.java`, `identity/infrastructure/audit/RbacAuthEventAdapter.java`, `rbac/application/port/out/RbacAuditPort.java` (Javadoc only — distinguishing the 5 post-commit methods from the 1 inline-denial method; signatures already added in T-002)
**Files created:** none (moved to T-002)
**Complexity:** M (reduced from original estimate — signature/record work moved to T-002)
**Risks:**
- `RoleAuditEvent` must have **no `targetUserId` field** — these events have no subject user by design; `auth_events.user_id` stays `NULL` (design §6.1). Adding one "for consistency" would silently redefine the column's meaning for 3 of 26 event types.
- Tenant-controlled `roleName`/`permissionName` now flows into a native JSON column for the first time in this bounded context (threat model T-T8) — must go through the existing injected Jackson-3 `ObjectMapper`, never string concatenation. This is already the adapter's existing pattern; do not deviate.
- `buildMetadataJson` must omit null keys (not emit JSON `null`) for the permission fields on a role-creation event.
**Testing requirements:** Unit — `RbacAuthEventAdapterTest` extended with the adversarial `roleName`/`permissionName` corpus (quotes, backslashes, control characters, U+2028/U+2029 — non-negotiable per threat model §8, and also the mandated DTO-layer equivalent against `CreateRoleRequest`'s `@Pattern`, asserting 400, covered in T-006) and the null-`permissionId` omit-the-key case. Modified — `AuthEventTypeTest` (23→26; priority 6→8; explicit `ROLE_CREATED`-is-not-priority assertion; **never weakened to `hasSizeGreaterThan`**).
**Definition of Done:** `AuthEventTypeTest` and the extended `RbacAuthEventAdapterTest` pass; no PII in any new field (all UUIDs, names, booleans); `nexus.rbac.audit_write_failed{operation}` gains the three new operation tags.

---

### T-005 — RC-7: exploitation-side detection signal in `RoleAssignmentService`

**Description:** The single most important threat-model finding (T-E16). An additive, non-authorization-changing change to US-012's existing code: emit `nexus.rbac.self_role_assignment` (unconditional — no new query, no dangerous-permission check) plus a WARN in `assign()`'s existing post-commit block when `actorUserId == targetUserId`. Also the D13 Javadoc amendment on `assign()`'s M-3 note and `revoke()`'s T-E9 note (design §10.3, exact text given verbatim there — copy it, do not paraphrase).

**Kept as its own task, separate from T-002**, because it touches a *different* story's shipped file (`RoleAssignmentService.java`, US-012) and carries its own explicit non-regression constraint: this must not change `assign()`'s signature, return type, or any 2xx/4xx outcome.

**Dependencies:** T-001 (no code dependency, but should land after the domain types exist so the Javadoc's cross-references resolve)
**Files impacted:** `rbac/application/RoleAssignmentService.java`
**Files created:** none
**Complexity:** S
**Risks:**
- **This is the one change in the entire story most likely to be over-engineered.** The threat model is explicit: unconditional emission, no lookup of the assigned role's permissions. Adding a "carries a dangerous permission" check here re-introduces a query `assign()` doesn't have today and was explicitly rejected as unnecessary — the severity distinction happens at alert-composition time (T-008), not here.
- Must not trip the §0 conditional-ADR trigger: no new branch, no new denial path, `AC8`'s existing name-match guard is untouched.
**Testing requirements:** Unit — extend `RoleAssignmentServiceTest` with a self-assignment case asserting the counter increments and the assignment still succeeds; a non-self-assignment case asserting it does not increment. Integration — covered by T-010's escalation-chain IT.
**Definition of Done:** `RoleAssignmentServiceTest` extended and green; `RoleAssignmentAuditIT` (existing, US-012) passes unmodified — this task must not require editing an existing assertion there (if it does, stop, per the same discipline as the D4 abort condition in T-006).

---

### T-006 — Interfaces: `RoleController`, `PermissionController`, DTOs, `RbacControllerSupport` extraction

**Description:** All six HTTP endpoints, their DTOs, and the shared `parsePathUuid`/`resolveActor`/`requestContext` helper — including migrating `UserRoleController` (US-012) onto it in the same change (D4).

**Explicit abort condition, carried over from the design verbatim:** if migrating `UserRoleController` requires editing any existing assertion in `UserRoleControllerTest` or `RoleAssignmentSecurityIT`, **stop and duplicate the helper instead.** A required test edit proves the migration was not behaviour-preserving.

**Dependencies:** T-002, T-004
**Files impacted:** `rbac/interfaces/rest/UserRoleController.java`
**Files created:** `rbac/interfaces/rest/RoleController.java`, `rbac/interfaces/rest/PermissionController.java`, `rbac/interfaces/rest/RbacControllerSupport.java`, `rbac/interfaces/rest/dto/CreateRoleRequest.java`, `rbac/interfaces/rest/dto/AttachPermissionRequest.java`, `rbac/interfaces/rest/dto/RoleResponse.java`, `rbac/interfaces/rest/dto/RoleListResponse.java`, `rbac/interfaces/rest/dto/PermissionResponse.java`, `rbac/interfaces/rest/dto/PermissionListResponse.java`
**Complexity:** L
**Risks:**
- **Blast-radius widening (threat model T-S6).** One helper now backs 8 endpoints across two stories. `RbacControllerSupportTest` must assert each fail-closed branch **throws**, not merely returns falsy — a test asserting `isNull()` would pass against a fail-open rewrite. The class must be `final`, private constructor, only `static` methods.
- `name`/`description` validation patterns must match design §8.1 exactly, including RC-3's broadened `description` pattern (`^[^\p{Cntrl}  ]*$`) and the reserved-name/cap checks living in the *service* (T-002), not the controller.
- Boolean JSON naming trap: `isSystemRole` record component must serialize as `isSystemRole`, not `systemRole` — assert the literal key in a controller test.
**Testing requirements:** Unit — `RoleControllerTest`/`PermissionControllerTest` (MockMvc slice) with a negative-control 403 per endpoint; `RbacControllerSupportTest` for all three fail-closed branches (throws, not falsy-return). DTO-layer adversarial corpus (quotes, backslashes, control chars, U+2028/2029) against `CreateRoleRequest`'s `@Pattern`, asserting 400 (per T-004's note). Target `*.interfaces.rest.*` ≥ 0.80. **Design §8.1/RC-3's "never logged/audited" invariant on `description`** (dropped from every earlier task — no task previously owned it): a test asserting no code path passes `description` to a logger or an audit call. Structurally already true (`RoleAuditEvent` has no `description` field; `RoleManagementService` only threads it through as a parameter) — this task adds the missing positive-assurance test, not a code fix.
**Definition of Done:** All six endpoints pass their MockMvc slice tests; `UserRoleControllerTest` and `RoleAssignmentSecurityIT` pass **unmodified** (or the abort condition was invoked and is documented in the PR); boolean JSON key literal asserted.

---

### T-007 — Cross-cutting: ArchUnit rules (D8 + RC-5a/c), health indicator (D9), JaCoCo exclusion removal (D10)

**Description:** The mechanical/architectural backstops. Three ArchUnit rules in `HexagonalArchitectureTest`: (1) `@RequiresPermission` methods must be public and non-final, (2) their declaring classes must be non-final, (3) **RC-5a** — `RoleManagementService` must never call `UserRoleAssignmentPort#findActiveAssignmentViews`. If the pinned ArchUnit version cannot express any of the three exactly as written, implement that one as a reflection-based JUnit test instead — **do not drop, weaken, or defer it (RC-5c)**. Extend `RbacDbPrivilegeHealthIndicator` to `roles`/`role_permissions` including the `COLUMN_PRIVILEGES` leg (D9). Remove the stale JaCoCo exclusion on `*.rbac.infrastructure.persistence` (D10).

**Dependencies:** T-002, T-003 (the ArchUnit rule and the coverage-gate removal need those classes to exist to be meaningful)
**Files impacted:** `src/test/java/com/example/nexus/architecture/HexagonalArchitectureTest.java`, `rbac/infrastructure/health/RbacDbPrivilegeHealthIndicator.java`, `nexus-backend/pom.xml`
**Files created:** none
**Complexity:** M
**Risks:**
- `role_permissions` must **not** be checked for `DELETE` in the health indicator — it's intentionally granted (no soft-delete column, no trigger). Copy-pasting the `user_roles` check would make the indicator permanently DOWN (design §9.5 explicitly flags this as a trap).
- Removing the JaCoCo exclusion may drop the `*.infrastructure.*` coverage gate below 0.70 — per design, **that failure is information, not an obstacle**: do not re-add the exclusion to make the number pass; add tests instead.
**Testing requirements:** `RbacDbPrivilegeHealthIndicatorTest` extended for the new per-table expectations (both `TABLE_PRIVILEGES` and `COLUMN_PRIVILEGES` legs). ArchUnit rules run as part of the standard `./mvnw verify` gate — verify each of the three fails on a deliberately-reverted local change before committing (proves the rule actually catches what it claims to).
**Definition of Done:** All three ArchUnit rules present and independently verified to fail on the condition they guard against; `RbacDbPrivilegeHealthIndicatorTest` green; JaCoCo exclusion removed from `pom.xml` and the resulting coverage number (pass or fail) is reported in the PR, not silently worked around.

---

### T-008 — Cross-cutting: feature flag, config properties, and alert wiring

**Description:** `feature.nexus-us015-rbac-role-management.enabled` on both controllers (`@ConditionalOnProperty`, default `false`, `true` in `dev`/`test`), the `nexus.rbac.max-roles-per-tenant` config property (default 500, RC-4), and the Prometheus alert rules from design §9.3 including the RC-5b threshold change (`RBAC_003` alert `>3` → `>0`) and the RC-7 composed alert (`self_role_assignment` ticket, escalating to page when `dangerous_permission_granted` has also fired for the same tenant).

**Dependencies:** T-006 (flag gates the controllers), T-005 (RC-7 counter must exist before its alert can be wired)
**Files impacted:** `src/main/resources/application.yml`, `src/main/resources/application-dev.yml`, `src/main/resources/application-test.yml`
**Files created:** none (alerting config lives in the existing Prometheus rule files, if version-controlled in this repo — confirm location at implementation time)
**Complexity:** S
**Risks:**
- **Known US-012 trap, explicitly carried forward:** the flag must live in profile YAML, never a `DynamicPropertyRegistrar` — `@ConditionalOnProperty` on a `@Component` is evaluated during component scan, before `DynamicPropertyRegistrar` contributions are visible (this repo's known Spring Boot 4 property-precedence gotcha).
- Every HTTP-level `*IT` must run with `@ActiveProfiles("test")`, or the controllers are absent and every request 404s — indistinguishable from a routing bug if this is missed.
**Testing requirements:** A smoke test confirming the flag is `false` by default and `true` under the `test` profile; confirm `application-smoke.yml` is unaffected (flag absent ⇒ `false`).
**Definition of Done:** Flag behaves correctly in all four profiles listed in design §11.1; `nexus.rbac.max-roles-per-tenant` is externally configurable and defaults to 500; alert thresholds match the corrected values, not the original design draft's.

---

### T-009 — Cross-cutting: dashboard panels and runbook

**Description:** The "RBAC / Role Management" dashboard row (design §9.6, including the RC-7 self-role-assignment panel overlaid with the mint-side counter) and `docs/features/US-015/runbook.md`, which must contain: the `command denied` first-check (T-003's failure mode), the corrected ~30-minute AC10 staleness window with the immediate-effect path (RC-2), the D15 escalation-review procedure, and the full D16 remediation sequence including the RC-6 flag-ordering trade note, the immediate DBA-SQL reverse lookup, and the mandatory JSON-path forensic query (RES-7 reword).

**Dependencies:** T-004, T-005, T-008
**Files impacted:** none
**Files created:** `docs/features/US-015/runbook.md`, `docs/features/US-015/monitoring.md`
**Complexity:** S
**Risks:** The single biggest risk here is copying an earlier draft's "~15 minutes" figure instead of the corrected "~30 minutes" — check against `03-design.md` §5.5 directly when writing, not from memory of an earlier conversation about this story.
**Testing requirements:** None (documentation) — but the DBA SQL in the runbook (`SELECT BIN_TO_UUID(user_id) FROM user_roles WHERE role_id = UUID_TO_BIN(?) AND revoked_at IS NULL;`) should be run once against a Testcontainers instance during review to confirm it's syntactically correct for the schema as shipped.
**Definition of Done:** Runbook contains all four required sections listed above with the corrected figures; dashboard panel list matches design §9.6 exactly, including the two RC-7-added rows.

---

### T-010 — Tests: cross-layer integration and security test suite

**Description:** The integration tests that exercise multiple layers together and cannot be owned by any single implementation task above. This is deliberately one task, not one per scenario, so the shared Testcontainers/`TestcontainersConfiguration` fixture setup happens once.

Must include, at minimum:
- `RoleManagementIT` — Scenarios 1–4, 7 + 404 branches + 404-on-never-attached `DELETE`
- `RolePermissionSecurityIT` — Scenarios 5, 6, 9, 10, with a second non-bootstrap tenant **and** a tenant with no seeded `TENANT_ADMIN`; **RC-5b named cases:** attach `role:write` to seeded `MEMBER` → 409 `RBAC_003`; detach `user:read` from seeded `MEMBER` → 409 `RBAC_003`
- `RoleManagementAdminGateIT` — AC11 including **the concurrent admin-revocation case** — the only test in the entire story that distinguishes the mandated locking read from the forbidden non-locking shortcut. **Non-negotiable, per Gate 2's recommendation §8.**
- `RolePermissionsPrivilegeIT` — as `nexus_app`: `INSERT INTO roles` succeeds, `UPDATE roles` denied, `INSERT`/`DELETE` on `role_permissions` succeed, `UPDATE role_permissions` denied. **Non-negotiable** — the only test catching a production-only `Role` dirty-flush.
- `RoleManagementAuditIT` — Scenarios 11–14 including Scenario 14's negative assertion
- `RoleNameUniquenessConcurrencyIT` — concurrent duplicate + cross-tenant-same-name + the F10 accent case
- **RC-1:** role creation named `TENANT_ADMIN`/`MEMBER` (any case) → 409 `RBAC_007`, in both a tenant with seeded system roles and one without
- **RC-4:** the (cap+1)th role creation in a tenant → 409 `RBAC_008`; a second tenant unaffected
- **RC-7:** `RoleAssignmentEscalationIT` (new) — (a) any self-assignment increments `nexus.rbac.self_role_assignment` regardless of the role's permissions; (b) the composed scenario (admin attaches a dangerous permission, non-admin self-assigns that role) leaves both counters incremented and the assignment still succeeding

**Dependencies:** T-002, T-003, T-005, T-006 (needs the full stack to exist)
**Files impacted:** none
**Files created:** `RoleManagementIT.java`, `RolePermissionSecurityIT.java`, `RoleManagementAdminGateIT.java`, `RolePermissionsPrivilegeIT.java`, `RoleManagementAuditIT.java`, `RoleNameUniquenessConcurrencyIT.java`, `RoleAssignmentEscalationIT.java`
**Complexity:** L
**Risks:** Shared-fixture caveats (design §11.2): all `*IT` sharing `@Import(TestcontainersConfiguration.class)` share one cached context and one MySQL schema for the whole run. Every fixture role must be `is_system_role = false` with a **randomised name**, or AC9's own tests collide non-deterministically with other suites; resolve `TENANT_ADMIN` by `(tenant_id, name)`, never the seeded literal (US-012's R-9).
**Testing requirements:** This task *is* the testing requirement for the cross-layer paths. e2e/load: none required — no load-scenario ACs in this story (see design §1 non-goals: no rate limiting requirement).
**Definition of Done:** All listed ITs exist and pass; `./mvnw verify` (not `-DskipITs`) is green; the two non-negotiable ITs (`RoleManagementAdminGateIT`'s concurrent case, `RolePermissionsPrivilegeIT`) are confirmed present in the PR diff, not merely planned.

---

### T-011 — Documentation: `SECURITY.md` error-code register + `CHANGELOG.md`

**Description:** Register `RBAC_001`–`RBAC_008` in a new "RBAC error code register" table in `SECURITY.md` §3.1 (closing F4 — the missing-registry root cause identified at Gate 1). Add the `CHANGELOG.md` entry at merge, matching how `RBAC_002`/`RBAC_004` were announced.

**Dependencies:** T-001 (needs all 5 new exceptions/codes finalized)
**Files impacted:** `SECURITY.md`, `CHANGELOG.md`
**Files created:** none
**Complexity:** S
**Risks:** None significant — this is bookkeeping, but it's the specific bookkeeping whose absence caused F4 (AC9's error code going unassigned at Gate 1). Don't skip it as "just docs."
**Testing requirements:** None.
**Definition of Done:** `SECURITY.md` §3.1 lists all 8 RBAC codes with status, meaning, and owning story; `CHANGELOG.md` entry present at merge.

---

### T-012 — Documentation/process: close out Gate 2's remaining conditions before merge

**Description:** Not a code task. Tracks the two Gate 2 conditions that can't be closed by an engineer writing code:
1. **C2** — get a named individual (not the current role placeholder) recorded as owner of the D15/R-3 risk acceptance in `03-design.md` §10.2, with sign-off before this story's PR merges.
2. **C3** — confirm `docs/story/2-rbac/US-016.md` (already filed) is acknowledged by PM/Architect as the tracked successor, and that it becomes P0 automatically the first time the RC-7 composed alert fires (a process commitment, not a code change).

**Dependencies:** none (can run in parallel with all engineering tasks; must complete before merge, not before `/implement` starts)
**Files impacted:** `docs/features/US-015/03-design.md` (§10.2 owner field only)
**Files created:** none
**Complexity:** S
**Risks:** This is the one task that requires a human decision outside the engineering loop. If it stalls, it blocks merge (per Gate 2 recommendation #2/#3), not implementation — flag early rather than discovering it at PR time.
**Testing requirements:** None.
**Definition of Done:** §10.2's owner field names a person; `US-016.md`'s status is acknowledged in the PR description as the tracked successor per C3.

**Resolution (closed 2026-09-07):**
- **C2** — owner named: **Md Nisar Ahmed (nisar.a@entomo.co)**, RBAC bounded-context tech lead. Recorded in `03-design.md` §10.2 and `03b-threat-model.md` §4.5 (accountable-owner field, RES-1 register row, and the Gate 2 recommendation checklist), replacing the role placeholder.
- **C3** — `docs/story/2-rbac/US-016.md` is filed and stands as the tracked successor per the design's own C3 condition; its status and the P0-on-first-RC-7-alert commitment will be called out explicitly in this story's PR description at merge time, per the DoD above.

---

## Summary

| Task | Layer | Complexity | Depends on |
|---|---|---|---|
| T-000 | Verification | S | — |
| T-001 | Domain | S | T-000 |
| T-002 | Application | L | T-001 |
| T-003 | Infrastructure | M | T-002 |
| T-004 | Infrastructure (audit) | M | T-002 |
| T-005 | Application (US-012 file) | S | T-001 |
| T-006 | Interfaces | L | T-002, T-004 |
| T-007 | Cross-cutting | M | T-002, T-003 |
| T-008 | Cross-cutting | S | T-006, T-005 |
| T-009 | Cross-cutting/Docs | S | T-004, T-005, T-008 |
| T-010 | Tests | L | T-002, T-003, T-005, T-006 |
| T-011 | Documentation | S | T-001 |
| T-012 | Process | S | — |

**Suggested implementation order:** T-000 → T-001 → {T-002, T-005 in parallel} → {T-003, T-004 in parallel} → T-006 → {T-007, T-008 in parallel} → T-010 → T-009 → T-011, with T-012 tracked in parallel throughout and closed before merge.

**Not broken out further, deliberately:** per-endpoint and per-AC tasks were collapsed into T-002/T-006 rather than split, since they share the same guard methods and the same controller-support helper — splitting them would mean reopening the same files repeatedly rather than implementing and validating each layer once.
