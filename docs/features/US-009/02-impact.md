# US-009 — Impact Analysis

_Output of `/impact-analysis` (architect). Feeds Gate 2._

This document maps blast radius for the four Gate-1-decided work streams behind US-009 (see `01-requirements.md` §17). It identifies files, layers, migrations, tests, and unknowns only — it does **not** propose class designs, method signatures, DDL, or solutions. Those belong to Gate 2 (`03-design.md`). The already-Accepted decisions in ADR-0013 (permission naming, `active_key` technique) and ADR-0014 (bootstrap tenant sourcing, `nexus_app` grants) are treated as settled inputs, not reopened.

**Verification basis:** every file referenced below was read directly during this pass. Key as-built facts confirmed:

- **Greenfield confirmed.** Glob for `nexus-backend/src/**/rbac/**` returned **zero files**. No `com.example.nexus.rbac` package exists in main or test source.
- **Migration head is `V4`.** On-disk migrations are exactly `V1__baseline.sql`, `V2__identity_schema.sql`, `V3__add_password_hash_to_users.sql`, `V4__auth_events_add_user_agent.sql`. **`V5__rbac_schema.sql` is the correct next slot** (no in-flight numbering ambiguity — `V4` is real and merged).
- **Reusable infra is genuinely reusable as-is.** `UuidGenerator` is a context-agnostic `@FunctionalInterface` (`identity/domain/UuidGenerator.java:7-9`); `UuidV7Generator` is a plain `@Component` (`identity/infrastructure/crypto/UuidV7Generator.java:9-10`); `UuidV7Converter` is `@Converter(autoApply = true)` — **persistence-unit-global**, applies to *any* `UUID` field in any package (`identity/infrastructure/persistence/UuidV7Converter.java:12`). None need recreation.
- **`User.java` is the entity template** (`identity/domain/User.java`): `@Id` `UUID id` mapped `columnDefinition = "BINARY(16)"` with **no `@GeneratedValue`** (lines 22-24); `@Version long version` (64-66); `created_at`/`updated_at` as `Instant` with `insertable = false, updatable = false` (68-72); `@NoArgsConstructor(access = PROTECTED)` + `@Getter` (18-19); enums via `@Enumerated(EnumType.STRING)` (45-47). `tenant_id` is a **bare `UUID` column with no JPA relationship** (26-27) — the exact pattern RBAC's cross-context ID columns should follow.
- **Trigger precedent is `V2__identity_schema.sql:92-110`** — `BEGIN … SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = '…'; END;`, with the inline comment (lines 94-96) that the `BEGIN/END` wrapper is mandatory on MySQL 8.4 via JDBC. `auth_events` has **both** `no_update` and `no_delete` triggers; `user_roles` must copy **only** the DELETE one.
- **`application.yml:105` has NO fallback today** (verified): `default-tenant-id: ${NEXUS_IDENTITY_DEFAULT_TENANT_ID}`. The literal `00000000-0000-7000-8000-000000000001` currently lives only in `application-dev.yml:40` and `TestcontainersConfiguration.java:167-168`.
- **All three grant artifacts list exactly `auth_events`, `users`, `refresh_tokens`, `auth_tokens` and none of the 4 RBAC tables** (verified): `nexus-database/mysql/init/02-grants-post-schema.sql:22-28`; `TestcontainersConfiguration.nexusAppGrantsCallback` (`:119-129`); `docs/runbooks/nexus-app-provisioning.md:67-73` (+ the `SHOW GRANTS` expected-output block at `:87-95`).
- **`docker-compose.yml` `full` profile is real and verified:** `backend` connects as `DB_USERNAME: nexus_app` (`:74`); a one-shot `flyway-migrate` service runs migrations as root then applies `02-grants-post-schema.sql` as `afterMigrate.sql` (`:39-63`). This is the exact path AC9's mandatory smoke check exercises.
- **ArchUnit rules already cover `rbac.*` with zero config:** `HexagonalArchitectureTest.java:18-58` scopes generic `..domain..`/`..application..`/`..infrastructure..`/`..interfaces..` rules to `com.example.nexus` with `allowEmptyShould(true)` (comment `:15-16`).
- **The DB-privilege health indicator is NOT affected by the new grants — verified.** It checks only table-scoped `UPDATE`/`DELETE`/`ALL PRIVILEGES` on `auth_events` specifically (`AUDIT_TABLE = "auth_events"`, `AuthEventDbPrivilegeHealthIndicator.java:47,121-125`) plus any **global** grant (`:142-144`). Table-scoped grants on the 4 RBAC tables are invisible to it — confirmed by reading the indicator's SQL directly.

---

## 1. Work Stream Overview & Sizing

| WS | Gate-1 decision | Primary layers | Size | Risk |
|----|-----------------|----------------|------|------|
| **WS-1** `V5__rbac_schema.sql` — 4 tables + indexes + seed DML + DELETE trigger | AC1-7, OQ-1/2/3/5 | infrastructure (DB) | **L** | **Medium — highest in story** (net-new `active_key` generated-column technique + 9 hand-written UUIDv7 literals + FK ordering + seed correctness) |
| **WS-2** JPA entities + Spring Data repositories | AC8, OQ-6 | domain + infrastructure/persistence | **M** | Low–Medium (read-only generated column under `ddl-auto=validate`) |
| **WS-3** `application.yml` default-tenant-id fallback | OQ-3 / ADR-0014 D5 | config (no Java) | **S** | Low (one line, but load-bearing for AC3 correctness) |
| **WS-4** `nexus_app` grants × 3 artifacts + docker-compose `full` smoke check | AC9, OQ-4 / ADR-0014 D6 | infra/ops config + test config + runbook | **M** | **Medium–High** (Testcontainers CI structurally cannot detect a miss; correctness rests on the manual smoke check) |

**Almost everything is a *create*, not a *modify*** — the inverse of a gap-closure story. WS-1 and WS-2 are entirely new files in a new package + a new migration. Only WS-3 (1 file) and WS-4 (3 files) touch existing artifacts. All DDL is **additive/expand-only** (ADR-0003); **no expand/contract sequencing** is required (greenfield tables, no reshaping of existing columns).

---

## 2. WS-1 — `V5__rbac_schema.sql` (schema + seed + trigger)

The single largest work item. One net-new Flyway file creating 4 tables, their indexes/constraints, ~17 seed rows, and one trigger.

### Files created
| File | Layer | Note |
|------|-------|------|
| `nexus-backend/src/main/resources/db/migration/V5__rbac_schema.sql` | infrastructure (DB) | All 4 tables, FK ordering `permissions`/`roles` → `role_permissions`/`user_roles`, `active_key` generated column + `uq_user_role_active`, `trg_user_roles_no_delete`, and all seed DML. |

### Sub-components inside the one file
- **4 tables** per the story's Explicit Column Lists, all temporal columns `DATETIME(6)` (OQ-1 resolved — matches `V2` exactly; `roles.updated_at` carries `ON UPDATE CURRENT_TIMESTAMP(6)` mirroring `users.updated_at` at `V2:25`).
- **`active_key BINARY(32)` STORED generated column + `UNIQUE INDEX uq_user_role_active`** (ADR-0013 D2). Net-new technique — no generated column exists anywhere in `V1`–`V4`.
- **`trg_user_roles_no_delete`** — copy the `BEGIN … SIGNAL SQLSTATE '45000' … END;` shape from `V2:105-110`, **DELETE only**. Deliberately asymmetric vs. `auth_events` (which also blocks UPDATE) because `revoked_at` is set via UPDATE. This is the single most important "don't over-copy the precedent" point for the implementer (requirements Gap 2).
- **Cross-context FKs at the DB level:** `role_permissions.role_id/permission_id` → RBAC tables; `user_roles.user_id/assigned_by` → `users(id)`, `user_roles.role_id` → `roles(id)`. `roles.tenant_id`/`user_roles.tenant_id` are **bare `NOT NULL BINARY(16)` with no FK** — matching `users.tenant_id` (`V2:14`), because no `tenants` table exists yet.
- **Seed DML:** 7 `permissions`, 2 `roles`, 8 `role_permissions` (7 for `TENANT_ADMIN` + 1 for `MEMBER`). PKs are **hand-authored, format-valid UUIDv7 literals** (OQ-2 resolved) documented in the file header. `roles.tenant_id` = `0x…000000000001` (the sentinel; OQ-3 resolved, paired with WS-3).

### Tests created (new `*IT`, mirroring existing patterns)
Existing precedents: `IdentitySchemaMigrationIT` (`@SpringBootTest` + `@Import(TestcontainersConfiguration.class)` + `JdbcTemplate`, asserts tables/columns via `information_schema`) and `AuthEventsAppendOnlyIT` (asserts trigger via `assertThatThrownBy(...).hasMessageContaining("append-only")`).

| New test | Covers | Maps to |
|----------|--------|---------|
| `RbacSchemaMigrationIT` | clean V1→V5, all tables/columns/indexes present, seed counts, join queries (`TENANT_ADMIN`=7 perms, `MEMBER`=`user:read` only) | AC1-3, AC7; Test Scenarios 1, 5, 6 |
| `UserRolesAppendOnlyIT` | single-row DELETE → `45000`; **multi-row DELETE → whole-statement abort, 0 rows** (OQ-5); `UPDATE revoked_at` **succeeds** (asymmetry proof) | AC4; Test Scenarios 4, 9 |
| `RoleUniquenessIT` / `ActiveAssignmentIT` | dup role name same tenant fails, diff tenant ok; second active `(user,role)` collides on `active_key`; revoke-then-reassign ok; **two concurrent inserts → exactly one wins** | AC5, AC6; Test Scenarios 2, 3, 7, 8, 10 |

Test Scenario 10 (concurrency) is the one that needs real thread-level exercise — mirror `SecureEventServiceConcurrencyTest`'s approach at Gate 3.

### Risk / sizing — **L, Medium risk.** No runtime code, but the generated-column technique is new to this schema, the 9 UUIDv7 literals must be hand-verified for correct version/variant nibbles, and the DELETE-only trigger asymmetry is an easy-to-get-wrong divergence from the copied precedent.

---

## 3. WS-2 — JPA Entities + Spring Data Repositories

Per OQ-6/AC8: entities + repositories **only**. No application services, no ports (`application/port/out`), no adapters, no DTOs, no controllers — those serve consumers (US-010/012/015) that are out of scope.

### Files created
| File | Layer | Note |
|------|-------|------|
| `rbac/domain/Permission.java` | domain | `@Id UUID` BINARY(16) (no `@GeneratedValue`), `name` unique, `description`, `created_at` read-only. Mirrors `User.java` conventions. |
| `rbac/domain/Role.java` | domain | + `tenant_id` (bare UUID), `is_system_role`, `updated_at` (read-only, DB-managed). **Design note:** whether `Role` needs `@Version` is an open item — see §10 / requirements Gap 9. |
| `rbac/domain/RolePermission.java` | domain | Composite PK `(role_id, permission_id)` via `@EmbeddedId` or `@IdClass` + `created_at`. **Must be a first-class `@Entity`, not a JPA `@ManyToMany` join table** — the table carries `created_at`, and `ddl-auto=validate` requires the mapping to match the real column set. |
| `rbac/domain/UserRole.java` | domain | `@Id UUID`; `user_id`/`role_id`/`tenant_id`/`assigned_by` as bare UUIDs; `assigned_at`, nullable `revoked_at`; **`active_key` mapped `byte[]` with `insertable = false, updatable = false`** (AC8). |
| `rbac/infrastructure/persistence/JpaPermissionRepository.java` | infrastructure | `extends JpaRepository<Permission, UUID>` (mirrors `JpaUserRepository:12`). |
| `rbac/infrastructure/persistence/JpaRoleRepository.java` | infrastructure | `extends JpaRepository<Role, UUID>`. |
| `rbac/infrastructure/persistence/JpaUserRoleRepository.java` | infrastructure | `extends JpaRepository<UserRole, UUID>`. |
| `rbac/infrastructure/persistence/JpaRolePermissionRepository.java` | infrastructure | `extends JpaRepository<RolePermission, RolePermissionId>` — see repository-count reasoning below. |

**Repository-count decision (4 entities, 4 repositories — recommended).** All 4 tables are modeled as first-class entities (none can be a mapped-collection-only join, because `role_permissions` carries `created_at` and `user_roles` carries the generated `active_key` — both must be explicit under `ddl-auto=validate`). On repositories: `JpaRolePermissionRepository` is the only genuinely *optional* one, since role→permission resolution could later be expressed as a join from `Role`. Recommend including it anyway because (a) AC8's wording is "entities (+ Spring Data repositories)" with `RolePermission` named as one of the four, (b) US-015 detaches permissions (`DELETE role_permissions`) and a composite-key repository is the cleanest surface for that, and (c) the marginal cost is one interface. Gate 2 may drop it if it prefers join-from-`Role` resolution — state whichever it picks.

**No ports/adapters this story.** In `identity`, ports (`application/port/out/*Port.java`) + adapters (`infrastructure/persistence/Jpa*Adapter.java`) exist to insulate *application services* from persistence. US-009 ships no application services, so introducing ports now would create unused abstractions. The Spring Data repositories are the entire persistence surface for this story; the port/adapter layer arrives with the first consuming use-case (US-010/012).

### Key mapping hazards for Gate 2
- **`active_key` under `ddl-auto=validate`:** must be `byte[]` (BINARY(32)), never `UUID` — it is `CONCAT(user_id, role_id)` = 32 bytes, and `UuidV7Converter` (`autoApply=true`, UUID-typed only) correctly leaves `byte[]` untouched. Mapping it `insertable=false, updatable=false` (and likely `@org.hibernate.annotations.Generated`) so Hibernate never tries to write it. Getting this wrong fails schema validation at boot.
- **Cross-context references stay ID-only.** `UserRole` holds `user_id`/`assigned_by` as `UUID`, **not** `@ManyToOne` to `identity.domain.User` — matching `User.tenant_id` and avoiding cross-bounded-context entity coupling. The DB FK constraint lives in the migration; the JPA layer knows only the IDs.

### Tests created
| New test | Covers |
|----------|--------|
| `rbac` repository slice or `*IT` (save/find round-trip for all 4 entities via the container's `test` user) | AC8 — proves mappings match the migrated schema under `ddl-auto=validate` |
| No new ArchUnit test | `HexagonalArchitectureTest` picks up `rbac.*` automatically (`:18-29`) |

### Risk / sizing — **M, Low–Medium risk.** Mechanical mirroring of a proven template; the only real hazards are the read-only generated-column mapping and the composite-key `RolePermission`.

---

## 4. WS-3 — `application.yml` default-tenant-id Fallback (ADR-0014 D5)

The smallest work stream — one line — but load-bearing for AC3 correctness.

### Files modified
| File | Layer | Change |
|------|-------|--------|
| `nexus-backend/src/main/resources/application.yml` | config | `:105` `default-tenant-id: ${NEXUS_IDENTITY_DEFAULT_TENANT_ID}` → `${NEXUS_IDENTITY_DEFAULT_TENANT_ID:00000000-0000-7000-8000-000000000001}`. Makes "migration seed literal" and "runtime default tenant" the same value by construction. |

### Files deliberately NOT changed
- `application-dev.yml:40` and `TestcontainersConfiguration.java:167-168` already hardcode the identical literal — no change needed; the base fallback simply makes them redundant-but-consistent.
- The stale comment at `application.yml:104` ("Must be set in all non-smoke envs") is now weaker (a default exists) — a one-line comment refresh is optional polish, not required.

### Drift risk to record
ADR-0014 D5 accepts a residual: the migration literal and the config fallback can drift if either changes alone. Mitigation is documentation-only (both live in ADR-0014 + the story) — flag for the PR checklist, not a code control.

### Tests
None new. Existing `application-dev`/Testcontainers behavior is unchanged (they already supply the literal). A context-load smoke test transitively exercises the fallback.

### Risk / sizing — **S, Low risk.** One line. The risk is entirely "forget to do it," which would silently scope seeded roles to a tenant the app never resolves at runtime (AC3 failure surfacing only in Epic 3).

---

## 5. WS-4 — `nexus_app` Grants × 3 Artifacts + docker-compose Smoke Check (ADR-0014 D6, AC9)

The grant shape (ADR-0014 D6) is fixed: `permissions` SELECT; `roles` SELECT,INSERT; `role_permissions` SELECT,INSERT,DELETE; `user_roles` SELECT,INSERT,UPDATE (**no DELETE** — defense-in-depth on top of the trigger). This must be added to **all three** provisioning artifacts identically, applied *after* `V5` runs (GRANT on a not-yet-created table fails `ERROR 1146`).

### Files modified
| File | Layer | Change |
|------|-------|--------|
| `nexus-database/mysql/init/02-grants-post-schema.sql` | infra/DB | Add 4 GRANT lines before `FLUSH PRIVILEGES` (`:30`). Runs via the `flyway-migrate` `afterMigrate.sql` callback. |
| `nexus-backend/src/test/java/com/example/nexus/TestcontainersConfiguration.java` | test config | Add 4 `statement.execute("GRANT …")` lines in `nexusAppGrantsCallback` (`:119-129` region, before the `FLUSH PRIVILEGES` at `:129`). |
| `docs/runbooks/nexus-app-provisioning.md` | ops doc | Add the 4 grants to Step 2 (`:67-73`); update the "What this runbook provisions" bullets (`:16-18`); **update the `SHOW GRANTS` expected-output block (`:87-95`)** — currently "four lines," becomes eight. |

### The mandatory smoke check (AC9)
Testcontainers ITs run the general app connection as the container's **default `test` user**, not `nexus_app` (`TestcontainersConfiguration.java:24-32`) — so a green IT suite **cannot** detect a missing RBAC grant. AC9 therefore requires a `docker compose --profile full up` run (backend connects as `nexus_app`, `:74`) plus a runtime RBAC read/write, verified manually or via a scripted check, as an explicit Definition-of-Done gate. This is a process/checklist artifact, not a code file. Flag it prominently at Gate 3 so it isn't silently skipped — it is the *only* automated-adjacent defense against the story's own Critical-severity risk.

### Blast radius that is NOT affected (verified)
`AuthEventDbPrivilegeHealthIndicator` (`:118-151`) only counts `UPDATE`/`DELETE`/`ALL PRIVILEGES` on **`auth_events`** (table-scoped) and any **global** grant. The new RBAC grants are table-scoped to the four RBAC tables and include no global grant, so the indicator's drift signal is **unchanged** — the `user_roles` UPDATE grant does not trip it. `AuthEventsPrivilegeAppendOnlyIT` asserts against `auth_events` only and is likewise unaffected. No existing grant-related test needs editing.

### Risk / sizing — **M, Medium–High risk.** No logic risk, but three artifacts must stay byte-for-byte consistent, and the safety net is a manual smoke step CI can't enforce. Strongest candidate in this story for a Gate-3 checklist item.

---

## 6. Database / Migration Impact (consolidated)

| Change | Type | Owner WS |
|--------|------|----------|
| Create `permissions`, `roles`, `role_permissions`, `user_roles` | **Additive** (ADR-0003) | WS-1 |
| `active_key` STORED generated column + `uq_user_role_active` unique index | Additive; net-new MySQL technique | WS-1 |
| `trg_user_roles_no_delete` (DELETE-only, asymmetric vs. `auth_events`) | Additive trigger | WS-1 |
| Seed DML: 7 permissions + 2 roles + 8 role_permissions, UUIDv7-literal PKs | Additive data | WS-1 |
| Cross-context DB FKs to `users(id)` | Additive constraint | WS-1 |
| `nexus_app` GRANTs on 4 tables (out-of-band, per ADR-0012 §2 / ADR-0014 D6) | DDL, **environment-specific, NOT in the Flyway file** | WS-4 |

**Single migration `V5__rbac_schema.sql`.** All changes additive/expand-only — **no expand/contract** needed (greenfield tables; no existing column reshaped, no data backfill). `ddl-auto=validate` means the four JPA entities (WS-2) must land in the same change as `V5` or boot-time schema validation fails. Grants are explicitly **out of the migration** — they are out-of-band DDL applied after migrate, exactly as ADR-0012 established for the identity tables.

**No non-additive change** anywhere; nothing to flag for expand/contract.

---

## 7. Cross-Cutting Impact

### API impact
**None.** No REST controllers, DTOs, endpoints, or status codes in this story. RBAC endpoints arrive with US-012 (assignment) and US-015 (role management). No versioning question.

### Frontend impact
**None.** No `nexus-frontend/` files touched. No routes, components, services, guards, or state. Role-management UI is Epic 3.

### Security impact
- **Tenant isolation at the DB layer** — `roles UNIQUE (tenant_id, name)` (AC5), consistent with "server-side enforced."
- **Append-only `user_roles`** via trigger (AC4) mirrors the `auth_events` audit rationale; the deliberate DELETE-only asymmetry preserves the `revoked_at` soft-delete path.
- **Least-privilege grants (WS-4)** extend ADR-0012's posture to 4 more tables, sized per actual read/write pattern; `user_roles` gets no DELETE grant (defense-in-depth atop the trigger).
- **Residual, explicitly accepted (ADR-0014 D6):** Testcontainers can't exercise `nexus_app`, so a grant mistake is invisible to CI — AC9's smoke check is the compensating control. Not a new attack surface, but a real detection gap to state in the threat-model handoff.
- No new authn/authz enforcement code (that is US-011); no PII, no secrets in seed data.

### Performance impact
- **No runtime hot path** — schema-only. No RPS/latency target applies.
- `role_permissions` composite PK `(role_id, permission_id)` serves role→permission lookups; **no secondary index on `permission_id` alone** — a future reverse lookup ("which roles grant X") would table-scan. Not a defect for this story; flag for whoever needs it (requirements §7).
- No N+1 risk introduced (no query code). No cache touches — Nexus uses no Redis today; nothing here proposes adding it (ADR-0013 D4's cache discussion is about US-015, not this story).
- Migration execution time is trivial (~17 seed rows); no CI budget stated (requirements Gap 1) — acceptable to leave unset for a seed-only migration.

### Observability impact
**None new.** No runtime code executes, so no new logs, metrics, or traces. This is a legitimate absence, not a skipped plan: there is no operable runtime surface in US-009. The first observability additions land with US-010/US-011 (enforcement). The only operational signal in scope is the AC9 smoke check, a pre-ship verification step, not a continuous metric.

### Dependency impact
**Zero new dependencies.** `uuid-creator` (ADR-0005) is already present and reused via the existing `UuidGenerator`/`UuidV7Generator`. No new libs, no version bumps, no license review.

### Backward compatibility
- **Fully additive.** New package, new tables, new migration. Nothing existing is renamed or reshaped.
- **`application.yml` fallback (WS-3)** is backward-compatible: environments that set `NEXUS_IDENTITY_DEFAULT_TENANT_ID` are unaffected; only those relying on the (previously absent) default gain behavior.
- **Grant additions (WS-4)** are additive `GRANT`s — idempotent and non-breaking for existing tables.
- No data migration needed (no shape change; seed data is fresh inserts).

---

## 8. ADR Recommendations

| Candidate | Recommendation |
|-----------|----------------|
| RBAC data model, `active_key` technique, permission naming | **No new ADR — ADR-0013 (Accepted) governs this.** WS-1 implements D1/D2; D3/D4 are for later stories. |
| Bootstrap tenant sourcing (WS-3) + `nexus_app` grants (WS-4) | **No new ADR — ADR-0014 (Accepted) governs this.** WS-3 = D5, WS-4 = D6, verbatim. |
| `DATETIME(6)` / UUIDv7-literal / DELETE-only-trigger / entities-in-scope decisions | **No ADR — resolved at Gate 1 (§17 OQ-1/2/5/6).** Capture the seed UUIDv7 literals and the trigger-asymmetry note in `03-design.md`, not a new ADR. |
| **Anything genuinely new requiring a new ADR** | **None found.** No architecturally-significant decision surfaced in this blast-radius pass that Gate 1 / ADR-0013 / ADR-0014 didn't already close. The `Role`/`user_roles` optimistic-locking (`@Version`) question (requirements Gap 9) is a design-detail-level choice for Gate 2, not ADR-worthy on its own — decide it in `03-design.md`. |

ADRs 0001–0014 are in use. **No next free number is needed** for this story.

---

## 9. Blast-Radius File List (quick reference)

**Production — create:**
`db/migration/V5__rbac_schema.sql`;
`rbac/domain/Permission.java`, `rbac/domain/Role.java`, `rbac/domain/RolePermission.java` (+ composite-id `RolePermissionId`), `rbac/domain/UserRole.java`;
`rbac/infrastructure/persistence/JpaPermissionRepository.java`, `JpaRoleRepository.java`, `JpaRolePermissionRepository.java`, `JpaUserRoleRepository.java`.

**Production — modify:**
`application.yml` (`:105`, default-tenant-id fallback);
`nexus-database/mysql/init/02-grants-post-schema.sql` (add 4 grants).

**Test / infra config — modify:**
`TestcontainersConfiguration.java` (add 4 grants in `nexusAppGrantsCallback`).

**Docs — modify:**
`docs/runbooks/nexus-app-provisioning.md` (grants + `SHOW GRANTS` expected output).

**Tests — create:**
`RbacSchemaMigrationIT`, `UserRolesAppendOnlyIT` (incl. multi-row DELETE + UPDATE-permitted), role-uniqueness / active-assignment / concurrency `*IT`, RBAC repository round-trip test.

**Process artifact — create/track:**
docker-compose `full`-profile grant smoke check (AC9) — Gate-3 checklist item, not a code file.

**Reused as-is (no change):**
`UuidGenerator.java`, `UuidV7Generator.java`, `UuidV7Converter.java`, `HexagonalArchitectureTest.java`.

**Unaffected (verified):**
all `nexus-frontend/`; all existing REST DTOs/controllers; `V1`–`V4` migrations and the `auth_events` triggers; `AuthEventDbPrivilegeHealthIndicator` + `AuthEventsPrivilegeAppendOnlyIT` (RBAC grants are table-scoped, no global, so they don't register as drift).

---

## 10. Open Unknowns for Gate 2 (design details — scope is closed)

These are implementation-shape choices, **not** the scope questions OQ-1–OQ-6 (all closed at Gate 1 §17). None reopens settled scope.

1. **`RolePermission` composite key style** — `@EmbeddedId` (with a `RolePermissionId` value object) vs. `@IdClass`. Pick one in `03-design.md`.
2. **`RolePermissionRepository` inclusion** — keep it (recommended, satisfies AC8 wording + US-015 detach surface) or resolve role→permission by join-from-`Role`. Default: keep.
3. **`active_key` mapping mechanics under `ddl-auto=validate`** — confirm `byte[]` + `insertable=false, updatable=false` (+ likely `@org.hibernate.annotations.Generated`) passes Hibernate schema validation against a STORED generated `BINARY(32)` column. Highest-value thing to prototype early.
4. **`@Version` on `Role`/`user_roles`?** (requirements Gap 9) — every other mutable table carries one; `user_roles` mutates only via `revoked_at`, `roles` never mutates in Epic 2's scope. Decide explicitly (default: omit, since no in-scope UPDATE path needs optimistic locking) and record the reasoning.
5. **`roles.updated_at ON UPDATE` value** (requirements Gap 8) — the column exists per the spec, but nothing in Epic 2 issues a `roles` UPDATE; confirm it's intentional forward-looking capability, not accidental.
6. **Within-context relationships** — whether `RolePermission`/`UserRole` map `role_id`/`permission_id` as bare UUIDs (recommended, for consistency with the cross-context ID-only pattern and minimal scope) or as `@ManyToOne` (architecturally permissible within one context). Default: ID-only.
7. **Concurrency test mechanics** (Test Scenario 10) — thread-pool harness shape; mirror `SecureEventServiceConcurrencyTest`.

---

## 11. What This Story Unblocks (dependency edges only — not analyzed here)

Per the epic, US-009's output is a hard gate. Noting the edges, **not** analyzing downstream impact:

- **US-010** (JWT permission population) — first *runtime reader* of `roles`/`role_permissions`/`user_roles`; the natural deadline for the WS-4 grants to be correct and smoke-verified. Needs the WS-2 repositories + WS-4 SELECT grants.
- **US-012** (assignment API) — first *writer* to `user_roles` (INSERT assign, UPDATE revoke); depends on the `active_key` uniqueness + DELETE trigger + `user_roles` SELECT/INSERT/UPDATE grant landing here.
- **US-015** (role management API) — first *mutator* beyond seed data (`roles` INSERT, `role_permissions` INSERT/DELETE); depends on those tables + grants + the `is_system_role` flag being seeded correctly for immutability enforcement.
- **Epic 3 (Tenant Management) kickoff** — hard-gated on `TENANT_ADMIN` existing and being correctly tenant-scoped (AC3 + WS-3 together). This is the epic-level go/no-go.

---

### File paths referenced (all absolute)
- Requirements: `C:\entomo\AI\nexus\docs\features\US-009\01-requirements.md`
- Story: `C:\entomo\AI\nexus\docs\story\2-rbac\US-009.md`
- ADRs: `C:\entomo\AI\nexus\docs\adr\0013-rbac-data-model-and-enforcement-contract.md`, `C:\entomo\AI\nexus\docs\adr\0014-rbac-bootstrap-tenant-and-db-grants.md`, `C:\entomo\AI\nexus\docs\adr\0012-least-privilege-runtime-db-user-for-auth-events.md`
- Format precedent: `C:\entomo\AI\nexus\docs\features\US-008\02-impact.md`
- Entity template: `C:\entomo\AI\nexus\nexus-backend\src\main\java\com\example\nexus\identity\domain\User.java`
- Reused infra: `...\identity\domain\UuidGenerator.java`, `...\identity\infrastructure\crypto\UuidV7Generator.java`, `...\identity\infrastructure\persistence\UuidV7Converter.java`
- Repository template: `...\identity\infrastructure\persistence\JpaUserRepository.java`
- Migrations: `C:\entomo\AI\nexus\nexus-backend\src\main\resources\db\migration\V2__identity_schema.sql` (triggers `:92-110`), `V4__auth_events_add_user_agent.sql`
- Config: `...\resources\application.yml` (`:105`), `application-dev.yml` (`:40`)
- Grants: `C:\entomo\AI\nexus\nexus-database\mysql\init\02-grants-post-schema.sql`, `...\test\java\com\example\nexus\TestcontainersConfiguration.java` (`:100-143`, `:167-168`), `C:\entomo\AI\nexus\docs\runbooks\nexus-app-provisioning.md`
- ArchUnit: `...\test\java\com\example\nexus\architecture\HexagonalArchitectureTest.java`
- docker-compose: `C:\entomo\AI\nexus\docker-compose.yml` (`:39-82`)
- Test precedents: `...\identity\infrastructure\persistence\IdentitySchemaMigrationIT.java`, `AuthEventsAppendOnlyIT.java`, `AuthEventsPrivilegeAppendOnlyIT.java`; `...\identity\infrastructure\audit\AuthEventDbPrivilegeHealthIndicator.java`
