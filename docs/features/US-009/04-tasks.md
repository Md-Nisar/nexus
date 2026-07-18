# US-009 — Task Breakdown

_Output of `/breakdown` (architect + backend-engineer + qa-engineer). Gate 3 deliverable. Turns the approved, Gate-2-amended design (`03-design.md`, incl. the ADR-0015 threat-model hardening) and threat model (`03b-threat-model.md`) into a sequenced, implementable task list. No design decisions are re-opened here._

**Test-first.** Backend tasks use Spring Boot 4 / Java 25 / JUnit 5 + Testcontainers MySQL 8.4 conventions (no H2 for `*IT`, per docs/TESTING.md). Owner role is `backend-engineer` or `qa-engineer` only.

**Explicitly N/A for this story (stated once, not padded):** no frontend (`03-design.md` §7 — zero `nexus-frontend/` files, no routes/components/services/guards); no `application/` or `interfaces/` layer (§1.2 — no use-cases, ports, adapters, controllers, or DTOs); no API contract (§7); no caching / Redis (§7); no runtime observability surface (§7 — the only operational signal is the AC9 smoke check); **no feature flag** (§8.2 — schema-only, no runtime behavior to gate); **no ADR-writing task** — ADR-0013, ADR-0014, ADR-0015 are all already Accepted (§9), unlike the US-008 precedent where writing the ADRs was part of the breakdown; **no `application.yml` change** — WS-3 is a deliberate no-op per ADR-0015 D8 (§5), and its *absence* is a verification item in the DoD, not a task.

**This story is almost entirely file-creation** (one migration, 4 entities + 1 `@IdClass` helper + 4 repositories, 5 new `*IT`s), plus additive grants to 3 existing provisioning files and one manual smoke gate. Task count is deliberately small (9).

**Two hard atomic couplings drive sequencing:**
1. **`V5__rbac_schema.sql` + the 4 entities + repositories must land in one PR** (`03-design.md` §3, §10.1) — `ddl-auto=validate` fails boot if the mappings and the schema disagree, and AC3's seeded `tenant_id` must equal the runtime default "by construction." T-09-01 and T-09-02 are therefore one atomic PR, sequenced (schema first, mappings against it), not independently schedulable.
2. **The `nexus_app` grants must change 3 files together** (`03-design.md` §6.1) — a partial landing produces an inconsistent grant surface that only the AC9 smoke check (not CI) can catch. T-09-08 is one task spanning all three artifacts.

**Size legend:** S = <0.5d, M = 0.5–1.5d, L = 1.5–3d. **Risk** flagged per task; the `active_key` `byte[]` mapping under `validate` (T-09-02) and the AC9 grant smoke gate (T-09-09, the *only* detection for the story's own Critical-severity grant gap) carry the highest risk.

---

## Task Map

```
T-09-01 (V5__rbac_schema.sql: 4 tables + active_key STORED gen col + uq index
         + revoked_at CHECK + DELETE-only trigger + seed DML w/ 9 UUIDv7 literals)   -- FIRST (DDL/validate coupling)
   |
   +--> T-09-02 (Permission/Role/RolePermission(+RolePermissionId)/UserRole entities
   |             + 4 Spring Data repositories)              [needs 01; SAME PR as 01 -- ddl-auto=validate]
   |
   +--> T-09-03 (RbacSchemaMigrationIT: tables/cols/indexes, seed counts 7/2/8,
   |             TENANT_ADMIN=7 & MEMBER=user:read join queries,
   |             T-E6 "admin holds every permissions row" assertion + convention note)   [needs 01]
   +--> T-09-04 (UserRolesAppendOnlyIT: single- + multi-row DELETE -> 45000;
   |             UPDATE revoked_at succeeds -- asymmetry proof)                            [needs 01]
   +--> T-09-05 (RoleUniquenessIT: dup name same tenant fails; diff tenants both persist) [needs 01]
   +--> T-09-06 (ActiveAssignmentIT: active_key collision; revoke-then-reassign;
   |             concurrent-insert harness; T-T3 explicit-active_key-INSERT rejected)      [needs 01,02]
   +--> T-09-07 (RbacRepositoryRoundTripIT: save/find all 4 entities under validate;
   |             proves active_key byte[] + @IdClass mappings)                             [needs 02]
   |
   +--> T-09-08 (nexus_app grants x3 artifacts: 02-grants-post-schema.sql
            |    + TestcontainersConfiguration.nexusAppGrantsCallback + runbook)          [needs 01; || Wave 2]
            |
            +--> T-09-09 (AC9 docker-compose --profile full grant smoke gate + Scen 12
                          nexus_app UPDATE non-revoked_at DENIED + grant-scope assertion)  [needs 08]
```

---

## WAVE 1 — Schema + mappings (single atomic PR)

### T-09-01 — `V5__rbac_schema.sql` (4 tables + `active_key` + CHECK + DELETE trigger + seed DML)

- **Owner:** backend-engineer
- **Depends on:** none (foundational — must be authored first; `ddl-auto=validate` couples it to T-09-02 in one PR)
- **Size / Risk:** M / Medium (the `active_key` `STORED` generated column, the `uq_user_role_active` NULL-tolerant unique index, and the `BEGIN/END`-wrapped DELETE-only trigger are the non-trivial parts)
- **Files:**
  - **Create** `nexus-backend/src/main/resources/db/migration/V5__rbac_schema.sql` — verbatim per `03-design.md` §2.2: four `CREATE TABLE`s in FK-authoring order (`permissions`, `roles` → `role_permissions`, `user_roles`); all temporal columns `DATETIME(6)` matching V2–V4; `roles.updated_at` carries `ON UPDATE CURRENT_TIMESTAMP(6)` (§3.2, intentional forward-looking parity, never exercised this epic); `active_key BINARY(32) GENERATED ALWAYS AS (CASE WHEN revoked_at IS NULL THEN CONCAT(user_id, role_id) ELSE NULL END) STORED`; `CREATE UNIQUE INDEX uq_user_role_active`; `CONSTRAINT chk_user_roles_revoked_not_before_assigned CHECK (revoked_at IS NULL OR revoked_at >= assigned_at)`; `trg_user_roles_no_delete` (`BEFORE DELETE … BEGIN SIGNAL SQLSTATE '45000' …; END;` — **DELETE only, no BEFORE UPDATE trigger**); seed DML = 7 permissions + 2 roles (both `is_system_role=TRUE`, scoped to bootstrap tenant `00000000-0000-7000-8000-000000000001`) + `role_permissions` (`TENANT_ADMIN` via `INSERT … SELECT id FROM permissions`, `MEMBER` = single `user:read` row), using the 9 format-valid UUIDv7 literals from §2.1 via `UUID_TO_BIN(...)` (default `swap_flag=0`, byte-identical to `UuidV7Converter`).
- **Acceptance criteria:**
  - **AC#:** AC1 (all 4 tables + columns + indexes per explicit lists), AC2 (7 permissions seeded, format-valid UUIDv7 PKs), AC3 (roles seeded, `TENANT_ADMIN` all 7 / `MEMBER` `user:read`, bootstrap tenant), AC4 (DELETE trigger), AC6 (`uq_user_role_active`).
  - **Migration slot (binding pre-check):** confirm the next free Flyway version against current `main` — the design verified head = **V4**, so `V5` is correct; if a newer migration has landed, bump accordingly. Do **not** blind-assume V5.
  - Migration runs cleanly on blank Testcontainers MySQL 8.4; Flyway checksum stable in CI (append-only, ADR-0003 — never edit after first apply).
  - **T-T2 (P1, RESOLVED at Gate 2):** the `chk_user_roles_revoked_not_before_assigned` CHECK constraint is present, and the migration header carries the invariant comment ("revocation is always immediate/past-dated, never scheduled; a future scheduled-revocation feature MUST revisit `active_key`'s definition") — `03-design.md` §2.2, `03b-threat-model.md` T-T2.
  - **T-E5 (P1, documentation):** the migration header records that `is_system_role` is **inert until US-015 AC7** — seeded `TRUE` but read/enforced by nothing in this story; no `role_permissions`-mutation endpoint may ship before US-015's immutability enforcement (`03b-threat-model.md` T-E5).
  - **T-E6 convention seed:** the header documents that every future permission-adding migration MUST also insert the matching `role_permissions` row(s) for `TENANT_ADMIN` (the `INSERT…SELECT` runs once, is a snapshot not a standing rule) — the enforcing test lives in T-09-03 (`03b-threat-model.md` T-E6).
- **Test plan:** exercised end-to-end by T-09-03/04/05/06 (Testcontainers). This task's own gate is "migration applies clean V1→V5 in CI" (proven by T-09-03).

---

### T-09-02 — RBAC entities (`Permission`, `Role`, `RolePermission` + `RolePermissionId`, `UserRole`) + 4 repositories

- **Owner:** backend-engineer
- **Depends on:** T-09-01 (**same PR** — `ddl-auto=validate` fails boot if mappings and schema disagree; `03-design.md` §3, §10.1)
- **Size / Risk:** M / Medium (5 domain classes + 4 repos are individually trivial and mirror `User.java`; the risk is concentrated in the `active_key` `byte[]` mapping under `validate` — the "highest-value thing to prototype early," §4.4)
- **Files (all create, `com.example.nexus.rbac`):**
  - `rbac/domain/Permission.java` — per §4.2: `@Id UUID id` `columnDefinition="BINARY(16)"` (no `@GeneratedValue`), `name`/`description`, `created_at` `insertable=false, updatable=false`; `@Getter` + `@NoArgsConstructor(access=PROTECTED)`.
  - `rbac/domain/Role.java` — per §4.2: bare-`UUID` `tenantId` (no `@ManyToOne`), `is_system_role`, `created_at` and `updated_at` both read-only (`insertable=false, updatable=false`, §3.2). **No `@Version`** — schema defines no `version` column; a `@Version` field would fail `validate` at boot (§4.6).
  - `rbac/domain/RolePermissionId.java` — plain `Serializable` class (not a record — JPA `@IdClass` needs a public no-arg ctor), two `UUID` fields `roleId`/`permissionId`, `@EqualsAndHashCode` (§4.3).
  - `rbac/domain/RolePermission.java` — `@IdClass(RolePermissionId.class)`, two flat `@Id UUID` fields, `created_at` read-only (§4.3).
  - `rbac/domain/UserRole.java` — per §4.4: bare-`UUID` `userId`/`roleId`/`tenantId`/`assignedBy`; `assigned_at` read-only; `revoked_at` **the one writable column**; `active_key` mapped **`byte[]`** (NOT `UUID` — 32 bytes, and `UuidV7Converter` is UUID-only so it leaves `byte[]` untouched) with `@Column(columnDefinition="BINARY(32)", insertable=false, updatable=false)` + `@org.hibernate.annotations.Generated(event={INSERT,UPDATE})`. **No `@Version`** (§4.6).
  - `rbac/infrastructure/persistence/JpaPermissionRepository.java` — `extends JpaRepository<Permission, UUID>`.
  - `rbac/infrastructure/persistence/JpaRoleRepository.java` — `extends JpaRepository<Role, UUID>`.
  - `rbac/infrastructure/persistence/JpaUserRoleRepository.java` — `extends JpaRepository<UserRole, UUID>`.
  - `rbac/infrastructure/persistence/JpaRolePermissionRepository.java` — `extends JpaRepository<RolePermission, RolePermissionId>` (OQ-2 → keep the 4th repo; §4.5).
- **Acceptance criteria:**
  - **AC#:** AC8 (4 entities + repositories in `com.example.nexus.rbac`, mirroring `identity`'s hexagonal layout; `active_key` read-only; passes `HexagonalArchitectureTest` with zero config).
  - Boot succeeds under `ddl-auto=validate` — the binding proof that every mapped column matches the T-09-01 schema (`BINARY(32)` ↔ `byte[]` passes; read-only `active_key` is not written by Hibernate).
  - No custom query methods, **no ports/adapters, no `application/`, no `interfaces/`** — those are US-010/012/015 concerns; adding them now is unused abstraction (§4.5).
  - `HexagonalArchitectureTest` (`:18-29`, `allowEmptyShould(true)`) needs **no change** — it auto-covers `rbac.*` the moment these classes exist (§1.2); confirm it stays green.
- **Test plan:** proven by T-09-07 (repository round-trip under `validate`); ArchUnit layering asserted by the existing `HexagonalArchitectureTest`.

---

## WAVE 2 — Schema & behavioral integration tests

_(All parallelisable; T-09-03/04/05 need only T-09-01, T-09-06/07 also need T-09-02. All are `*IT` on Testcontainers MySQL 8.4 — never H2 — mirroring `IdentitySchemaMigrationIT` / `AuthEventsAppendOnlyIT` / `SecureEventServiceConcurrencyTest`.)_

### T-09-03 — `RbacSchemaMigrationIT` (schema presence, seed counts, join queries, T-E6 assertion)

- **Owner:** qa-engineer
- **Depends on:** T-09-01
- **Size / Risk:** M / Low
- **Files (create):** `nexus-backend/src/test/java/com/example/nexus/rbac/RbacSchemaMigrationIT.java`
- **Acceptance criteria:**
  - **AC#:** AC1, AC2, AC3, AC7; **Test Scenarios 1, 5, 6** (`03-design.md` §8.4).
  - Clean V1→V5 applies; all 4 tables + every column (type/nullability) + `uq_permissions_name`, `uq_roles_tenant_name`, `uq_user_role_active`, and the InnoDB-auto FK indexes present via `information_schema` (§2.2 note — corrects impact doc's "table scan" assumption: `role_permissions.permission_id` reverse lookup **is** indexed).
  - Seed counts: `permissions`=7, `roles`=2, `role_permissions`=8. Join queries: `TENANT_ADMIN`→ all 7 permissions (Scen 5); `MEMBER`→ `user:read` only (Scen 6).
  - **T-E6 (P1):** an assertion that **`TENANT_ADMIN` holds every row currently in `permissions`** (`SELECT COUNT(*) FROM permissions` == count of `TENANT_ADMIN`'s `role_permissions`), so a future permission-adding migration that forgets to grant `TENANT_ADMIN` fails this test rather than silently under-granting (`03b-threat-model.md` T-E6). Add a test-method comment restating the future-migration convention seeded in T-09-01's header.
- **Test plan:** the `*IT` above; JDBC/`information_schema` assertions + seed-count + join queries + the T-E6 count-equality assertion.

---

### T-09-04 — `UserRolesAppendOnlyIT` (DELETE blocked; `UPDATE revoked_at` permitted)

- **Owner:** qa-engineer
- **Depends on:** T-09-01
- **Size / Risk:** S / Low
- **Files (create):** `nexus-backend/src/test/java/com/example/nexus/rbac/UserRolesAppendOnlyIT.java`
- **Acceptance criteria:**
  - **AC#:** AC4; **Test Scenarios 4, 9** (`03-design.md` §8.4).
  - Single-row `DELETE` → `SQLSTATE '45000'` (Scen 4). Multi-row `DELETE` matching several rows → **whole-statement abort on the first row evaluated, zero rows deleted** (Scen 9).
  - **Asymmetry proof:** `UPDATE user_roles SET revoked_at = ?` **succeeds** — confirming the deliberate divergence from `auth_events` (which blocks UPDATE too); there is intentionally no `BEFORE UPDATE` trigger (§2.2, story Technical Notes).
  - **T-R2 (positive control):** append-only history holds against the app-reachable path; the DBA `DROP TRIGGER` residual is out of scope (accepted risk, `03b-threat-model.md` T-R2).
- **Test plan:** the `*IT` above; seed parent `users`/`roles`/`user_roles` rows in `@BeforeEach`, assert the two DELETE outcomes and the UPDATE success.

---

### T-09-05 — `RoleUniquenessIT` (tenant isolation on `roles`)

- **Owner:** qa-engineer
- **Depends on:** T-09-01
- **Size / Risk:** S / Low
- **Files (create):** `nexus-backend/src/test/java/com/example/nexus/rbac/RoleUniquenessIT.java`
- **Acceptance criteria:**
  - **AC#:** AC5; **Test Scenarios 2, 3** (`03-design.md` §8.4).
  - Duplicate role `name` within the same `tenant_id` → `uq_roles_tenant_name` violation (`DataIntegrityViolationException`) (Scen 2). Same `name` across two different `tenant_id`s → both rows persist (Scen 3).
- **Test plan:** the `*IT` above.

---

### T-09-06 — `ActiveAssignmentIT` (`active_key` collision, revoke-reassign, concurrency, T-T3 negative)

- **Owner:** qa-engineer
- **Depends on:** T-09-01, T-09-02 (concurrency harness inserts via `JpaUserRoleRepository`, per §8.3)
- **Size / Risk:** M / Medium (concurrency correctness)
- **Files (create):** `nexus-backend/src/test/java/com/example/nexus/rbac/ActiveAssignmentIT.java`
- **Acceptance criteria:**
  - **AC#:** AC6; **Test Scenarios 7, 8, 10** (`03-design.md` §8.4).
  - Second active `(user_id, role_id)` row → collision on `uq_user_role_active` (`DataIntegrityViolationException`) (Scen 7). Revoke (set `revoked_at`) then re-assign → new active row inserts, original revoked row untouched (Scen 8).
  - **Concurrency (OQ-7 / §8.3):** mirror `SecureEventServiceConcurrencyTest` — `ExecutorService` of N≈8 threads released via `CyclicBarrier`/`CountDownLatch`, each firing the same active-`(user,role)` insert in its own transaction; assert **exactly one** commit, the remaining N−1 fail on `uq_user_role_active` (Scen 10). Seed parent `user`/`role` in `@BeforeEach`.
  - **T-T3 (P2, Scenario 11):** a negative test that an explicit `INSERT … (active_key) VALUES (…)` (attempting to supply a value for the `GENERATED ALWAYS` column) is **rejected by MySQL** — guards the generated-column property so a future migration author cannot accidentally "fix" it into a plain writable column (`03b-threat-model.md` T-T3). _(Placed here for cohesion with the other `active_key` assertions; satisfies the design's Task-Seed-14 T-T3 item.)_
- **Test plan:** the `*IT` above; collision + revoke-reassign + the barrier-released concurrency harness (count successes == 1) + the explicit-`active_key`-INSERT rejection.

---

### T-09-07 — `RbacRepositoryRoundTripIT` (save/find all 4 entities under `validate`)

- **Owner:** qa-engineer
- **Depends on:** T-09-02
- **Size / Risk:** S / Low
- **Files (create):** `nexus-backend/src/test/java/com/example/nexus/rbac/RbacRepositoryRoundTripIT.java`
- **Acceptance criteria:**
  - **AC#:** AC8 (`03-design.md` §8.4).
  - Save + find round-trip for `Permission`, `Role`, `RolePermission` (via `RolePermissionId`), `UserRole` under `ddl-auto=validate` — proves the mappings boot and function, specifically the `active_key` `byte[]` read-only mapping (populated in-memory after INSERT via `@Generated`) and the `@IdClass` composite key.
- **Test plan:** the `*IT` above; assert `active_key` is non-null after a `UserRole` save/re-fetch (proving `@Generated` re-selection), and that a `RolePermission` is retrievable by `RolePermissionId`.

---

## WAVE 3 — `nexus_app` provisioning grants (WS-4)

### T-09-08 — RBAC grants across all 3 provisioning artifacts (single atomic change)

- **Owner:** backend-engineer
- **Depends on:** T-09-01 (`GRANT … ON db.table` fails `ERROR 1146` if the table doesn't exist; can run in parallel with Wave 2 once T-09-01 lands)
- **Size / Risk:** S / Low (mechanical, but must land in all 3 files together — a partial landing is an inconsistent grant surface that only T-09-09 can catch)
- **Files (all modify, identical 5-statement grant block per `03-design.md` §6, ADR-0014 D6 as amended by ADR-0015 D7):**
  - `nexus-database/mysql/init/02-grants-post-schema.sql` — add the 5 grants before `FLUSH PRIVILEGES` (`:30`).
  - `nexus-backend/src/test/java/com/example/nexus/TestcontainersConfiguration.java` — add 5 `statement.execute("GRANT …")` in `nexusAppGrantsCallback` before `FLUSH PRIVILEGES` (`:129`). (Harmless in CI — the app runs as the container `test` user, not `nexus_app` — but keeps all three artifacts byte-consistent so the grant shape is reviewable in one place.)
  - `docs/runbooks/nexus-app-provisioning.md` — add the 5 grants to Step 2 (`:67-73`); update the `SHOW GRANTS` expected-output block (`:87-95`) from four lines to **nine** (four identity + five RBAC).
- **Acceptance criteria:**
  - **AC#:** AC9 (grants added to all 3 artifacts; smoke verification is T-09-09).
  - Grant block is **exactly** (§6): `SELECT` on `permissions`; `SELECT, INSERT` on `roles`; `SELECT, INSERT, DELETE` on `role_permissions`; `SELECT, INSERT` on `user_roles`; and **`UPDATE (revoked_at)` column-scoped** on `user_roles`.
  - **T-T1 (P0, RESOLVED via ADR-0015 D7):** the `user_roles` UPDATE grant is column-scoped to `revoked_at` — **no table-wide UPDATE, no DELETE** on `user_roles` — restoring `auth_events`-equivalent grant-level immutability for `user_id`/`role_id`/`assigned_by`/`assigned_at` (`03b-threat-model.md` T-T1; `03-design.md` §6).
  - **T-E4/T-E3 shape (P1):** no `DROP`/`ALTER`/`GRANT`, no global grant, `permissions` read-only — the closed permission set cannot be extended via `nexus_app` (`03b-threat-model.md` T-E4).
  - No existing grant test needs editing — `AuthEventDbPrivilegeHealthIndicator` is `auth_events`-scoped and the new table-scoped grants don't trip it (§6.3).
- **Test plan:** grant scope is verified by T-09-09 (the only path that runs as `nexus_app`); this task's own gate is "all three artifacts carry the identical 5-statement block and the runbook `SHOW GRANTS` block reads nine lines."

---

## WAVE 4 — AC9 operational go/no-go gate

### T-09-09 — docker-compose `full`-profile grant smoke check (manual gate) + Scen 12 + grant-scope assertion

- **Owner:** qa-engineer
- **Depends on:** T-09-08
- **Size / Risk:** M / Medium — this is a **process/checklist artifact, not a code file**, and it is the **only** detection for the story's own Critical-severity risk (a missing/misconfigured RBAC grant); Testcontainers CI structurally cannot catch it (`03-design.md` §6.2, §10.4).
- **Files:** no product code. Deliverable is an executed-and-recorded procedure appended to `docs/runbooks/nexus-app-provisioning.md` (or the PR checklist), documenting the exact commands, observed output, and pass/fail.
- **How to execute (Definition of Done for the gate):**
  1. `docker compose --profile full up` — `flyway-migrate` applies `V5` + `02-grants-post-schema.sql` (`afterMigrate.sql`), then `backend` connects as `nexus_app` (`docker-compose.yml:74`).
  2. As `nexus_app`, exercise each RBAC path: `SELECT` on all 4 tables; `INSERT` into `roles`, `role_permissions`, `user_roles`; `UPDATE user_roles SET revoked_at = NOW()` on a seeded/inserted row.
  3. **Scenario 12 / T-T1 negative (P0 proof):** as `nexus_app`, attempt `UPDATE user_roles SET assigned_by = ?` (any column other than `revoked_at`) → must be **denied at the grant level with `ERROR 1143`** — proving the column-scoped grant (not merely the JPA mapping) blocks it (`03b-threat-model.md` T-T1; story Scen 12).
  4. **T-E4/T-E3 grant-scope assertion (P1):** `SHOW GRANTS FOR 'nexus_app'@'%'` matches exactly the ADR-0014 D6 / ADR-0015 D7 shape — **no `DROP`/`ALTER`/`GRANT`, no `DELETE` on `user_roles`, no `ALL PRIVILEGES`, no global grant** (`03b-threat-model.md` T-E4, T-E3).
- **Acceptance criteria:**
  - **AC#:** AC9.
  - **Pass** = no `Access denied for user 'nexus_app'` on any granted path; seeded rows readable; step-3 UPDATE denied with `ERROR 1143`; step-4 `SHOW GRANTS` is exactly the intended shape.
  - **Fail** = any granted path denied (a grant is missing in an artifact) OR the column-scoped UPDATE is *permitted* (grant too broad) OR `SHOW GRANTS` shows anything beyond the intended shape → **block merge**.
  - **T-E3 (P0):** this gate is a **mandatory Gate-3 DoD item**, not optional — it is the sole non-Testcontainers detection for the missing-grant case (`03b-threat-model.md` T-E3; `03-design.md` §10.4).
  - **T-E3 over-grant residual → forwarded to US-010:** the smoke check (a positive read/write test) cannot detect the *still-on-`root`/over-granted* case at runtime; a startup self-check / actuator indicator (analog of `AuthEventDbPrivilegeHealthIndicator`) is a US-010 obligation, recorded here.
- **Test plan:** the manual/scripted procedure above; capture command output in the PR as evidence.

---

## Threat → Task Coverage Matrix

Every row of `03b-threat-model.md`'s "Threat → Task Mapping" table (and every STRIDE ID) is accounted for below — mapped to a task in **this** story, marked "forwarded to US-0XX" (with the AC it becomes there), or "accepted, no task."

| Threat ID(s) | Priority | Covered by | Form |
|---|---|---|---|
| **T-T1** | P0 (done at Gate 2, ADR-0015 D7) | **T-09-08** (column-scoped `UPDATE (revoked_at)` grant implemented) + **T-09-09** (Scen 12 negative proof: `ERROR 1143`) | Grant change + privilege-level negative test |
| **T-E2** | P0 (done at Gate 2, ADR-0015 D8) | **No task — WS-3 no-op**; verified in DoD (`application.yml:105` unchanged, prod retains fail-fast) | Design decision; verified by *absence* of change |
| **T-T2** | P1 (done at Gate 2) | **T-09-01** (`chk_user_roles_revoked_not_before_assigned` CHECK + invariant header comment) | Schema constraint + documented invariant |
| **T-E6** | P1 | **T-09-03** ("`TENANT_ADMIN` holds every `permissions` row" assertion) + **T-09-01** (future-migration convention in header) | Migration-IT assertion + convention note |
| **T-E4, T-E3** | P1 | **T-09-09** (grant-scope assertion: exactly the ADR-0014/0015 shape — no `DROP`/`ALTER`/`GRANT`, no `DELETE` on `user_roles`) | Grant-scope smoke assertion |
| **T-E3** (missing-grant) | P0 | **T-09-09** (AC9 `docker compose --profile full` smoke gate — mandatory Gate-3 DoD) | Manual go/no-go gate |
| **T-E3** (over-grant / still-on-`root` residual) | P1 | **Forwarded to US-010** — startup self-check / actuator indicator (US-009 has no runtime surface to host it) | Forward-tracked |
| **T-T3** | P2 | **T-09-06** (Scen 11: explicit `INSERT … (active_key) …` rejected) | Generated-column negative test |
| **T-S1** | P0 (US-010) | **Forwarded to US-010** — JWT `tenant_id` from `user.getTenantId()`, never defaulting an unresolved tenant to the sentinel (US-010 security AC) | Forward-tracked |
| **T-S2, T-R1** | P0 (US-012) | **Forwarded to US-012** — `assigned_by` from authenticated principal (T-S2); revoke emits an actor-attributed `auth_events` record (T-R1) (US-012 ACs) | Forward-tracked |
| **T-E5** | P1 | **T-09-01** (header documents `is_system_role` inert until US-015 AC7; no role-permission-mutation endpoint before US-015) | Documentation + sequencing note |
| **T-I3** | P1 (downstream) | **Forwarded to US-011/012/015** — map DB constraint/trigger violations to `RBAC_00x` RFC-7807 without leaking constraint names (design §8.1 lists the DB error contracts) | Forward-tracked |
| **T-D2** | P1 (US-012) | **Forwarded to US-012** — authenticated + rate-limited assign/revoke endpoints | Forward-tracked |
| **T-E1** | P0 (US-012) | **Forwarded to US-012** — hard EPIC-002 AC: only an existing `TENANT_ADMIN` (or platform bootstrap) may grant `TENANT_ADMIN`, tenant-scoped from JWT; co-tenancy is a pre-existing EPIC-001 reality, not a US-009 change | Forward-tracked (tracked ahead of US-012 Gate 1) |
| **T-R2** | Low (mitigated) | **T-09-04** (DELETE trigger, single + multi-row) — positive control; DBA `DROP TRIGGER` residual **accepted, no task** | Append-only IT + accepted residual |
| **T-T4** | Low | **Accepted, no task** (ADR-0014 D5 as amended by ADR-0015 D8) — migration-literal ↔ non-prod-config drift is a **PR-checklist item** (DoD), no runtime control | Accepted + PR checklist |
| **T-I1** | Low | **Accepted, no task** — reviewer-verified the 4 tables store only metadata + `UUID`s, no PII (T-09-01/02 introduce none) | Accepted (verified clean) |
| **T-I2** | Low | **Accepted, no task** — well-known seed/reference IDs and the sentinel are intentional, non-authorization inputs | Accepted |
| **T-D1** | N/A | **Accepted, no task** — schema-only story ships no unauthenticated (or any) runtime path to flood | Accepted (no DoS surface) |

---

## Sequencing Summary

| Wave | Tasks | Notes |
|---|---|---|
| 1 | T-09-01, T-09-02 | **One atomic PR** — schema first (01), then mappings against it (02); `ddl-auto=validate` couples them. AC3's "by construction" tenant guarantee depends on shipping them together. |
| 2 | T-09-03, T-09-04, T-09-05, T-09-06, T-09-07 | Schema/behavioral `*IT`s, parallelisable. 03/04/05 need only 01; 06/07 also need 02. Ideally in the same PR as Wave 1 (test-first). |
| 3 | T-09-08 | `nexus_app` grants across all 3 artifacts — one task, needs 01, runs parallel to Wave 2. |
| 4 | T-09-09 | AC9 grant smoke gate — mandatory Gate-3 go/no-go after 08; the only detection for the Critical grant gap. |

---

## Definition of Done

- [ ] **AC1** — `V5__rbac_schema.sql` creates all 4 tables with every column + index per the explicit lists; verified in `RbacSchemaMigrationIT` (T-09-01, T-09-03). Flyway slot reconfirmed against `main` before merge.
- [ ] **AC2** — 7 permissions seeded with format-valid UUIDv7 literal PKs (T-09-01, T-09-03).
- [ ] **AC3** — `TENANT_ADMIN` has all 7, `MEMBER` has `user:read` only, both scoped to bootstrap tenant `00000000-0000-7000-8000-000000000001`; join queries verified (T-09-01, T-09-03).
- [ ] **AC4** — single- and multi-row DELETE → `SQLSTATE '45000'`; `UPDATE revoked_at` permitted (asymmetry) (T-09-01, T-09-04).
- [ ] **AC5** — role-name uniqueness per tenant; cross-tenant same-name coexistence (T-09-05).
- [ ] **AC6** — `active_key` collision on second active `(user,role)`; revoke-then-reassign; exactly-one-wins under concurrency (T-09-06).
- [ ] **AC7** — clean V1→V5 in CI (Testcontainers) (T-09-03).
- [ ] **AC8** — 4 entities + `RolePermissionId` + 4 repositories in `com.example.nexus.rbac`; `active_key` read-only `byte[]`; boots under `validate`; passes `HexagonalArchitectureTest` unchanged (T-09-02, T-09-07).
- [ ] **AC9** — grants in all 3 artifacts (T-09-08) **and** docker-compose `full`-profile smoke gate executed & recorded, incl. Scen 12 `ERROR 1143` and the `SHOW GRANTS` scope assertion (T-09-09).
- [ ] **All 12 Test Scenarios** covered: 1/5/6 (T-09-03), 4/9 (T-09-04), 2/3 (T-09-05), 7/8/10 (T-09-06), **11** (T-09-06, T-T3), **12** (T-09-09, T-T1).
- [ ] **Every threat-model row mapped** (matrix above); the two Gate-2 design changes (T-T1 column-scoped grant, T-E2 no-fallback) reflected — the latter verified by `application.yml:105` remaining unchanged.
- [ ] **No ADR-writing task** — ADR-0013/0014/0015 are all already Accepted; confirm they are referenced, not re-authored.
- [ ] **T-T4 PR-checklist item present:** any change to the sentinel literal updates the migration **and** every non-prod env file (`application-dev.yml`, `application-smoke.yml`) in the same PR (no base-`application.yml` fallback — ADR-0015 D8).
- [ ] **Atomic-PR invariant honoured:** `V5` + entities + repositories in one PR (T-09-01 + T-09-02).
- [ ] **`mvnw verify`** (full gate, Testcontainers MySQL 8.4) green — ArchUnit `rbac.*` layering, JaCoCo ≥80%, all 5 new `*IT`s passing; `mvnw lint`/format clean.

---

### File paths referenced (all absolute)
- This breakdown: `C:\entomo\AI\nexus\docs\features\US-009\04-tasks.md`
- Inputs: `C:\entomo\AI\nexus\docs\features\US-009\03-design.md`, `...\03b-threat-model.md`, `C:\entomo\AI\nexus\docs\story\2-rbac\US-009.md`
- Governing ADRs (all Accepted, not re-authored): `C:\entomo\AI\nexus\docs\adr\0013-rbac-data-model-and-enforcement-contract.md`, `...\0014-rbac-bootstrap-tenant-and-db-grants.md`, `...\0015-us-009-threat-model-hardening.md`
- Format precedent: `C:\entomo\AI\nexus\docs\features\US-008\04-tasks.md`
- Create: `C:\entomo\AI\nexus\nexus-backend\src\main\resources\db\migration\V5__rbac_schema.sql`; `...\src\main\java\com\example\nexus\rbac\domain\{Permission,Role,RolePermission,RolePermissionId,UserRole}.java`; `...\rbac\infrastructure\persistence\{JpaPermissionRepository,JpaRoleRepository,JpaRolePermissionRepository,JpaUserRoleRepository}.java`; `...\src\test\java\com\example\nexus\rbac\{RbacSchemaMigrationIT,UserRolesAppendOnlyIT,RoleUniquenessIT,ActiveAssignmentIT,RbacRepositoryRoundTripIT}.java`
- Modify: `C:\entomo\AI\nexus\nexus-database\mysql\init\02-grants-post-schema.sql`; `...\nexus-backend\src\test\java\com\example\nexus\TestcontainersConfiguration.java`; `C:\entomo\AI\nexus\docs\runbooks\nexus-app-provisioning.md`
- **Not modified (verify):** `...\nexus-backend\src\main\resources\application.yml` (:105 unchanged — ADR-0015 D8)
