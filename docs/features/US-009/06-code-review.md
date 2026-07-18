# Code Review — US-009: Establish RBAC Data Model and Seed System Roles and Permissions

_Output of `/review` (code-reviewer, fresh context). Phase 6 deliverable._

**Scope reviewed:** `V5__rbac_schema.sql`, the 5 new `rbac.domain` entities, 4 `rbac.infrastructure.persistence` repositories, 10 new `*IT`/domain unit tests, `pom.xml` JaCoCo exclude, and the grant additions across `02-grants-post-schema.sql` / `TestcontainersConfiguration.java` / the runbook. Cross-referenced against `03-design.md`, `03b-threat-model.md`, ADR-0013/0014/0015, `CLAUDE.md`, and `docs/coding-standards.md`.

Overall this is unusually well-documented, disciplined work — the design/threat-model/code triangle is genuinely consistent (every `GRANT` statement checked byte-for-byte across all three provisioning artifacts and confirmed matching; the `active_key` mapping, the `@EmbeddedId` deviation, the DELETE-only trigger, and ADR-0015 D7/D8 are all implemented exactly as specified). Findings below are the residue after that check, not evidence of sloppiness.

---

## Findings

### [Medium] T-T2 mitigation is weaker than the threat-model claims — CHECK constraint doesn't actually prevent scheduled/future revocation

**File:** `nexus-backend/src/main/resources/db/migration/V5__rbac_schema.sql:78-83`

**Problem:** `03b-threat-model.md` T-T2 describes the risk as "`revoked_at` set to a future timestamp → `active_key` silently `NULL` → the 'one active assignment' invariant bypassed" and marks it "RESOLVED at Gate 2" via `CHECK (revoked_at IS NULL OR revoked_at >= assigned_at)`. Independently verified: that `CHECK` only rejects backdating `revoked_at` before `assigned_at` — it does nothing to stop `revoked_at` being set to a future timestamp (any future value trivially satisfies `revoked_at >= assigned_at`), which is exactly the scenario T-T2 warns about. MySQL `CHECK` constraints can't reference `NOW()`/`CURRENT_TIMESTAMP` (non-deterministic functions are disallowed), so this gap is not closable at the schema level at all — the ADR's "RESOLVED" framing overstates what was actually achieved; it's a documentation/convention control, not a technical one.

**Why it matters:** A future implementer (US-012) skimming this constraint's name (`chk_user_roles_revoked_not_before_assigned`) and the "RESOLVED" threat-model entry could reasonably assume the DB already guards against scheduled revocation, and skip adding the actual application-layer guard. That's the same "someone must remember" failure mode ADR-0015 D8 explicitly rejected for the tenant-fallback case, but it's exactly what's happening here for T-T2.

**Suggested fix:** Either (a) soften the threat-model wording from "RESOLVED" to "partially mitigated — the CHECK is a sanity guard against backdating, not a technical block on future-dating; US-012 MUST validate `revoked_at <= now()` at the application layer before any write," or (b) add that validation now as a documented contract even though no write path exists yet in this story, so it's not rediscovered at US-012 time.

---

### [Low] Concurrency test doesn't verify *why* the losing threads failed

**File:** `nexus-backend/src/test/java/com/example/nexus/rbac/ActiveAssignmentIT.java:172-185`

**Problem:** `should_allowExactlyOneWinner_when_eightConcurrentActiveInsertsRace` only asserts `successCount == 1` and `successCount + failureCount == threadCount`. It never inspects the actual exception on the losing futures. The code comment says "`ExecutionException` wrapping `DataIntegrityViolationException` on `uq_user_role_active`" but nothing enforces that — a `TimeoutException` from `barrier.await(5, TimeUnit.SECONDS)`, a connection-pool exhaustion error, or any other unrelated failure would be silently counted as a "correct" rejection.

**Why it matters:** This is exactly the kind of test that can pass for the wrong reason — if the uniqueness constraint were accidentally weakened (e.g. the unique index dropped) but 7 threads instead failed on an unrelated transient error, the test would still go green.

**Suggested fix:** In the failure branch, unwrap the cause chain and assert it's a `DataIntegrityViolationException` (mirroring the pattern already used elsewhere in this same file), e.g.:
```java
assertThat(unwrapCause(e)).isInstanceOf(DataIntegrityViolationException.class);
```

---

### [Low] Stale Javadoc still references the reverted @IdClass design

**File:** `nexus-backend/src/test/java/com/example/nexus/rbac/RbacRepositoryRoundTripIT.java:27`

**Problem:** The class Javadoc says "...both boot and function correctly," referring to "the `@IdClass` composite key," but `RolePermissionId`/`RolePermission` were changed to `@EmbeddedId` during implementation (documented in `RolePermissionId.java`'s own Javadoc). This one comment wasn't updated to match.

**Why it matters:** Minor, but it's exactly the kind of drift that makes a future reader briefly doubt which mapping strategy is actually in use — especially since the rest of the codebase (`RolePermissionId.java`, `RolePermission.java`) is careful to document this deviation everywhere else.

**Suggested fix:** `s/the {@code @IdClass} composite key/the {@code @EmbeddedId} composite key/`.

---

### [Low] RolePermissionId lacks a serialVersionUID

**File:** `nexus-backend/src/main/java/com/example/nexus/rbac/domain/RolePermissionId.java:37`

**Problem:** `RolePermissionId implements Serializable` (required for a JPA composite-key class) but declares no `serialVersionUID`. This is a minor code smell — a missing explicit UID means the compiler-generated one is fragile under refactors (e.g. field reordering, adding a field) and can trigger a Checkstyle/SpotBugs warning in strict configs.

**Why it matters:** Low practical risk here since Hibernate mostly uses this for identity comparisons within one JVM/process, not cross-JVM serialization, but it's cheap to fix and is a Java-101 convention when implementing `Serializable`.

**Suggested fix:** `private static final long serialVersionUID = 1L;`

---

### [Low] UserRole.getActiveKey() exposes a mutable array reference

**File:** `nexus-backend/src/main/java/com/example/nexus/rbac/domain/UserRole.java:66`

**Problem:** `@Getter` on the `byte[] activeKey` field returns the entity's internal array by reference; a caller can mutate the returned array and corrupt the entity's in-memory state (e.g. `userRole.getActiveKey()[0] = 0` silently changes what Hibernate would try to re-persist, or at minimum makes the in-memory representation lie).

**Why it matters:** Low risk in practice since this field is DB-generated/read-only (`insertable=false, updatable=false`) and nothing in this story writes it back, but it's a latent foot-gun for whichever future consumer (US-010/012) starts passing this value around.

**Suggested fix:** Not blocking for this PR given the field is read-only and unused outside tests today; worth a defensive `.clone()` in a custom getter if/when `activeKey` starts getting passed across a boundary in a later story. Flagging now so it isn't forgotten.

---

## Positive notes worth calling out

- The `GRANT` shape is byte-for-byte identical across all three provisioning artifacts (`02-grants-post-schema.sql`, `TestcontainersConfiguration.java`, the runbook including the `SHOW GRANTS` expected-output block) — verified directly, not just diffed by eye.
- `RolePermissionId`'s Javadoc explaining the `@IdClass` → `@EmbeddedId` deviation (Hibernate's `AttributeConverter`-on-`@IdClass` restriction) and the reverted explicit `@Convert` (which would have created a real `rbac.domain` → `identity.infrastructure` layering violation) is an exemplary piece of "why," not "what," documentation — exactly what `docs/coding-standards.md` asks for.
- `RbacSchemaMigrationIT`'s seed-count scoping (`is_system_role = TRUE`, named permission list, known role IDs) to avoid cross-test-class pollution under the shared Testcontainers schema is correctly and consistently applied in every sibling test that inserts fixture `roles` rows (`ActiveAssignmentIT`, `RoleUniquenessIT`, `UserRolesAppendOnlyIT`, `RbacRepositoryRoundTripIT` all pass `is_system_role=false`).
- The trigger is genuinely DELETE-only (verified against `V2`'s DELETE+UPDATE pair for `auth_events`), the CHECK constraint syntax is valid MySQL 8.4, and the JaCoCo exclude for the interface-only `rbac.infrastructure.persistence` package is well-justified and narrowly scoped rather than a blanket coverage-gate bypass.
- T-T3 (generated-column forgery) and T-E6 (TENANT_ADMIN snapshot-not-standing-rule) both have concrete, correctly-implemented negative tests (`ActiveAssignmentIT.should_rejectExplicitActiveKeyInsert_when_generatedColumnValueSuppliedDirectly`, `RbacSchemaMigrationIT.should_grantTenantAdminEveryPermissionRow_when_migrationApplied`) — these aren't just documented as resolved, they're actually enforced in CI.

---

## Summary

| Severity | Count |
|---|---|
| Blocker | 0 |
| High | 0 |
| Medium | 1 |
| Low | 4 |
| Nit | 0 |

**Verdict: APPROVE WITH NITS**

The one Medium finding (T-T2's `CHECK` constraint not actually closing the scheduled-revocation gap it's documented as resolving) is worth a follow-up comment/ADR clarification before this is treated as fully closed, but it doesn't block this PR — the underlying threat has no exploitable path in this schema-only story (no write path exists yet), and the fix belongs partly to US-012's application layer, not this migration. The Low findings are all real but genuinely minor (doc drift, test-assertion tightening, defensive-copy nit, missing `serialVersionUID`) and none block merge.
