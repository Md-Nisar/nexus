# Test Coverage Audit — US-009: Establish RBAC Data Model and Seed System Roles and Permissions

_Output of `/test-validate` (qa-engineer). Phase 8 deliverable._

**Scope:** schema-only story — no runtime API, no controllers/use-cases, no frontend files. Authorization tests, load test scenarios, and frontend-state tests are correctly N/A (confirmed by inspecting the actual diff, not assumed) and are deferred to US-011/012/015, the stories that expose RBAC over HTTP.

## Existing tests (audited directly)

- `rbac/domain/{Permission,Role,RolePermission,RolePermissionId,UserRole}Test.java` — constructor field assignment, DB-managed-column null defaults, `RolePermissionId`'s Lombok `equals`/`hashCode` contract, `Role`'s nullable `description` already covered.
- `rbac/RbacSchemaMigrationIT.java` — table/column/index presence, Flyway history, scoped seed counts, `TENANT_ADMIN`/`MEMBER` join correctness, T-E6 invariant.
- `rbac/RoleUniquenessIT.java` — `uq_roles_tenant_name` violation + cross-tenant same-name success.
- `rbac/UserRolesAppendOnlyIT.java` — single/multi-row DELETE rejection, `UPDATE revoked_at` still permitted.
- `rbac/ActiveAssignmentIT.java` — `uq_user_role_active` collision, revoke-then-reassign, 8-thread concurrency race, explicit `active_key` write rejection.
- `rbac/RbacRepositoryRoundTripIT.java` — save/find round trip for all 4 entities, `active_key` population via `@Generated`.

Happy path was solid before this pass.

## Gaps found and closed

| Severity | Gap | Fix |
|---|---|---|
| High | Concurrency test (`06-code-review.md` Low finding) never verified *why* losing threads failed — could pass for the wrong reason | `ActiveAssignmentIT`: unwraps the full cause chain, asserts `DataIntegrityViolationException` and that the root `SQLException` message specifically mentions `uq_user_role_active` (new helper `assertLostRaceOnActiveKeyUniqueIndex`) |
| High | `chk_user_roles_revoked_not_before_assigned` (T-T2's CHECK constraint) had **zero test coverage** — confirmed via grep, no existing test touched it | `ActiveAssignmentIT`: `should_rejectInsert_when_revokedAtBeforeAssignedAt` (violation) + `should_allowInsert_when_revokedAtEqualsAssignedAt` (boundary — the constraint is `>=`, not `>`) |
| Medium | `permissions.description NOT NULL` never exercised (plain `String` field, no compile-time null-safety) | `RbacRepositoryRoundTripIT`: `should_rejectNullDescription_when_permissionSaved` |
| Medium | No FK-violation path exercised for any of the 5 FKs this migration adds | `RbacRepositoryRoundTripIT`: `should_rejectInsert_when_roleIdDoesNotExist` (representative of `fk_user_roles_role`) |

**Deliberately not added** (reasoning, not oversight):
- Discrete FK-violation tests for the other 4 FKs (`user_roles.user_id`/`assigned_by`, `role_permissions.role_id`/`permission_id`) — identical `FOREIGN KEY ... REFERENCES` DDL pattern, same InnoDB enforcement, zero custom logic layered on top. Testing all 5 would be re-testing InnoDB itself.
- Lombok `equals`/`hashCode` edge cases on `RolePermissionId` (null/different-type comparisons) — `@lombok.Generated` is already excluded from this project's JaCoCo gate; adding these would be padding boilerplate coverage, not testing story-specific behavior.
- Structural `information_schema` existence checks for the FK constraints — the functional violation test already proves existence + behavior; a second structural check would be redundant.

## A real bug caught mid-pass (in the new test, not production code)

The first version of `should_rejectInsert_when_revokedAtBeforeAssignedAt` asserted `DataIntegrityViolationException`, but MySQL's CHECK-violation error code (3819) isn't in Spring's `SQLErrorCodeSQLExceptionTranslator` MySQL table for raw `JdbcTemplate` calls — it actually surfaces as `UncategorizedSQLException`. Fixed by asserting the broader `DataAccessException`, matching the pattern the existing `active_key`-rejection test in the same file already uses for the identical underlying reason.

## Test run results (actually executed, not assumed)

**Backend unit tests:** `Tests run: 579, Failures: 0, Errors: 0, Skipped: 1` — BUILD SUCCESS. (The 1 skip is a pre-existing, unrelated benchmark test case.)

**RBAC integration tests** (Testcontainers MySQL 8.4, run twice for confidence):
```
ActiveAssignmentIT:          6/6 passing  (was 4 before this pass)
RbacRepositoryRoundTripIT:   6/6 passing  (was 4 before this pass)
RbacSchemaMigrationIT:      10/10 passing (unchanged)
RoleUniquenessIT:            2/2 passing  (unchanged)
UserRolesAppendOnlyIT:       3/3 passing  (unchanged)
Total:                      27/27 passing, 0 failures, 0 errors
```
BUILD SUCCESS both runs, including the JaCoCo `check` goal (90% `*.domain` line-coverage gate).

**Combined: 606/607 passing** (579 unit + 27 RBAC IT; 1 unrelated pre-existing skip).

## Load test scenarios

None added, by design — no controller, use-case, or HTTP endpoint exists anywhere in this diff for any load profile to target (the 4 repositories are bare `JpaRepository` marker interfaces with zero method bodies). Belongs to US-011/012/015.

## Flaky-test flag

- `ActiveAssignmentIT.should_allowExactlyOneWinner_when_eightConcurrentActiveInsertsRace` — inherently timing-dependent (8-thread `CyclicBarrier` race against a live MySQL unique index), same risk class as the `RefreshTokenRotationIT` pattern it deliberately mirrors. Ran twice independently this session with consistent results (exactly 1 winner both times). Worth watching in CI if it ever shows sporadic timeouts — executor has a 15s termination budget, barrier a 5s wait, both generous locally but CI runner contention could theoretically stretch either.
- No other timing/ordering/external-state dependence found. The shared-Spring-context/shared-schema design across the `*IT` suite is already handled by consistent scoping (fresh `UUID.randomUUID()`-tagged fixtures, filtered counts) in every test class, including the new ones added in this pass.

## Files touched

- `nexus-backend/src/test/java/com/example/nexus/rbac/ActiveAssignmentIT.java`
- `nexus-backend/src/test/java/com/example/nexus/rbac/RbacRepositoryRoundTripIT.java`

No production code was touched — all gaps were test-only; no bug was found in `V5__rbac_schema.sql` or the entities themselves (confirmed via `git status` — only the two test files above show further modification beyond their initial staged-add state).
