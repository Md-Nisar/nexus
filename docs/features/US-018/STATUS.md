# US-018 — Progress and handoff

**Updated:** 2026-10-04 · **Source of truth for scope:** `04-tasks.md` (Gate 3 approved). This file only tracks where we are.

## Milestone status

| Milestone | Tasks | State |
|---|---|---|
| **M2** A1–A4 grant-subset core | T-001..T-003 | **Code complete on branch `feature/US-018/M2`**; PR not yet merged. See below. |
| M1, M3..M9 | see `04-tasks.md` | Not started. **M3 is gated on M2 merged and soaked in staging (≥ 1 sprint).** |

## M2 exit sequence

| Step | State |
|---|---|
| Implement T-001..T-003 | Done |
| `/review` (`06-code-review.md`) | Done, APPROVE WITH NITS; 9 findings fixed |
| `/security-review` (`07-security-review.md`) | Done, APPROVED; M-1, L-1, L-2, L-5 fixed. L-3 deferred to M8 (scanner, T-021), L-4 by design, L-6 pre-existing, handled with M3 |
| `/test-validate` (`08-test-audit.md`) | Done: 1177 unit (1 skipped), 353 IT, 0 failures; Checkstyle/SpotBugs/ArchUnit/JaCoCo green |
| `/docs` | Done: `09-technical`, `deployment`, `rollback`, `monitoring`, `runbook`, CHANGELOG. No new ADR, no api-spec (no endpoint added) |
| `/pre-pr-check` | Backend gates and artifact records pass; Definition of Done (`CONTRIBUTING.md`) not yet walked |
| Open PR | **Pending** |

## Open items

Before or at the M2 PR:
- Walk the `CONTRIBUTING.md` Definition of Done.
- Decide whether commit `0b9af67` (Claude settings trim) belongs in the M2 PR or a separate one.
- Ops: confirm `application-prod.yml` / env vars do not override the parent flags `feature.nexus-us012-rbac-role-assignment.enabled` and `feature.nexus-us015-rbac-role-management.enabled`.
- PR body and EPIC-002 must report RES-1(b) as **"self path closed; transformed into RES-26"** (T-E32), never "fully closed".

Merge and deploy checklist (owners outside the code; full list in `04-tasks.md` M2 merge checklist): RES-6 log-retention sign-off, A1 detection query per environment, custom-admin exposure check, permset cache flush after V6, V6 version number confirmed, staging soak starts.

After merge:
- Move ADR-0021 from Proposed to Accepted.
- Tidy `DenialReason.NOT_TENANT_ADMIN` when B8 lands in M8 (throttled actors get it today; pre-existing).

## Facts a new session needs

- Behaviour change: service-level callers must now hold the permission in the DB, not only in the JWT. Affects M7 load/seed fixtures; the break-glass CLI (M5) is not on this branch.
- Order of checks in `assign()`: tenant checks → throttle → legacy gate → M13 → A4 → A2 → duplicate 409 → insert. `revoke()` runs the grant-subset check before the last-admin 409.
- One denial metric (`nexus.rbac.permission_denied{permission,reason}`) emitted centrally in `GlobalExceptionHandler`; one `ROLE_ASSIGNMENT_DENIED` audit row per denied request.
- Recorded design deviations D-1..D-3 (M14 signature, M15 host class, adapter constructor) are in `09-technical.md`.
- Unverified claims in the docs: Redis key prefix at runtime, Flyway behaviour on code revert, the SQL snippets, and M5/M7 statements (design only).
- The revoke 403 `@ApiResponse` text in `UserRoleController` does not yet mention the subset denial.
- `02-impact.md:450` and `04-tasks.md:150` still carry stale permission counts (8→9, 7→8 ordering) fixed in `03-design.md`.

## Branch convention

Milestone branches are `feature/US-018/M<n>` (renamed from the `-m<n>` spelling at M2).
