# Security Review — US-009: RBAC Data Model and Seed System Roles/Permissions

_Output of `/security-review` (security-reviewer, fresh hostile-mindset context). Cross-referenced against `docs/features/US-009/03b-threat-model.md`._

**Branch:** `feature/US-009` · **Scope:** schema-only (Flyway `V5`, 5 JPA entities, 4 repositories, 10 tests, DB grant additions across 3 provisioning artifacts). **No runtime API, no controllers, no use-cases, no auth/crypto code in this diff.**

Audited cold; every "RESOLVED" threat-model claim was independently re-verified against the actual code rather than trusted from the document.

## Cross-reference verification (threat model claims vs. code)

| Threat | Claim | Independently verified? | Result |
|--------|-------|------------------------|--------|
| **T-T1** | Grant column-scoped to `UPDATE (revoked_at)` in all 3 files | Yes — read all 3 | **CONFIRMED.** `02-grants-post-schema.sql`, `nexus-app-provisioning.md`, and `TestcontainersConfiguration.java` all carry `GRANT UPDATE (revoked_at) ON nexus.user_roles`, separate from the `SELECT, INSERT` grant. No table-wide `UPDATE` anywhere. Byte-identical across artifacts. |
| **T-E2** | `application.yml` NOT touched; no fallback added | Yes | **CONFIRMED.** `git diff origin/main` shows `application.yml` is not in the changeset. Line 105 is still `default-tenant-id: ${NEXUS_IDENTITY_DEFAULT_TENANT_ID}` with no `:default`. Prod retains fail-fast. |
| **T-T2** | `CHECK` "RESOLVED" — code review calls it overstated | Yes — read the constraint directly | **Code review is correct; see finding below.** |
| **T-E1** | Absent from this diff; forward-tracked to US-012 as hard AC | Yes | **CONFIRMED.** No assignment/authorization code exists in the diff. US-012 AC8 (`EPIC-002.md`, P0) is a real, explicit hard AC: "only an existing `TENANT_ADMIN` may grant `TENANT_ADMIN`." T-S2/T-R1 also folded into US-012 AC1/AC7. |
| **T-E5** | `is_system_role` inert, no enforcement | Yes | **CONFIRMED.** `Role.java` maps `systemRole` as a plain boolean field with zero read/enforcement logic anywhere in the diff. |

## Additional angles audited

- **SQL injection (A03):** `V5__rbac_schema.sql` is 100% static DML with hardcoded `UUID_TO_BIN('...')` literals — no string concatenation, no untrusted input. All 4 repositories are bare `JpaRepository` marker interfaces with zero custom `@Query` methods. **No injection surface.**
- **Grant scope re-derived from the actual `GRANT` statements** (not the design doc's description): `permissions` → `SELECT` only; `roles` → `SELECT, INSERT` (no UPDATE/DELETE); `role_permissions` → `SELECT, INSERT, DELETE` (no UPDATE); `user_roles` → `SELECT, INSERT` + `UPDATE (revoked_at)`, no DELETE. Genuinely least-privilege for the consuming stories' needs. The T-E4 residual (leaked credential rewriting `role_permissions`) is inherent to US-015's needs and correctly accepted.
- **`RolePermissionId` / `@EqualsAndHashCode`:** Lombok generates `equals`/`hashCode` over both `UUID` fields, both `nullable=false`. Two distinct `(roleId, permissionId)` pairs cannot compare equal. No Lombok/Hibernate quirk affecting security semantics. Safe.
- **Secrets:** No credentials, tokens, or connection strings in any new file. The bootstrap tenant UUID and 9 seed permission/role UUIDs are non-secret reference identifiers.
- **PII:** Independently verified. The 4 tables store only `UUID`s, names, descriptions, and timestamps — no email/name/IP/credential. Fixture `users` rows in the IT tests use synthetic randomized `@example.com` values, encrypted via `EmailCipher`, never logged.
- **Dependencies (A06):** `pom.xml` diff adds only a JaCoCo package exclude — **zero new dependencies**. No frontend files touched.

## Findings

### [Low] Threat model labels T-T2 "RESOLVED" but the CHECK constraint does not close the gap it describes

**File:** `nexus-backend/src/main/resources/db/migration/V5__rbac_schema.sql:82-83`

**Issue:** `CHECK (revoked_at IS NULL OR revoked_at >= assigned_at)` only rejects backdating `revoked_at` before `assigned_at`. Any future timestamp trivially satisfies `revoked_at >= assigned_at`, so scheduled/future-dated revocation — the exact scenario T-T2 warns about (multiple future-revoked rows all compute `active_key = NULL` and coexist, defeating the "one active assignment" invariant) — is **not** blocked. MySQL `CHECK` constraints cannot reference `NOW()` (non-deterministic), so this is not closable at the schema level. The threat model and ADR-0015 label this "RESOLVED"; it is a documentation/convention control, not a technical one.

**Risk:** In this diff, no exploitable path — there is no write path, and no current story introduces scheduled revocation. Security risk is Low. The real hazard is claim integrity (OWASP A04 Insecure Design): a US-012 implementer trusting the "RESOLVED" label and the constraint's name could skip the actual application-layer guard, silently re-opening the invariant bypass at that point.

**Fix:** Downgrade the threat-model/ADR wording from "RESOLVED" to "partially mitigated — CHECK guards against backdating only; US-012 MUST validate `revoked_at <= now()` at the application layer before any revoke write." No schema change is possible or needed.

**Note:** Rated Low here from a security-risk lens for this schema-only diff, vs. the prior code review's Medium from a correctness/claim-accuracy lens. Both are defensible; the divergence is scope (no runtime path today), not disagreement on the underlying fact.

### [Info] `nexus_app` write grants are provisioned ahead of any code that exercises them

**File:** `nexus-database/mysql/init/02-grants-post-schema.sql` (and the 2 sibling artifacts)

**Issue:** This story ships zero runtime code, yet `nexus_app` is granted `INSERT` on `roles`, `INSERT`/`DELETE` on `role_permissions`, and `INSERT` + `UPDATE(revoked_at)` on `user_roles` — write privileges on tables no application path touches until US-012/US-015 ship. Strict point-in-time least-privilege would grant only `SELECT` now.

**Risk:** Minimal and deliberate. The only exposure is a leaked-credential raw-SQL path (already captured as T-E4, accepted). CI runs as the container `test` user, so `nexus_app` isn't even exercised yet. Provisioning grants alongside the schema is an explicit, documented choice (ADR-0014 D6) to avoid the grant-drift / fail-at-first-query problem T-E3 describes.

**Fix:** None required — noted for completeness. Ensure the T-E4/T-E3 smoke assertion (already executed once for T-09-09) stays part of any future grant change.

No Blocker, Critical, High, or Medium findings.

## Mandatory reviewer statements

- **Auth/authorization:** No authentication or authorization enforcement code exists in this diff — no controllers, `@PreAuthorize`, token handling, or assignment logic. The only authz-adjacent surface is the DB grant set, reviewed line-by-line and re-derived independently: least-privilege, column-scoped on the one mutable path, DELETE-denied on the append-only table, DDL-free. The security-load-bearing controls (who may assign `TENANT_ADMIN`, tenant-from-JWT, `is_system_role` immutability) are correctly deferred and confirmed to exist as real, hard P0 ACs in US-010/US-012/US-015 — not vapor.
- **Cryptography:** No crypto surface added. UUIDv7 PKs and the sentinel tenant ID are non-secret identifiers; their predictability is not independently exploitable in this diff (access is gated by authenticated, tenant-scoped sessions that don't exist until US-011). Reviewed and confirmed.
- **PII handling:** Explicitly reviewed. The 4 new tables and all 10 new test files contain no email/name/IP/government-ID/credential data; the only email values are synthetic randomized `@example.com` fixtures, encrypted at rest, never logged. Consistent with `SECURITY.md` §7.

## Dependency scans

| Scan | Result |
|---|---|
| `npm audit --omit=dev --audit-level=high` (frontend) | **0 vulnerabilities.** Not applicable to this diff (zero frontend files touched by US-009). |
| `./mvnw -Psecurity dependency-check:check` (backend) | **Skipped by explicit user decision.** First run with no NVD API key configured; observed progress (~9% of 349,260 NVD records after ~10 minutes) extrapolated to 1.5–2 hours to finish, and the user chose to not wait on it for this review. Not blocking: the security-reviewer agent independently confirmed this diff adds **zero new dependencies** (`pom.xml`'s only change is a JaCoCo exclude), so any CVE this scan would surface is a pre-existing, whole-project condition, unrelated to US-009. **Follow-up recommended, not required:** configure an NVD API key (free from NVD) and re-run this scan against the full project outside any story's critical path — with a key, the same scan typically finishes in under a minute. |

## Verdict

**APPROVED**

This is disciplined, greenfield schema-only work. The two structural threats requiring code changes (T-T1 column-scoped grant, T-E2 no base-config fallback) are genuinely implemented as claimed and verified in the actual code across all provisioning artifacts. Injection, secrets, and PII surfaces are clean; grants are least-privilege; no new dependencies. The single Low finding is a documentation-accuracy issue with no exploitable path in this diff, and the Info item is a deliberate, documented trade-off — neither blocks merge.
