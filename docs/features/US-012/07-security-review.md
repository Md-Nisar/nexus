# US-012 — Security Code Audit (Phase 7)

**Story:** US-012 "Enable role assignment and revocation API" · **Epic:** EPIC-002 RBAC Foundation
**Basis:** `git status --porcelain` enumeration; `git diff` on modified files; full `Read` of all 28 new production files; `docs/features/US-012/03b-threat-model.md` read in full (688 lines)
**Standards:** `SECURITY.md`, OWASP Top 10 (2021), `docs/observability-standards.md`

## 0. Mandatory review attestation

Per standing policy, auth / crypto / PII-handling code is never approved silently:

- **Authentication — REVIEWED.** US-012 adds no authentication primitives. It consumes `Authentication` produced by `JwtAuthenticationFilter` (RS256, alg-pinned; reviewed under US-011, unchanged). The one new authentication-adjacent surface is `UserRoleController.resolveActor` (`UserRoleController.java:184-208`), reviewed line by line — see §2 T-S3/T-S4. Fail-closed on all four failure shapes (null/unauthenticated, non-`Map` details, non-`String`/non-UUID principal, unparseable tenant). The inherited US-011 T-02 tenant-provenance invariant remains the load-bearing trust dependency and is unchanged (no second producer of `Authentication.details` was introduced). **No authentication findings.**
- **Cryptography — REVIEWED.** No new cryptographic code. The only primitive-adjacent addition is `rbac/infrastructure/crypto/UuidV7IdGenerator.java`, a one-line delegate to `UuidCreator.getTimeOrderedEpoch()` (ADR-0005, `SecureRandom`-backed). `Math.random` / `new Random(` grep across `src/main`: **zero matches**. `user_roles.id` is never exposed in any DTO (`RoleAssignmentResponse` carries `userId`/`roleId` only), so UUIDv7 time-ordering creates no enumeration surface. No key material, no hashing, no encryption touched. **No cryptographic findings.**
- **PII handling — REVIEWED against the organisation's no-PII rule.** Grep for `email|firstName|lastName|getPasswordHash` across the entire `rbac` package: **zero matches**. Every DTO field audited: `RoleAssignmentResponse(userId, roleId, roleName, assignedAt, assignedBy)` — three UUID strings, a role label, a timestamp. `RbacAuditEvent` carries UUIDs + `roleName` + `RequestContext`. Every one of the six new/changed log statements audited individually (§2, T-log): all values are `UUID` objects or compile-time constants; no email, name, credential, token, or free-text user input in any log call. `auth_events.ip_address`/`user_agent` are fed by the pre-existing `RequestContext.of` path (IP is arguably PII under GDPR, but it is persisted only, never returned in any response and never logged by US-012 code). **No PII exposure introduced.** One adjacent defence-in-depth item: L-3 (an entity carrying encrypted PII is materialised, though never read or exposed).

**Dependency scans run** — see §4. **Backend: no CVSS ≥ 7 identified. Frontend production dependencies: 0 vulnerabilities.**

---

## 1. Threat-model cross-reference (03b-threat-model.md §5/§6)

Every threat the threat model marks mitigated or conditionally approved was verified against the real code, not the document's own text. **All 16 verified present. Zero claimed-mitigated-but-absent. Zero over-claims in either direction.**

| Threat | Claimed | Verified in code | Result |
|---|---|---|---|
| **T-E7** AC8 live-admin check must be a *locking* read, never JWT-derived | Cond. 5 | `RoleAssignmentService.java:88-90` → `hasActiveAdminAssignment(actor.userId(), role.getId(), actor.tenantId())` → `JpaUserRoleAssignmentAdapter.java:50-52` → `JpaUserRoleRepository.java:152` `@Lock(LockModeType.PESSIMISTIC_READ)` over an **entity-root** query (not a `COUNT`, correctly avoiding the implementation-defined `@Lock`-on-scalar case). `RoleChangeActor` is `record(UUID userId, UUID tenantId)` — structurally carries **no** permission or role data, so no JWT claim is reachable from the service. ArchUnit bans `org.springframework.security..` from `..application..`. Regression test present: `RoleAssignmentSecurityIT:266 should_return403WithNotTenantAdmin_when_staleJwtStillClaimsAdminAfterOutOfBandRevocation`. | **MITIGATED — verified** |
| **T-E8** Tenant isolation on `GET`, not just POST/DELETE | Cond. 1 | `RoleAssignmentService.java:239` — `verifySameTenant(targetUserId, actor, USER_READ)` executes **before** `findActiveAssignmentViews` at line 242. Ordering correct. Test asserts 403 and explicitly *not* 200-empty: `RoleAssignmentSecurityIT:146 should_return403WithCrossTenantTarget_notEmptyList_when_gettingRolesForUserInDifferentTenant`, plus `:199 should_return404_when_gettingRolesForNonexistentUser`. All three verbs call `verifySameTenant` (lines 77, 163, 239). | **MITIGATED — verified** |
| **T-T6** M3 must return a projection, never a managed `UserRole` | Cond. 3 | `JpaUserRoleRepository.java:96-104` — JPQL constructor projection `SELECT new …ActiveAssignmentRef(ur.id, ur.assignedAt)`, return type `Optional<ActiveAssignmentRef>` (`record(UUID id, Instant assignedAt)`). Repo-wide grep for `.revoke(`: `UserRole.revoke(Instant)` is called in **zero** `src/main` locations — only `RoleResolutionServiceIT:198` and `UserRoleTest:56` (both test setup, both superuser connections). Write path is `revokeById` bulk single-column JPQL only. | **MITIGATED — verified** |
| **T-R3** Audit-write failure must be loud (ERROR + counter), not swallowed | Cond. 2 | `RbacAuthEventAdapter.java:92-107` — `catch (Exception)` → `log.atError()` with `event=RBAC_AUDIT_WRITE_LOST` + all five reconstruction fields (`tenantId`, `targetUserId`, `roleId`, `actorUserId`, `traceId`) → `Counter.builder("nexus.rbac.audit_write_failed").tag("operation", …)`. Mitigation #3 also present: `buildMetadataJson` is called at **line 81, before** `secureEventService.recordEvent` at line 91, so a Jackson failure never becomes a commit-time DB rejection. Tests: `RbacAuthEventAdapterTest:198, :225, :239`. | **MITIGATED — verified, all 3 sub-items** |
| **T-S3** `assignedBy` provenance always from the principal | (a) | `AssignRoleRequest` is `record(String roleId)` — single field; **no** `assignedBy`/`tenantId` to bind. `RoleAssignmentService.java:111` passes `actor.userId()`. Test `RoleAssignmentSecurityIT:394 should_recordJwtSubjectAsAssignedBy_never_thePathUserIdDiffersFromCaller` pins the value-level provenance bug ArchUnit cannot express (T-E10 item 2). | **MITIGATED — verified** |
| **T-S4** Fail-closed on an unparseable principal | Cond. 6 | `UserRoleController.java:188-198`. See §2 for the current (just-fixed) state. Test `:436 should_return403WithMalformedAuthentication_notInternalServerError_when_principalIsNotAUuid`. | **MITIGATED — verified** |
| **T-D3** AC5 lock scoped by `role_id`, never `tenant_id` | (a) | `JpaUserRoleRepository.java:68-77` — `@Lock(PESSIMISTIC_WRITE)`, single-table (no `Role` join), predicate `ur.roleId = :roleId AND ur.tenantId = :tenantId AND ur.revokedAt IS NULL`. `roleId` leads; `tenant_id` is unindexed so the optimiser must drive on `fk_user_roles_role`. Javadoc records the constraint for future maintainers. No full-table-lock DoS. | **MITIGATED — verified** |
| **T-E9** `user:write` alone can revoke `TENANT_ADMIN` (accepted/deferred) | (b) | Javadoc **present and complete** at `RoleAssignmentService.java:150-158` — states the asymmetry with AC8, that it is deliberate, that it is unreachable today, and that a future custom-roles story must add the symmetric check before shipping. Not merely claimed. | **DOCUMENTED — verified** |
| **T-R4** Role-change events must be `PRIORITY` lane | Cond. 4 | `AuthEventType.java:51-58` — `ROLE_ASSIGNED`, `ROLE_REVOKED` added to the `PRIORITY` `EnumSet`; Javadoc at `:74-77` updated to "6 highest-value signals". Design reversal adopted. | **MITIGATED — verified** |
| **T-I5** `assignedBy` visible to every `user:read` holder | Decision | Option **(b)** implemented: `RoleAssignmentService.java:244-247` + `withAssignedByRedacted` (`:268-272`) null out `assignedBy` unless `callerHoldsActiveTenantAdmin(actor)`. DTO Javadoc documents the nullability. | **MITIGATED — option (b) verified** |
| **T-E13** Pin the `ObjectMapper` FQN | Cond. 7 | `RbacAuthEventAdapter.java:16` — `import tools.jackson.databind.ObjectMapper` (Jackson 3, the Boot 4.1 managed bean), constructor-**injected** (`:57`), with a Javadoc note at `:27-33` naming `LoginRateLimitFilter` as the anti-pattern. | **MITIGATED — verified** |
| **T-T7** `RBAC_004` must not echo constraint text | (test) | `DuplicateRoleAssignmentException` and `LastAdminRoleException` both have **no-arg constructors only**, with static literal messages. No caller-supplied or cause-derived message is constructible. Adapter (`JpaUserRoleAssignmentAdapter.java:83-85`) discards the `DataIntegrityViolationException` entirely. Discharges US-009 T-I3. | **MITIGATED — verified** |
| **T-E12** Positive column-scope grant check | Cond. 8 | `RbacDbPrivilegeHealthIndicator.hasBareTableUpdatePrivilege` (`:171-186`) added — DOWN on a bare table-scoped `UPDATE` in `TABLE_PRIVILEGES`. `UserRolesPrivilegeIT` carries all five assertions incl. `:154` and asserts error **1143** / SQLState **42000** (`:127-129`). | **MITIGATED — verified** |
| **T-D4** Zero-active-admins detection, adopted unconditionally | Cond. 8 | New `RbacZeroActiveAdminsHealthIndicator` + `findTenantsWithZeroActiveAssignmentsForRole` (`JpaUserRoleRepository.java:200-209`, case-insensitive via `UPPER()`). Fallback SQL not implemented anywhere. | **MITIGATED — verified** (but see M-1/M-2) |
| **T-E11** `@RequiresPermission` silently unenforced | (a) | All three handlers `public`, non-`final` (`:101, :130, :159`). **Paired** controls present per endpoint: `:302/:317` (assign), `:334/:348` (list), `:361/:376` (revoke) — 403 without, 2xx with. Tests assert 403 specifically, never "not 2xx", closing the D11 404 trap. | **MITIGATED — verified** |
| **T-T5** `roleName` JSON injection | (a) | Jackson 3 `writeValueAsString`. Adversarial matrix retargeted correctly: `RbacAuthEventAdapterTest:144` uses `"x\",\"traceId\":\"forged"` and `:163` asserts the **real** traceId survives — the discriminating case per the key-ordering analysis. Lone-surrogate case added at `:174`. **Additional control found:** `traceId` itself is charset-restricted by `CorrelationIdFilter.SAFE_ID` = `^[A-Za-z0-9._-]{1,64}$`, so the second tenant-influenced string in the metadata cannot carry JSON or CRLF either. | **MITIGATED — verified, double-controlled** |

**Also verified as requested (directly-applied, previously unreviewed changes):**

- **M6 app-side clamp.** `RoleAssignmentService.java:194-197` computes `Instant now = Instant.now(); Instant revokedAt = now.isBefore(ref.assignedAt()) ? ref.assignedAt() : now;`. `revokedAt` is **provably not attacker-influenceable**: `Instant.now()` is server-side; `ref.assignedAt()` is DB-sourced via the M3 projection; `UserRoleController.revokeRole` (`:159-169`) accepts no timestamp in path, body, query, or header and the `DELETE` handler has no body at all. The `revoked_at >= assigned_at` CHECK (`V5__rbac_schema.sql:83`, non-strict `>=`) **cannot be violated by construction**. Confirmed no `Instant`/`Date`/`String` timestamp is bound from request input anywhere on the path. **Clean** — one residual, L-2.
- **Three new log statements** in `RoleAssignmentService` (DEBUG duplicate, WARN last-admin-block, INFO assign/revoke). Every `addKeyValue` value is a `UUID` object. **`role.getName()` appears in none of them** — verified by reading all four call sites; it is passed only into `RbacAuditEvent` (where Jackson escapes it) and compared via `equalsIgnoreCase`. No string concatenation into any message. **No log-injection surface, no PII. Clean.**
- **`resolveActor` current state.** Correct, and the fix is real: fails closed on all four shapes, and `MISSING_TENANT` vs `MALFORMED_AUTHENTICATION` are genuinely distinguished, not collapsed. `tenantId` is read **only** from `details`, never from path or body. **Clean.**
- **Test fixes** (`RoleAssignmentCacheIT` actor-seeding, `RoleAssignmentIT` timestamp cast) — skimmed, test-only, no production reachability, no security relevance.

---

## 2. Findings

No **Blocker** and no **High** findings. Three **Medium**, ten **Low**.

### Medium

```
[Medium] M-1 — /actuator/health leaks cross-tenant tenantIds and the DB account
              name to ANY authenticated user of ANY tenant
File: rbac/infrastructure/health/RbacZeroActiveAdminsHealthIndicator.java:56-64
      rbac/infrastructure/health/RbacDbPrivilegeHealthIndicator.java:76-93
OWASP: A01 Broken Access Control, A05 Security Misconfiguration
Issue: Health.down().withDetail("tenantIds", affectedTenantIds) publishes a list of
       OTHER tenants' UUIDs. management.endpoint.health.show-details is
       "when-authorized"; because management.endpoint.health.roles is not configured,
       Spring Boot's WHEN_AUTHORIZED treats *any authenticated principal* as
       authorized, and /actuator/health/** is permitAll, so every self-registered
       MEMBER of every tenant can read the detail map.
Fix: Set management.endpoint.health.roles to an operator role; OR replace the
     tenantIds detail with a COUNT so the runbook keeps its signal without
     publishing identifiers. Add to the §10.2 staging->prod exit criteria.
```

```
[Medium] M-2 — New unauthenticated DB cost-amplification path: every anonymous
              /actuator/health request runs a cross-tenant roles scan
File: rbac/infrastructure/health/RbacZeroActiveAdminsHealthIndicator.java:47-49
      rbac/infrastructure/persistence/JpaUserRoleRepository.java:200-209
Issue: findTenantsWithZeroActiveAssignmentsForRole runs on EVERY /actuator/health
       hit (no cache TTL configured), permitAll, no rate limit covers the path.
Fix: Set management.endpoint.health.cache.time-to-live; and/or move the check to a
     @Scheduled gauge instead of the request path.
```

```
[Medium] M-3 — AC8 gates the role NAME, not the privilege it confers: a user:write
              holder may self-grant any role not literally named TENANT_ADMIN.
              Unreachable today; a complete AC8 bypass the day custom roles ship
File: rbac/application/RoleAssignmentService.java:80-94
Issue: The AC8 guard is conditioned on RbacRoleNames.TENANT_ADMIN.equalsIgnoreCase(
       role.getName()). Every other role is grantable — including self-grantable —
       by any user:write holder, with no privilege-based check.
Fix: (now) Document via Javadoc, matching T-E9's treatment. (custom-roles story,
     blocking entry criterion) Gate granting any role carrying user:write/role:write
     on an active TENANT_ADMIN check, or a subset-of-caller's-own-permissions rule.
```

### Low

1. **L-1** — `assign()`'s `FOR SHARE` and `revoke()`'s `FOR UPDATE` range lock can deadlock (MySQL 1213) or lock-wait-timeout (1205); `GlobalExceptionHandler` has no `DataAccessException` handler, so it falls to a 500 with a full stack trace instead of a structured 409/503. Fix: add a handler mapping `PessimisticLockingFailureException` to 409, WARN-logged with a counter.
2. **L-2** — `revoked_at` is now app-clock-sourced while `assigned_at` stays MySQL-clock-sourced; the `max()` clamp silently masks backward skew with no WARN/counter. Fix: log+count when the clamp actually engages; document the clock-authority split.
3. **L-3** — `JpaUserDirectoryAdapter.findTenantId` materialises a managed `User` (carrying the Argon2 hash + encrypted email) to read one column, on every assign/revoke/list. Fix: scalar projection `findTenantIdById`.
4. **L-4** — `auth_events.metadata.traceId` is caller-selectable via `X-Correlation-Id` (charset-restricted, so not an injection vector, but still attacker-influenceable data in a security audit record). Fix: document in the runbook as not a trust anchor; no code change required for US-012.
5. **L-5** — The T-R3 ERROR log passes the `Throwable` as a trailing vararg to the SLF4J fluent builder rather than `.setCause(e)`; the stack trace for the one log line that matters most may not be captured. Fix: use `.setCause(e)` explicitly (pre-existing platform pattern elsewhere too).
6. **L-6** — `listActive`'s T-I5 redaction check doubles the DB work of every `GET`, an endpoint reachable by every `MEMBER` (unlike POST/DELETE's `user:write` restriction) — T-D5's "reachable only by the most privileged principal" rate-limiting justification doesn't fully cover this verb. Fix: cheaper existence check, or reconcile T-D5's scope note.
7. **L-7** — `pom.xml`'s `failBuildOnCVSS` is 9 (above this review's own CVSS≥7 bar) and `.github/workflows/security.yml` is cron/dispatch-only, not a PR gate. Pre-existing, not introduced by US-012. Fix: lower to 7; add `pull_request` trigger.
8. **L-8** — `RbacDbPrivilegeHealthIndicator`'s `LIKE '<user>'@%` pattern treats `nexus_app`'s underscore as a wildcard (over-matches only — fail-safe direction, hygiene only). Fix: escape LIKE metacharacters.
9. **L-9** — `/actuator/metrics` and `/actuator/prometheus` are readable by any authenticated user; US-012 adds `nexus.rbac.audit_write_failed`, `nexus.domain.conflict`, and new `permission_denied` reason tags to that surface. Pre-existing, widened by this story. Fix: restrict to an operator role.
10. **L-10** — Base `application.yml` defaults `DB_USERNAME`/`DB_PASSWORD` to `root`/`root`; a deploy that forgets these env vars silently connects as root, defeating the column-scoped-grant defence T-S3/T-E12 rely on. Pre-existing. Fix: drop the defaults so a misconfigured deploy fails closed. (Detected at runtime by the existing `isRoot` health check — genuine coverage, subject to M-1's exposure caveat.)

### Explicitly checked, no finding

- **A03 Injection** — all `@Query` JPQL with `@Param` binding; zero string-concatenated queries; `@RequiresPermission` values are compile-time constants; log injection closed (no user string in any log call; `traceId` charset-restricted); JSON injection into `auth_events.metadata` closed by Jackson 3 + adversarial tests. **Clean.**
- **A01 IDOR / object-level authorization** — all three verbs resolve target's tenant and role's tenant from the DB and compare to `actor.tenantId()` before any read/write; neither is bindable from request input. **Tenant isolation correct on all three verbs.**
- **A05 fail-closed feature flag** — verified default-`false`, dev/test-only `true`, absent controller ⇒ 404, unauthenticated still 401 first.
- **A02/A08 integrity** — no new migration; append-only triggers/grants unchanged; `revokeById`'s affected-row count is the concurrency guard.
- **Secrets** — zero credential/key/token literals in the diff.
- **Error-response hygiene** — no handler echoes user input or internals.
- **Frontend** — zero files changed; `npm audit --omit=dev`: 0 vulnerabilities.

---

## 3. Dependency scans (A06)

**Frontend — completed, clean.** `npm audit --omit=dev --audit-level=high` → 0 vulnerabilities (exit 0). Full audit incl. dev: 11 advisories, all dev/build tooling, none ship to the browser. Down from the design-phase count of 14 — an improvement, no regression.

**Backend — did not complete locally (35 min, no NVD API key configured, cold-cache download); substitute manual inventory review performed instead.** `dependency:tree`: **198 artifacts, byte-identical to the design-phase count. Zero new dependencies, zero version drift.** Manual CVE review of all major artifacts (Spring Boot 4.1.0, Spring Framework 7.0.8, Spring Security 7.1.0, Hibernate 7.4.1, mysql-connector-j 9.7.0, Tomcat 11.0.22, logback 1.5.34, jjwt 0.12.6, Jackson 3.1.4/2.21.4, uuid-creator 6.1.1, lettuce 7.5.2, micrometer 1.17.0): **no CVSS ≥ 7 identified.** This is a manual review, not an NVD-backed scan — run `security.yml` via `workflow_dispatch` before merge for the authoritative A06 evidence (see L-7).

---

## 4. Verdict

# APPROVED

**Rationale.** All sixteen threats the Gate-2 threat model marked mitigated or conditionally approved have a real, verifiable control in the actual code, not just in the document's prose — including all eight "before `/breakdown`" conditions. The two most security-critical mechanisms are correct where it counts: T-E7's AC8 check is a genuine `@Lock(PESSIMISTIC_READ)` DB read on the caller with no reachable path to any JWT-derived claim, and `verifySameTenant` executes before the query on all three verbs including `GET`. Both directly-applied, previously-unreviewed changes (the M6 app-side clamp, the three new log statements) survive scrutiny. `resolveActor` correctly distinguishes `MISSING_TENANT` from `MALFORMED_AUTHENTICATION` and fails closed on every principal shape.

No Blocker and no High findings. Nothing in this diff is exploitable today to cross a tenant boundary, escalate privilege, leak PII, or bypass authentication.

**Conditions (none block the merge; tracked as follow-ups):**
1. M-1/M-2 before the feature flag is enabled in production — add to the §10.2 staging→prod exit criteria.
2. M-3 — Javadoc now; raise as a custom-roles-story entry criterion alongside T-E9's, to the PM.
3. L-1 and L-3 are small, well-scoped follow-ups worth doing in this story if schedule allows.
4. L-7 — run `security.yml` via `workflow_dispatch` before merge for authoritative A06 evidence; separately, fix the CVSS threshold and PR-gate status platform-wide.
5. Remaining Lows to the backlog.

**Process note.** Nothing in the repository was modified, staged, or committed during this review.

---

### Files reviewed

Production — new: `rbac/application/RoleAssignmentService.java` · `rbac/interfaces/rest/UserRoleController.java` · `rbac/interfaces/rest/dto/{AssignRoleRequest,RoleAssignmentResponse,RoleAssignmentListResponse}.java` · `rbac/application/port/out/{UserRoleAssignmentPort,UserDirectoryPort,RbacAuditPort,RbacAuditEvent}.java` · `rbac/domain/{ActiveAssignmentRef,ActiveRoleAssignment,RoleChangeActor,RbacRoleNames,IdGenerator,DuplicateRoleAssignmentException,LastAdminRoleException}.java` · `rbac/infrastructure/crypto/UuidV7IdGenerator.java` · `rbac/infrastructure/persistence/JpaUserRoleAssignmentAdapter.java` · `rbac/infrastructure/health/RbacZeroActiveAdminsHealthIndicator.java` · `identity/infrastructure/audit/RbacAuthEventAdapter.java` · `identity/infrastructure/persistence/JpaUserDirectoryAdapter.java`

Production — modified: `rbac/infrastructure/persistence/JpaUserRoleRepository.java` · `rbac/infrastructure/health/RbacDbPrivilegeHealthIndicator.java` · `common/security/DenialReason.java` · `common/web/GlobalExceptionHandler.java` · `identity/domain/AuthEventType.java` · `application.yml` / `application-dev.yml` / `application-test.yml`

Context read (trust dependencies): `common/security/AuthenticatedRequestDetails.java` · `common/web/CorrelationIdFilter.java` · `config/SecurityConfig.java` · `identity/domain/User.java` · `db/migration/V5__rbac_schema.sql` · `pom.xml` · `.github/workflows/security.yml`

Tests skimmed: `rbac/security/RoleAssignmentSecurityIT.java` · `rbac/UserRolesPrivilegeIT.java` · `identity/infrastructure/audit/RbacAuthEventAdapterTest.java`

Threat model cross-referenced in full: `docs/features/US-012/03b-threat-model.md`
