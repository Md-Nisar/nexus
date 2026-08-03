# US-012 -- Code Review: Enable role assignment and revocation API

**Reviewer:** Staff Engineer (fresh-context review)
**Scope:** All uncommitted working-tree changes on feature/US-012 under
nexus-backend/src/main/java/com/example/nexus/rbac/,
nexus-backend/src/main/java/com/example/nexus/identity/infrastructure/{audit,persistence}/,
nexus-backend/src/test/java/com/example/nexus/rbac/,
common/security/DenialReason.java, common/web/GlobalExceptionHandler.java,
application*.yml (feature-flag lines), architecture/HexagonalArchitectureTest.java.
**Cross-referenced against:** docs/features/US-012/03-design.md, 03b-threat-model.md,
04-tasks.md, CLAUDE.md.

## Overview

This is a well-executed implementation of a security-critical story. Every one of the
threat-model's required design changes (T-E7, T-E8, T-T6, T-R3, T-R4, T-S3, T-S4, T-E10, T-E11,
T-D4/zero-admins) is present in the code and, in almost every case, has a dedicated unit and/or
integration test proving it. The three bugs described as fixed during the final mvnw verify
pass (M6's app-side revokedAt clamp, the RoleAssignmentCacheIT actor-seeding fix, the
LocalDateTime JDBC cast fix) are coherent end-to-end -- verified below. The three log statements
added directly (WARN on lockout, DEBUG on duplicate, INFO on success) are correctly placed at the
throw sites / inside the post-commit lambdas, carry only UUIDs (no PII), and match
docs/observability-standards.md's structured-logging convention.

No Blocker or High findings. Two Medium findings (one a real, currently-unreachable spec
deviation; one a test-coverage gap on a threat-model-mandated adversarial case) and four Low
nits.

---

## Findings

### [Medium] Unparseable (non-blank) tenantId is misclassified as MALFORMED_AUTHENTICATION instead of the design-mandated MISSING_TENANT

**File:** nexus-backend/src/main/java/com/example/nexus/rbac/interfaces/rest/UserRoleController.java:184-200

**Problem:** 03-design.md Section 4.1 and Section 8.4 row 4 both specify that UUID.fromString(details.tenantId()) must fail closed to InsufficientPermissionException(perm, DenialReason.MISSING_TENANT) -- explicitly covering "absent, blank, or not a parseable UUID". AuthenticatedRequestDetails.fromAuthentication (common/security/AuthenticatedRequestDetails.java:50-53) only validates that tenantId is a non-blank String; it does not check UUID shape. resolveActor's single try block wraps both UUID.fromString(principalId) and UUID.fromString(details.tenantId()) in one catch (IllegalArgumentException e), throwing MALFORMED_AUTHENTICATION for both. A present-but-malformed tenantId (e.g. a claim containing "abc") is therefore misclassified as MALFORMED_AUTHENTICATION rather than MISSING_TENANT as the design and its own error-contract table require.

**Why it matters:** Not attacker-reachable today (the JWT tenantId claim is always written as a valid UUID by JwtRs256Service.issue), but it is a genuine contract violation that would misclassify the nexus.rbac.permission_denied{reason} metric tag and the WARN log's reason field if this branch is ever hit. UserRoleControllerTest only tests MALFORMED_AUTHENTICATION for a bad principal and MISSING_TENANT only for an absent tenant key -- the "present but not a parseable UUID" tenant case is untested and, as implemented, mishandled.

**Suggested fix:** split the try/catch so the principal parse and the tenant parse throw distinct DenialReasons, e.g. a small parseUuidOrThrow(value, requiredPermission, reason) helper called once with MALFORMED_AUTHENTICATION for the principal and once with MISSING_TENANT for the tenant. Add a UserRoleControllerTest case with a non-blank, non-UUID tenantId asserting MISSING_TENANT.

---

### [Medium] The T-T5 adversarial roleName matrix is missing the two cases the design calls mandatory, and the one "duplicate-key" case present targets the wrong field

**Files:**
nexus-backend/src/test/java/com/example/nexus/identity/infrastructure/audit/RbacAuthEventAdapterTest.java:129-136,
nexus-backend/src/test/java/com/example/nexus/rbac/RoleAssignmentAuditIT.java:171-181

**Problem:** 03-design.md Section 11.2 and 04-tasks.md T-009's testing requirements both mandate a roleName adversarial set containing a quote, a backslash, a newline, a raw U+0000-U+001F control character, a lone high surrogate, a JSON-shaped payload, and a duplicate-key attempt of the exact shape `","traceId":"forged`. The design explains precisely why the traceId variant (not assignedBy) is "the case that actually distinguishes a working escaper from a broken one": the metadata map is built in the order traceId, roleId, roleName, assignedBy, so an injected duplicate assignedBy (emitted after roleName) is harmless even under a broken escaper -- MySQL's "last duplicate key wins" rule means the legitimate trailing assignedBy always survives regardless of whether escaping works. A duplicate traceId (emitted before roleName) is the opposite: under a broken escaper the forged value would be the later one in the raw text and would win.

Both RbacAuthEventAdapterTest.adversarialRoleNames() and RoleAssignmentAuditIT.adversarialRoleNames() include only a duplicateKeyInjection case targeting assignedBy (`x","assignedBy":"forged`) -- the case the design says does not discriminate -- and neither file contains a lone-high-surrogate case at all. Compounding this, RoleAssignmentAuditIT's class Javadoc (lines 56-59) asserts that RbacAuthEventAdapterTest "already exhaustively covers ... lone surrogate ... and the duplicate-key traceId case", which is not accurate for the file as it currently stands.

**Why it matters:** Jackson's serialization is correct today, so this is not currently exploitable, but the one test case the threat model identifies as actually able to catch a regression (e.g. a future hand-rolled escaper, or a Jackson-major migration changing escaping behavior per T-E13's own risk) is absent, and the surrogate-pair case -- called out in 03b-threat-model.md T-T5 as the one residual that can cause a silent audit-write loss via encoding failure, feeding directly into T-R3 -- is untested end-to-end.

**Suggested fix:**
1. Add a roleName case containing `","traceId":"forged` to both files, asserting (unit test) the serialized JSON's traceId value equals the real trace id, and (IT) JSON_EXTRACT($.traceId) returns the real trace id, not the injected one.
2. Add a lone-high-surrogate case to RbacAuthEventAdapterTest, asserting either a successful round-trip or, if rejected, that the failure is caught by the existing T-R3 ERROR-log/counter path rather than propagating.
3. Correct the RoleAssignmentAuditIT Javadoc to describe what is actually covered.

---

### [Low] Order-of-checks in UserRoleController diverges from 03-design.md Section 3.1, changing which error a doubly-malformed request returns

**File:** nexus-backend/src/main/java/com/example/nexus/rbac/interfaces/rest/UserRoleController.java:106-108

**Problem:** The design's sequence diagram (Section 3.1) validates path/body UUID strings and parses them before resolving the actor from Authentication. The implementation calls resolveActor(authentication, ...) first and parsePathUuid(userId, "userId") second in all three handlers. When both the principal/tenant and the path userId are malformed in the same request, the response is 403 rather than 400 -- the opposite ordering from the design. Not a security issue (both fail closed), and not exercised by any test either way.

**Suggested fix:** either reorder the two calls to match the design, or note the deliberate deviation in the controller's Javadoc.

---

### [Low] Canonical-UUID regex duplicated between UserRoleController and AssignRoleRequest

**Files:**
nexus-backend/src/main/java/com/example/nexus/rbac/interfaces/rest/UserRoleController.java:69-71,
nexus-backend/src/main/java/com/example/nexus/rbac/interfaces/rest/dto/AssignRoleRequest.java:22-24

**Problem:** The same canonical-UUID pattern is written out independently in two places (one Pattern.compile, one @Pattern(regexp=...)). Also, UserRoleController.parsePathUuid is reused for request.roleId() (a body field, already validated by the DTO's own @Pattern), so a value that has already passed Bean Validation is silently re-validated by a method named for path variables.

**Why it matters:** two independent copies of a security-relevant validation pattern will drift if one is ever tightened or loosened without the other being noticed.

**Suggested fix:** hoist the regex into a single shared constant, and rename parsePathUuid to something verb-neutral (e.g. parseCanonicalUuid) since it is also used for the request body field.

---

### [Low] Redundant field duplication between structured key-values and message-format arguments in RbacAuthEventAdapter's ERROR log

**File:** nexus-backend/src/main/java/com/example/nexus/identity/infrastructure/audit/RbacAuthEventAdapter.java:94-102

**Problem:** The RBAC_AUDIT_WRITE_LOST log call adds tenantId/targetUserId/roleId/traceId via addKeyValue(...) (correct, structured) and also repeats operation/tenantId/targetUserId/roleId again as message-format placeholder arguments in the human-readable text. This works, but it means every field except operation is emitted twice per log line, which is exactly the concatenation-flavored style docs/observability-standards.md's log-injection-prevention guidance asks this story to avoid -- and which the WARN/INFO logs in RoleAssignmentService correctly avoid by using addKeyValue only.

**Suggested fix:** drop the field values from the message template and log a fixed message ("RBAC audit write lost"), letting the structured fields alone carry the data, matching the pattern used elsewhere in this story.

---

### [Low] RoleAssignmentService.listActive re-runs the identical M4 query for the caller when the caller is viewing their own roles

**File:** nexus-backend/src/main/java/com/example/nexus/rbac/application/RoleAssignmentService.java:241-247

**Problem:** listActive calls findActiveAssignmentViews(targetUserId, actor.tenantId()) for the response, then unconditionally calls callerHoldsActiveTenantAdmin(actor), which issues findActiveAssignmentViews(actor.userId(), actor.tenantId()) again. When actor.userId() equals targetUserId (a user listing their own roles), this executes the identical query twice with identical parameters in the same read-only transaction.

**Why it matters:** this endpoint is explicitly documented as low-volume/bounded (Section 8.3), so this is not a real performance risk -- flagged only as a one-line opportunity, not a defect.

**Suggested fix:** short-circuit: reuse the already-fetched list when actor.userId().equals(targetUserId) instead of issuing a second identical query.

---

## What was verified as correct (worth calling out)

- **M6 revocation clamp end-to-end (bug fix #1).** ActiveAssignmentRef gained assignedAt; UserRoleAssignmentPort#revoke(UUID, Instant), JpaUserRoleAssignmentAdapter#revoke, and JpaUserRoleRepository#revokeById(id, revokedAt) are all consistently wired; RoleAssignmentService.revoke computes revokedAt = max(now, ref.assignedAt()) correctly, which can never violate the revoked_at >= assigned_at CHECK constraint. UserRolesPrivilegeIT and the domain Javadoc both correctly document why FUNCTION('now', 6) was abandoned.
- **AC4 tenant isolation** is enforced identically and correctly on all three verbs, including the listActive (GET) check that the threat model's T-E8 finding specifically worried would be skipped as "redundant with M4" -- it is present, documented as mandatory-not-redundant, and unit-tested with an explicit assertion that findActiveAssignmentViews is never called on a tenant mismatch.
- **AC8 (T-E7)** correctly uses the live, locking (PESSIMISTIC_READ) hasActiveAdminAssignment port method, never a JWT claim; RoleAssignmentSecurityIT includes the mandated out-of-band-revocation test.
- **AC5 (T-D3/T-D4)** -- M1's lock is correctly driven by roleId, not tenantId; the actor-agnostic lockout guard is tested for both self-revocation and a different-admin-revoking variant; the zero-active-admins health indicator (adopted "unconditionally" per the threat model) is implemented and tested.
- **T-T6** -- M3 (findActiveAssignmentRef) returns the ActiveAssignmentRef projection, never a managed UserRole, closing the R-1 footgun on the write path.
- **T-R3/T-R4** -- RbacAuthEventAdapter serializes metadata JSON before opening the REQUIRES_NEW transaction, logs ERROR (not WARN) with a distinct RBAC_AUDIT_WRITE_LOST marker and increments nexus.rbac.audit_write_failed{operation} on failure; ROLE_ASSIGNED/ROLE_REVOKED are correctly added to AuthEventType.PRIORITY, reversing the original D10 decision as required.
- **T-S3/T-S4** -- assignedBy/revokedBy are provably sourced only from actor.userId(); the differing-path-vs-JWT-sub provenance test exists in UserRoleControllerTest; the principal fail-closed path (MALFORMED_AUTHENTICATION) is implemented and tested (see the Medium finding above for the one sub-case that isn't).
- **T-E10** -- RoleAssignmentService's parameter-shape invariant is enforced by a purpose-built ArchUnit rule (rbac_application_methods_must_not_accept_principal_or_map) in addition to the existing Spring-Security-package rule.
- **D9** -- the rbac_must_not_depend_on_identity ArchUnit rule is correctly scoped and its because() clause documents the common-laundering blind spot it cannot close.
- **O-10 (T-I5)** -- listActive's assignedBy redaction for non-admin callers is implemented and tested for both the redacted and non-redacted cases, and the controller/DTO correctly omit the field.
- **UserRolesPrivilegeIT** is an excellent, faithful implementation of the design's four mandatory nexus_app privilege assertions, including the column-scope-not-table-scope regression check the design calls the one thing that would catch a future silent grant-widening.
- **RoleAssignmentServiceTest** has thorough branch coverage of every documented AC and error path, including both transaction-synchronization-active and inline-fallback side-effect branches, and the equalsIgnoreCase case-variant test for TENANT_ADMIN matching (R-9).
- The feature-flag wiring (application.yml/-dev/-test) and the DenialReason/AuthEventType additions are minimal, additive, and match the design exactly.

---

## Summary

| Severity | Count |
|---|---|
| Blocker | 0 |
| High | 0 |
| Medium | 2 |
| Low | 4 |

**Verdict: APPROVE WITH NITS**

Neither Medium finding blocks merge: the MISSING_TENANT/MALFORMED_AUTHENTICATION misclassification is unreachable under the current JWT-issuance invariant, and the adversarial-test gap concerns a case Jackson's serializer already handles correctly -- the gap is in regression protection, not current behavior. Recommend fixing both before the next story that touches this audit path (US-014) rather than blocking this PR, given the very high bar already met on the story's actual security substance (AC4/AC5/AC8) and the size of the correctly-implemented threat-model remediation set.
