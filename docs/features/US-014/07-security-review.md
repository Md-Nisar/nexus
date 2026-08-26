# US-014 Security Review — Audit role assignment and revocation events

Branch `feature/US-014` · uncommitted working tree · reviewer: security-reviewer sub-agent (fresh, hostile-mindset context)
Standards basis: `SECURITY.md` (§3 authz, §4 validation, §5 injection, §7 PII, §10 audit, §11 dependencies, §12 OWASP Top 10)
Threat model cross-referenced: `docs/features/US-014/03b-threat-model.md`

## Explicit review attestation

- **Authorization / access control (A01) — reviewed in full.** No new authorization decision point; no change to any denial outcome; emission is strictly post-decision.
- **PII handling (§7, A09) — reviewed in full.** No email, name, or credential reaches the denial row, the metadata JSON, or the failure log.
- **Cryptography — not applicable to this change, confirmed so.** No key, hash, token, signature, or randomness decision is introduced.

---

## Findings scoped to US-014's own diff

### [Low] A04 — Denial emission is not exception-isolated at the call site
`RoleAssignmentService.java:103, 119-121, 369-380`

The "must never throw or block" contract on `RbacAuditPort.recordRoleAssignmentDenied` is defended only inside the adapter's own `catch (Exception e)`. The call site takes it on trust. If a future implementation lets an exception/Error escape, `throw e` never executes and the original `InsufficientPermissionException` is replaced.

**Risk:** bounded — this cannot fail open. The mutation is unreachable on every denial path (T1/T2 throw before any write; T3 throws before the actual role assignment), so the realistic worst case is a `403` degrading to a `500`, never an authorization bypass.

**Fix (defense in depth):** `try { recordDenial(...); } catch (RuntimeException ignored) { /* audit is best-effort; the denial must win */ } throw e;` — or enforce the port's never-throws contract structurally rather than by convention in one adapter.

### [Low] A09 — Stale lane-routing Javadoc contradicts the ADR amendment this story just landed
`AuthEventRetryBuffer.java:190-192`

US-014 amended ADR 0011 §8 because the "four priority types" claim was stale (it's six). The identical stale count survives in `isPriorityWireName`'s Javadoc — the one place a reader goes to understand lane routing. `AuthEventType.isPriority()`'s own Javadoc is correct.

**Risk:** documentation only — a responder reading this comment could wrongly conclude `ROLE_ASSIGNED`/`ROLE_REVOKED` share the drop-newest standard lane, the exact misreading the ADR amendment exists to prevent.

**Fix:** change "the 4 named priority types" to "the priority types listed on `AuthEventType.PRIORITY`" so it can't go stale again.

### [Low] A01 — The accepted cross-tenant-placement residual (T-I6) also covers `metadata.roleId`, which the threat model discusses only for `user_id`
`RbacAuthEventAdapter.java:140-142`, `RoleAssignmentService.java:103` (T2 path)

On the T2 denial (cross-tenant role), the row stores tenant A's `tenant_id` alongside a `roleId` belonging to tenant B. T-I6 reasons about the foreign `user_id` and accepts it; it doesn't name `roleId`.

**Risk:** negligible — reviewer concurs with acceptance. The value was supplied by the actor (not disclosed to an attacker), it's an opaque UUID with no join path (`auth_events` has no FK), and on the cheap probing path it's a published bootstrap role id (public information). The only new reader is another tenant-A admin.

**Fix:** extend the forward note in `03-design.md` §15 item 2 so a future `auth_events` viewer is told not to assume either `user_id` or `metadata.roleId` belongs to the viewing tenant on a `ROLE_ASSIGNMENT_DENIED` row.

### [Low] A09 — No detection threshold attached to the new event type itself
`03-design.md` §9.3 / §11

Detection for denial probing rests entirely on the pre-existing `nexus.rbac.permission_denied{reason}` counter; no alert on growth of `auth_events` rows with `event_type='ROLE_ASSIGNMENT_DENIED'`.

**Risk:** low and appropriate for a 3-point story — the existing counter is the correct series and is per-tenant. T-D7 already leaves row growth unmitigated by design.

**Fix:** none required now; fold into the Epic 7 / US-015 rate-limiting work already carrying T-D6/T-D7/T-E9.

### [Medium] A08/A09 — A raw NUL byte makes a file this story modified binary to git, so US-014's changes to it were never diff-reviewable
`RbacAuthEventAdapterTest.java:214` — `Arguments.of("controlChar", "TENANT\x00ADMIN")` (literal `0x00` embedded in source, not an escape)

Pre-exists in `HEAD` (a US-012-era artifact, confirmed via `git show HEAD:... | tr -dc '\000' | wc -c` = 1) — **not introduced by US-014**. But US-014 modified this file, and it carries the adversarial-`roleName` escaper suite plus two load-bearing `outcome == "SUCCESS"` guards, so the single most security-relevant test change in this story reached review as an opaque binary diff. Reviewed out-of-band; contents confirmed correct.

**Risk:** (a) diff-based controls (code review, the `secret-scan` hook, CI diff linters) silently skip this file; (b) a formatter/IDE/Sonar pass that normalizes the file could strip the NUL, silently turning the `controlChar` adversarial case into the harmless `"TENANTADMIN"` — a security test that keeps passing while testing nothing.

**Fix:** replace the raw byte with `"TENANT" + (char) 0 + "ADMIN"` or `"TENANT\0ADMIN"`; add `*.java text` to a `.gitattributes` (none currently exists) so this can't recur silently.

---

## Findings on branch state outside US-014's scope

Per prior direction, the build-cache/CVSS-threshold/wrapper changes on this branch are the user's own separate CI work, not part of US-014. They are recorded here because the agent found them while running the mandated dependency-scan step, and one is a live Critical/High-severity supply-chain finding — not because they're attributed to this story.

### [High] A06 — The mandated dependency gate is currently RED on this branch
`nexus-backend/pom.xml:562` and the dependency tree as a whole

`./mvnw -Psecurity dependency-check:check` fails: **29 CVEs at CVSS ≥ 7**, including `CVE-2026-56817` (netty-transport, 9.8/CRITICAL). Concentrated in `tomcat-embed-core:11.0.22`, `netty-transport:4.2.15.Final`, `mysql-connector-j:9.7.0`, `jackson-databind:2.21.4`, and DOMPurify bundled in `swagger-ui` (reachable only in non-prod). Confirmed via `dependency:tree`: 197 artifacts, byte-identical composition to the US-012 baseline — **zero new dependencies from US-014**.

**Fix:** bump the affected managed versions, re-run the gate, and reconcile with `SECURITY.md` §11's stated ≥7 threshold. Suppress only a specific unfixable advisory, with a dated expiry — never by raising the global threshold.

### [High] A05 — `failBuildOnCVSS` was widened from 9 to 9.5, suppressing 5 Critical CVEs
`nexus-backend/pom.xml:562`

Threat-model finding T-T9 item 3 required this be restored to 9 or justified in an ADR with a dated expiry — not done. Five Critical (9.1) CVEs in tomcat-embed-core and netty-transport currently pass CI purely because of this line.

**Fix:** restore `failBuildOnCVSS` to 9 (or 7, matching `SECURITY.md`), or land an ADR naming the specific advisory forcing 9.5 with a dated expiry and per-advisory suppression instead.

### [Medium] A08 — Build-cache/wrapper state can let test evidence report green without executing
`.mvn/maven-build-cache-config.xml`, `.mvn/maven.config`, `mvnw-verify.log`

Build cache is enabled with `mandatoryClean` commented out; `mvnw-verify.log` in the tree has no Surefire/Failsafe summary. Relevant to this story only in that AC3/AC4/AC5 are test-evidence stories — recommend a clean, uncached `./mvnw verify` run with Docker up before merge, capturing the Failsafe summary showing `RoleAssignmentAuditIT` executed (this was already done manually earlier this session — `./mvnw.cmd verify -DskipITs -q` and full `verify` both confirmed exit 0 — but that run predates the current cache config).

---

## Threat-model cross-reference summary

Every threat-model item with a stated code/comment mitigation was checked and found present: REQUIRES_NEW durability, audit-write-failure isolation, 409/404 structural exclusion via catch type, compile-time-enforced non-swallowing (definite assignment on `Role role;`), `listActive` exclusion pinned by `verifyNoInteractions`, ADR 0011 §8 correction, escaper/outcome test retention, and the priority-lane exclusion. **T-D6 and T-D7 are confirmed accepted residual risks per Gate 2** (priced and monitored, not silently unmitigated) — not flagged as findings. **T-T9 (build/supply-chain integrity)** is the one threat-model item still open, tracked above as branch-scope, not story-scope.

## Injection, PII, and secrets — no new surface

No new query or dynamic SQL. Metadata built via `LinkedHashMap` with compile-time literal keys, serialized by the injected Jackson 3 `ObjectMapper` — no string concatenation. `reason` is a closed 5-member enum name. Key ordering (`traceId, roleId, roleName, reason, attemptedBy`) keeps the duplicate-key defense-in-depth control correctly positioned. No PII in the denial row, metadata, response, or logs; `traceId` is MDC-constrained (`^[A-Za-z0-9._-]{1,64}$`), `user_agent` is length-capped before reaching its column. No new dependency, no DDL, no secrets/config changes.

## OWASP Top 10 — scoped to US-014's diff

| ID | Verdict |
|---|---|
| A01 Broken Access Control | Pass |
| A02 Cryptographic Failures | N/A |
| A03 Injection | Pass |
| A04 Insecure Design | Pass (1 Low) |
| A05 Security Misconfiguration | N/A to story; branch-level Fail noted above |
| A06 Vulnerable Components | N/A to story (zero new deps); branch-level Fail noted above |
| A07 Auth Failures | N/A |
| A08 Integrity | Concerns — NUL byte defeats diff review on a touched file |
| A09 Logging & Monitoring | Pass with notes (2 Low) |
| A10 SSRF | N/A |

---

## Verdict

**US-014's functional diff: APPROVED.** Zero Blocker, zero High in the story's own code — a faithful, tightly scoped extension of the existing audit pipeline. The durability claim is genuinely mechanised and test-proven; the authorization surface is unchanged; no PII exposure, no injection surface, no new dependency, no DDL. Every Gate-2 required mitigation with a code/comment expression is present. Four Low findings and one Medium (pre-existing NUL byte, worth a quick fix since it currently defeats diff review on a security-relevant test file) — none blocking.

**The branch overall: BLOCKED**, on two items that are pre-existing, out of US-014's scope, and inherit no approval from this review:
1. `dependency-check:check` fails (CVE-2026-56817, CVSS 9.8, netty-transport; 29 findings ≥ 7).
2. `failBuildOnCVSS` weakened from 9 → 9.5 in `pom.xml:562`, suppressing 5 Critical CVEs, contrary to threat-model T-T9.

### Relevant files
- `nexus-backend/pom.xml`
- `nexus-backend/src/main/java/com/example/nexus/rbac/application/RoleAssignmentService.java`
- `nexus-backend/src/main/java/com/example/nexus/identity/infrastructure/audit/RbacAuthEventAdapter.java`
- `nexus-backend/src/main/java/com/example/nexus/identity/infrastructure/audit/AuthEventRetryBuffer.java`
- `nexus-backend/src/main/java/com/example/nexus/identity/domain/AuthEventType.java`
- `nexus-backend/src/main/java/com/example/nexus/rbac/application/port/out/RbacAuditPort.java`
- `nexus-backend/src/test/java/com/example/nexus/identity/infrastructure/audit/RbacAuthEventAdapterTest.java`
- `nexus-backend/src/test/java/com/example/nexus/rbac/RoleAssignmentAuditIT.java`
- `docs/features/US-014/03b-threat-model.md`
- `docs/features/US-014/03-design.md`
