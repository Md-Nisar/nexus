# US-014 — STRIDE Threat Model: Audit role assignment and revocation events

_Output of Phase 3 Step B (`/security-review` in threat-model mode). **Gate 2 deliverable.** Adversarial STRIDE analysis of `03-design.md`, run alongside — not instead of — the design. Closes `03-design.md` §0 decision 12 and answers all six items in §15._

**Epic:** EPIC-002 (RBAC Foundation) · **Story:** US-014 (3 points) · **Reviewer:** Application Security Engineer · **Status:** Gate 2 review

---

## 0. Scope, verification basis, and headline result

**Scope.** The design in `docs/features/US-014/03-design.md`: one new port method (`RbacAuditPort.recordRoleAssignmentDenied`), one new adapter method plus a two-parameter widening of `RbacAuthEventAdapter.record`/`buildMetadataJson`, one new `AuthEventType` constant deliberately excluded from `PRIORITY`, and two `try/catch` wrappings plus one inline call in `RoleAssignmentService`. Zero DB diff, zero API diff, zero frontend diff, zero dependency diff. US-012's shipped enforcement and US-008's audit pipeline are in scope only as **trust dependencies**.

**Headline result: APPROVE FOR GATE 2. No Blocker, no Critical, no High.** Two Medium findings need mitigation before `/breakdown` closes, both cheap and neither redirecting the approach. Design decisions 5 (priority-lane exclusion) and 7 (subject placement) are **confirmed correct**; decision 5's stated *rationale* is factually wrong in one respect and must be corrected before it is written into ADR 0011, which is a durable artifact.

**The one substantive thing this pass adds that the design did not identify:** the story's stated motivation — capturing the T-E1 escalation attempt — is **not** what it delivers. See **T-R5**.

### 0.1 Verification basis — code, schema, and ADR re-read this session, not trusted from the design doc

| Claim under test | Verified how | Result |
|---|---|---|
| The three throw sites T1/T2/T3 are where the design says they are | Read `RoleAssignmentService.java` | **Confirmed** — T1 `verifySameTenant:304`, T2 `resolveRoleInTenant:319`, T3 inline `:110`. `assign` calls the two helpers at `:95-96`, `revoke` at `:181-182` |
| The proposed `catch` cannot swallow a 409 or a 404 | Type check on `LastAdminRoleException`, `DuplicateRoleAssignmentException`, `ResourceNotFoundException` | **Confirmed structural** — none is an `InsufficientPermissionException`; the catch *type* enforces the 403-only scope, not a condition |
| The proposed `catch` cannot silently continue | Java definite-assignment analysis on `Role role;` (assign) and on `Role role = ...` inside `try` (revoke) | **Confirmed** — a `catch` that does not end in `throw`/`return` fails to compile. A real compile-time guarantee, correctly claimed |
| `record(...)` hardcodes `"SUCCESS"` today | Read `RbacAuthEventAdapter.java:85` | **Confirmed** — the design's `outcome` parameterisation does touch both success paths (see T-T8) |
| `buildMetadataJson` key order is `traceId, roleId, roleName, actorField` | Read `RbacAuthEventAdapter.java:115-131` | **Confirmed** — inserting `reason` after the `roleName` block and before the actor block yields the design §4.2 order exactly |
| `ObjectMapper` is the Jackson-3 Spring bean (US-012 T-E13) | Read `RbacAuthEventAdapter.java:16` | **Confirmed** — `tools.jackson.databind.ObjectMapper`, injected. T-E13 is closed and stays closed |
| `SecureEventService.recordEvent` is `REQUIRES_NEW` | Read `SecureEventService.java:52-55` | **Confirmed** — the F4 durability claim mechanism is real; TX1 is suspended, TX2 commits independently, and the row survives TX1 rollback |
| The port contract "never throws" actually holds for the new path | Read `RbacAuthEventAdapter.java:93-108` | **Confirmed** — `catch (Exception e)` wraps the whole body including `secureEventService.recordEvent`, so a commit-boundary failure is caught here (US-012 T-R3 mechanism), logged ERROR `RBAC_AUDIT_WRITE_LOST`, counted, and never reaches the caller |
| `auth_events` has no FK constraints | Read `V2__identity_schema.sql:73-90` | **Confirmed** — header comment "append-only audit trail — no updated_at, no FK"; `user_id`/`tenant_id` are nullable `BINARY(16)` with no reference. A T1 row (actor tenant + foreign `user_id`) is insertable, exactly as the design states |
| `outcome VARCHAR(20)`, no CHECK | Same, `:81` | **Confirmed** — `"DENIED"` fits, no constraint to violate |
| Append-only triggers exist and are event-type-agnostic | Same, `:98-103` | **Confirmed** — `trg_auth_events_no_update` SIGNALs SQLSTATE `45000` for any row |
| ADR 0011: priority lane capacity 200, drop-newest **per lane**, priority drained first, depth-warn on **any** priority depth >= 1 for 1 min | Read `docs/adr/0011-in-process-bounded-retry-buffer-for-audit-writes.md` sections 1, 2, 5 | **Confirmed on every parameter.** Decision 5 mechanism argument is correct — see section 4.3 |
| **Who can actually reach the two 403 paths** | Read `UserRoleController` (`@RequiresPermission(USER_WRITE)` on POST `:93` and DELETE `:153`) plus `V5__rbac_schema.sql:128-136` seed | **REFUTES the design framing.** `user:write` is granted to `TENANT_ADMIN` **only**; `MEMBER` holds `user:read` alone. Every emission path is **TENANT_ADMIN-gated today**, not reachable by "any authenticated caller" (T-D7, T-R5) |
| Attacker influence over `roleName` in a denial row | T3 fires only when `RbacRoleNames.TENANT_ADMIN.equalsIgnoreCase(role.getName())` (`:98`) | **Injection surface is empty** — a denial row `roleName` can only be a case variant of `tenant_admin`, or absent (T1/T2). See section 4.4 |
| Existing `outcome` assertions the refactor could regress | Grepped `RbacAuthEventAdapterTest:77,101` and `RoleAssignmentAuditIT:131,160` | **Already covered** — all four assert `SUCCESS`. T-T8 mitigation is "do not delete these", not "add them" |
| HikariCP sizing on the path that now nests a second connection | `application.yml:22-26` — `spring.datasource` has **no** `hikari` block anywhere | **Confirmed unset, so defaults apply**: `maximumPoolSize=10`, `connectionTimeout=30s`. This is what makes T-D6 quantifiable |
| Dependency baseline | `mvn -o dependency:tree` (system Maven 3.9.11 — see T-T9) | **198 artifacts, identical count to the US-012 baseline. Zero new dependencies.** Boot 4.1 / Spring 7.0.8 / Spring Security 7.1.0 / Hibernate 7.4.1 / mysql-connector-j 9.7.0 / micrometer 1.17.0 / jjwt 0.12.6. Dual Jackson majors (3.1.4 and 2.21.4) persist — the known, benign Boot-4 transition state |

**`npm audit` — not applicable, and this is a justified skip, not an omission.** The design carries a verified zero-line frontend diff (design sections 6 and 13), so the browser-shipped dependency set is unchanged from the US-013 audit. The 14 pre-existing dev-tooling advisories recorded in US-012 remain open platform hygiene debt on the O-8 backlog and are unaffected either way by this story.

### 0.2 Explicit review attestation (standing policy — auth, crypto, PII are never approved silently)

- **Authentication — reviewed.** US-014 adds **no** authentication code and reads no credential, token, cookie, or header. It consumes a `RoleChangeActor` already constructed by `UserRoleController` from the JWT principal plus `details.tenantId`, on the provenance chain verified end-to-end under US-012 T-S3 and locked by US-011 T-02 (`only_jwtAuthenticationFilter_sets_authentication_details`). **That inherited trust dependency is unchanged and still load-bearing.** No new authentication-adjacent surface.
- **Authorization — reviewed, and this is the security-relevant core of the review.** **No authorization decision changes.** Every 403/409/404 outcome is bit-identical before and after (design section 5, independently confirmed by reading the proposed diff: the same exception *instance* is rethrown, and `GlobalExceptionHandler.handleInsufficientPermission:159-176` is untouched, so `RBAC_001`, `requiredPermission`, the WARN, and `nexus.rbac.permission_denied{permission,reason}` all still fire). The emission is strictly **after** the decision and can never influence it. The three in-scope denial paths were re-walked against `RoleAssignmentService`, and the reachable population was independently established from the `V5` seed (section 0.1). **No elevation-of-privilege path is created, widened, or reordered by this story.**
- **Cryptography — reviewed, nothing to flag.** No new crypto, no key material, no algorithm selection. The only randomness is the pre-existing `uuidGenerator.newId()` (`UuidCreator.getTimeOrderedEpoch()`, `SecureRandom`-backed, ADR-0005) used for the `AuthEvent` `@Id` — unchanged, and that id is never exposed to any caller. Zero `Math.random` in the backend (re-grepped). **No cryptographic findings.**
- **PII — reviewed field by field against the organisation no-PII rule.** The new row carries: `event_type`, `outcome` (`"DENIED"`), `user_id` (target UUID), `tenant_id` (actor tenant UUID), `ip_address`/`user_agent` (pre-existing `RequestContext` columns, 512-char capped, on the established path), and a metadata JSON of `traceId`, `roleId`, `roleName`, `reason` (enum name), `attemptedBy` (UUID). **No email, no display name, no credential, no free-text customer value.** `roleName` is a tenant-authored label, and on a denial row it can only be a case variant of `tenant_admin` (section 0.1). `reason` is a closed 5-value enum. The one disclosure question that stands on its own merits is the cross-tenant *placement* of an otherwise-opaque UUID — **T-I6**, rated and accepted below. **No PII exposure introduced.**

**Severity scale:** Blocker / Critical / High / Medium / Low.

**Threat ID numbering** continues the epic STRIDE-lettered backend sequence: US-009 allocated T-S1–S2, T-T1–T4, T-R1–R2, T-I1–I3, T-D1–D2, T-E1–E6; US-012 allocated T-S3–S4, T-T5–T7, T-R3–R4, T-I4–I5, T-D3–D5, T-E7–E13. **US-014 therefore begins at T-S5, T-T8, T-R5, T-I6, T-D6, T-E14.** The US-011 `T-01..T-13` and US-013 `T-01..T-12` sequences are disjoint and are not extended.

---

## 1. Trust boundaries and data flow (delta only)

```
[ Authenticated client holding a VALID token WITH user:write -- i.e. an active TENANT_ADMIN,
  or a just-revoked ex-admin inside the ~15-min JWT window ]
        |  POST/DELETE /api/v1/users/{userId}/roles[/{roleId}]  + Bearer JWT
        v
=== TB1..TB3 unchanged from US-012 ====================================
  CorrelationIdFilter -> JwtAuthenticationFilter -> .anyRequest().authenticated()
  -> @ConditionalOnProperty(feature.nexus-us012-rbac-role-assignment.enabled)  [404 if off]
  -> @RequiresPermission("user:write")  == flat Set.contains on the JWT claim ==
        |  MISSING permission -> InsufficientPermissionException(PERMISSION_ABSENT)
        |  ...which NEVER reaches RoleAssignmentService  ---> NOT AUDITED (T-R5)
        v
=== TB4: interfaces -> application ====================================
  RoleAssignmentService.assign/revoke  @Transactional  [TX1 opens, connection #1 bound]
     T1 verifySameTenant          -> 403 CROSS_TENANT_TARGET  \
     T2 resolveRoleInTenant       -> 403 CROSS_TENANT_TARGET   >  NEW: audited pre-throw
     T3 !hasActiveAdminAssignment -> 403 NOT_TENANT_ADMIN     /   (T3 while holding FOR SHARE)
        v
=== TB5 (NEW ON THIS PATH): doomed TX1 -> independent TX2 =============
  RbacAuditPort.recordRoleAssignmentDenied
    -> buildMetadataJson (Jackson 3, BEFORE any transaction)
    -> SecureEventService.recordEvent  @Transactional(REQUIRES_NEW)
         ^^ TX1 SUSPENDED but its connection is NOT released; connection #2 borrowed
            from a default 10-connection pool with a 30s acquisition timeout  (T-D6)
    -> JpaAuthEventAdapter -> auth_events INSERT -> TX2 COMMITS (row durable)
    -> any failure: caught, ERROR RBAC_AUDIT_WRITE_LOST, audit_write_failed{operation=deny}
        v
  rethrow the SAME exception -> TX1 ROLLS BACK (audit row unaffected)
        v
=== TB6: unchanged ====================================================
  GlobalExceptionHandler: WARN + nexus.rbac.permission_denied -> 403 RBAC_001 (bit-identical)
```

**Components.** **C1** `RoleAssignmentService` emission sites (the only judgement-bearing change) · **C2** `RbacAuditPort` plus `RbacAuditEvent` (unchanged record) · **C3** `RbacAuthEventAdapter.recordRoleAssignmentDenied` plus the widened `record`/`buildMetadataJson` · **C4** `AuthEventType.ROLE_ASSIGNMENT_DENIED` and its `PRIORITY` non-membership · **C5** the inherited pipeline `SecureEventService` -> `AuthEventRetryBuffer` -> `auth_events` (zero diff) · **C6** `listActive` — the deliberately excluded path · **C7** the `@RequiresPermission` gate upstream (unmodified, and the source of T-R5).

---

## 2. Component-by-component STRIDE table

| Component | S | T | R | I | D | E |
|---|---|---|---|---|---|---|
| **C1** Service emission sites | `attemptedBy`/`tenantId` are `actor.*`, never path/body — inherits the proven T-S3 chain (OK). New 6-arg helper is transposition-prone (T-S5) | Catch *type* makes the 409/404 exclusion structural (OK); definite assignment makes "swallow the denial" a compile error (OK) | Denial row survives TX1 rollback via `REQUIRES_NEW` — mechanism verified (OK). Trail omits `PERMISSION_ABSENT` (**T-R5**) | Emission invisible to the caller; same exception instance rethrown (OK, T-I7) | Inline nested TX on an unrate-limited path (**T-D6**); unbounded row growth (T-D7) | No authz decision added, moved, or reordered (OK) |
| **C2** Port and `RbacAuditEvent` | — | 6-component record unchanged; no widening for anyone to "complete" (OK) | Javadoc pins "never throw, never block" and the pre-throw call position (OK) | Carries UUIDs, a role label, and `RequestContext` only (OK, no PII) | — | Parameters are a record plus an enum — all three ArchUnit rules stay green, verified (OK) |
| **C3** Adapter | Four adjacent `String` params after widening (T-S5/T-T8) | `reason` emitted **after** `roleName`, so a forged duplicate loses (OK as defense in depth; the injection surface is empty anyway, section 4.4) | Catch-all still ERROR plus `audit_write_failed{operation=deny}` (OK, T-R3 mitigation intact) | Metadata is UUIDs, an enum name, and `traceId` (OK) | One extra INSERT per denial (T-D6/T-D7) | — |
| **C4** `AuthEventType` | — | Additive constant; `event_type VARCHAR(64)` fits 22 chars, no DDL (OK) | STANDARD-lane routing accepts droppability for this type (OK, correct trade — section 4.3) | — | **Exclusion from PRIORITY prevents an attacker-reachable type evicting `LOCKOUT` and prevents an attacker-triggerable pager (confirmed against ADR 0011)** | — |
| **C5** Inherited pipeline | — | Append-only triggers plus `INSERT,SELECT`-only grant unchanged (OK) | Inherits T-R3/T-R4 residuals unchanged | — | A standard-lane flood can now also evict `LOGIN_FAILURE`/`REGISTER`/`VERIFY` during an outage (accepted, T-D7) | — |
| **C6** `listActive` | — | — | Read denials remain unaudited by design (OK — "assignment denied" is the wrong event name for a read) | — | — | Exclusion is convention plus a build-blocking test, **not** structure as claimed (**T-E14**) |
| **C7** `@RequiresPermission` gate | Inherits US-011 T-02 | — | **Its denials are the ones a compliance reader most wants and the ones not recorded (T-R5)** | Echoes `requiredPermission` (US-011 T-09, accepted) | In-memory `Set.contains` (OK) | Zero tenant comparison — by design; the reason C1 must be right |

---

## 3. Findings

---

### [Medium] T-R5 — The story stated motivation (T-E1) is the one denial it does **not** audit: an unprivileged escalation attempt is stopped at `@RequiresPermission` with `PERMISSION_ABSENT` and never reaches the emission point

**Component:** C1/C7. **STRIDE:** Repudiation (audit completeness). **OWASP:** A09, A04.

Design section 15 item 6 states the net posture is "positive... directly against EPIC-002 T-E1 (self-registered bootstrap-tenant users sitting one denied check away from `TENANT_ADMIN`)". Requirements section 7 Decision 1 makes the same argument, and the ADR 0011 amendment text in design section 14 says "**any authenticated caller** can generate them in a loop". **All three are wrong in the same way, and the error is verifiable from the seed data:**

| Actor | Route to a role-assignment denial | `DenialReason` | Audited by US-014? |
|---|---|---|---|
| Self-registered `MEMBER` (the T-E1 attacker) — holds `user:read` only (`V5:134-136`) | Blocked at `@RequiresPermission("user:write")` (`UserRoleController:93`) before the service is entered | `PERMISSION_ABSENT` | **NO** |
| Active `TENANT_ADMIN` probing another tenant user or role | T1 / T2 | `CROSS_TENANT_TARGET` | Yes |
| Ex-admin whose assignment was revoked, still inside the ~15-min JWT window | T3 | `NOT_TENANT_ADMIN` | Yes |
| Any holder of a future custom role carrying `user:write` (post-US-015) | T1 / T2 / T3 | either | Yes |

So the delivered trail is a record of **privileged actors** overstepping — genuinely useful, and T3 in particular is a high-signal event (it is reachable today *only* by a revoked admin re-attempting escalation inside their stale token window, i.e. exactly the US-012 T-E7 scenario). But the T-E1 attempt — the unprivileged member reaching for `TENANT_ADMIN`, which the requirements cite as the *reason to build AC4 at all* — produces **no `auth_events` row**, only the pre-existing WARN plus `nexus.rbac.permission_denied{reason=PERMISSION_ABSENT}` counter, which Decision 1 itself dismisses as "operational signals — mutable in effect, not permanent audit records, and not queryable by the AC5 shape".

**Risk:** the classic A09 failure — **absence of evidence read as evidence of absence.** A compliance auditor or incident responder querying `auth_events` for `ROLE_ASSIGNMENT_DENIED` in a tenant, finding none, and concluding "no one attempted privilege escalation here" would be wrong: the entire unprivileged-attempt population is invisible in that table. The gap is structural (Decision 5 puts the emission point inside the service and `GlobalExceptionHandler` is deliberately untouched) and therefore permanent until a later story addresses it.

**Assessment: Medium.** Not exploitable, not a vulnerability, and **not a reason to hold Gate 2** — the story ACs scope AC4 to the service own 403s, and the design implements that scope faithfully. It is Medium because the *documented compliance claim* materially overstates the delivered coverage, in a durable artifact (an ADR amendment), for the platform highest-severity threat.

**Required mitigation (documentation plus one forwarded obligation; no design change):**
1. **Correct section 15 item 6.** State plainly: this audits denials by callers who *already hold* `user:write`; a `PERMISSION_ABSENT` denial at the method-security layer is **not** audited, so the T-E1 attacker attempt is visible only in the WARN log and the `permission_denied` counter.
2. **Correct the ADR 0011 amendment text in section 14 before it is appended.** "Any authenticated caller can generate them in a loop" is false — `user:write` is `TENANT_ADMIN`-exclusive per `V5:130-136`. An ADR is durable; a wrong reachability claim in one will be cited later. Replace with "any caller holding `user:write` (today: `TENANT_ADMIN` only; a wider population from the moment custom roles with `user:write` ship)". This does **not** change decision 5 — see section 4.3 for the rationale that does hold.
3. **Record the coverage gap as a named future obligation**, not a silent one: auditing `PERMISSION_ABSENT` denials on RBAC-mutating endpoints requires an emission point at or above `GlobalExceptionHandler` (or a controller-level advice), which Decision 5 correctly rejects for this story on coupling grounds (Risk R-3). Forward it to Epic 7 / the audit-coverage backlog with this finding as the reference.
4. Optionally note in section 9.4 that "we have no denial trail for an incident" may legitimately mean "the denial was `PERMISSION_ABSENT`, which is by design not in `auth_events`" — a diagnostic that will otherwise be mistaken for T-R3 data loss.

**Residual after mitigation:** Low — a documented, deliberate coverage boundary instead of an implied-complete trail.

---

### [Medium] T-D6 — The inline `REQUIRES_NEW` write holds **two of ten** default pool connections on an unrate-limited, repeatable path, abandoning the pool-pressure property US-012 `afterCommit` design was praised for

**Component:** C1/C3/C5. **STRIDE:** Denial of Service. **OWASP:** A04, A05.

Design section 8.3 lists "second pooled connection on a formerly write-free path" as an accepted cost and stops there. Quantifying it changes the picture:

- **`spring.datasource` has no `hikari` block anywhere in `application.yml`** (verified `:22-26`). HikariCP defaults therefore apply: **`maximumPoolSize = 10`**, **`connectionTimeout = 30_000 ms`**.
- Spring `REQUIRES_NEW` **suspends** TX1 but does not release its connection — Hibernate resource-local release mode keeps it bound to the suspended `EntityManager` holder. So for the duration of the audit INSERT the request holds **two** connections simultaneously.
- Therefore **5 concurrent denials saturate the pool**, and the 6th blocks in `getConnection()` for up to **30 seconds** *while still holding its own connection*. That is a self-reinforcing stall: every waiter is also a holder. The effect is pool-wide and therefore **platform-wide and cross-tenant** — every other endpoint, every other tenant, and the `identity` login path share this pool.
- **This is precisely the hazard the US-012 threat model called out, and the reason its design chose `afterCommit`:** T-R3 recorded that a `REQUIRES_NEW` audit write is more likely to fail on "a full pool — the last *more* likely precisely because `REQUIRES_NEW` borrows a second pooled connection", and credited D14 `afterCommit` ordering with releasing locks *and* reducing pool pressure before the second connection is borrowed. US-014 **cannot** reuse `afterCommit` (the transaction is doomed — the design is right about that, and right that this is the only workable shape), so it necessarily reintroduces the nesting. The problem is not the choice; it is that the choice is booked as a footnote rather than priced.
- **T3 compounds it.** Design section 0.1 item 3 correctly identifies that T3 emits while TX1 holds a `PESSIMISTIC_READ` (`FOR SHARE`) lock on the caller `user_roles` rows, and accepts the cost as "one `INSERT` round-trip on an already-failing request". That estimate is only valid when the pool has spare capacity. Under pool pressure the same lock is held for up to the 30s acquisition timeout, during which a concurrent legitimate **revocation** of those rows (which needs an X lock) blocks. No deadlock is possible — the disjoint-tables reasoning is sound and was re-verified — but the availability cost is an order of magnitude larger than stated.

**Risk:** a single `user:write` holder issuing ~10 concurrent cross-tenant probes (a trivial loop using the *published* bootstrap-tenant `TENANT_ADMIN` role id from `V5:11`, which makes T2 free to trigger — no valid foreign user UUID needed) can stall the application entire connection pool for up to 30 seconds per wave, with no rate limiter anywhere on the path (US-012 Res. 10). Insider or compromised-admin abuse, not anonymous DoS — hence Medium, not High.

**Existing mitigations that genuinely help:** the emission is only on failing requests (bounded by the caller own request rate); metadata is serialised before any transaction, so the second connection is held for one round trip in the healthy case; the ADR 0011 buffer absorbs `auth_events` unavailability without extending the hold much further.

**Required mitigation (cheap; no design change to the emission shape):**
1. **Price it in section 8.3** with the actual numbers: pool size 10 (unconfigured default), acquisition timeout 30s, nesting depth 2, so denial concurrency of 5 or more saturates the pool — and state that this is the specific cost of losing `afterCommit`, cross-referencing US-012 T-R3.
2. **Add pool telemetry to the section 11 24-hour watch list**, which currently watches four audit-specific signals and nothing about the pool: `hikaricp_connections_pending` and `hikaricp_connections_acquire_seconds` (both free from the existing Actuator/Micrometer wiring) must stay at their pre-deploy baseline. This is the one signal that distinguishes "the design estimate held" from "T-D6 is live".
3. **Make the rollback trigger explicit:** any sustained non-zero `hikaricp_connections_pending` newly correlated with `nexus.rbac.permission_denied` volume is a rollback condition, alongside the two already listed.
4. **Forward to US-015 as an entry criterion, together with T-D7:** the moment `user:write` can be carried by a tenant-created custom role, the population able to trigger this expands from "the tenant most privileged principal" to "anyone an admin hands a custom role", and rate limiting on these endpoints stops being optional. Same treatment US-012 gave T-E9.

**Residual after mitigation:** Low today (privileged, observable, bounded-duration, no data loss). Medium the day US-015 ships without a rate limiter.

---

### [Low] T-I6 — Cross-tenant subject placement: a T1 denial row pairs the actor `tenant_id` with a foreign tenant `user_id` in indexed columns — **accepted**, with two documentation corrections (design section 15 item 2)

**Component:** C1/C3. **STRIDE:** Information Disclosure / tenant-boundary hygiene. **OWASP:** A01, A04.

**Verdict: ACCEPT decision 7. Severity Low. This does not change the design and does not block Gate 2.** Do **not** force `user_id` to the actor: that would break the single "user_id is the subject" convention (`RbacAuthEventAdapter:86`, matching `LOCKOUT`) for one event type, which is a worse long-term outcome than a Low, reader-side placement quirk. Reasoning, taking each of the three grounds the design offers and adding the two it missed:

| Ground | Assessment |
|---|---|
| (a) the value is an opaque UUID | **Holds, and is stronger than stated.** `users.id` is a runtime UUIDv7 (ADR-0005) — unguessable; per US-012 T-I4 the *only* published low-entropy ids in this schema are the seeded **role** ids, not user ids. A reader of the row learns a 128-bit opaque token with no join path: `auth_events` has **no FK** (`V2:74`, re-verified), and every application query they could make with that UUID is itself tenant-checked and will 403/404 (the US-012 T-E8 `GET` fix is shipped and verified at `listActive:257`). |
| (b) only platform operators or a future `audit:read` holder can query `auth_events` | **Holds today.** Verified: `JpaAuthEventRepository` is a bare `JpaRepository` with zero custom methods, no controller queries `auth_events`, and `audit:read` (`V5:114`) is granted only to `TENANT_ADMIN` — with no endpoint consuming it. There is **no reader at all** right now. |
| (c) the Epic 7 UI does not exist yet | **Holds, but is the weakest ground** — it is a timing argument, not a control, and the row is permanent (append-only, no retention policy). The obligation must therefore travel to Epic 7 rather than expire. |
| **(d) the disclosure is not to the attacker** — missed by the design | The actor *supplied* the foreign `user_id`; they learn nothing from it being stored. The only new readers are **tenant A other admins** (or a future `audit:read` holder scoped to tenant A), who learn "one of our admins probed a user id that is not ours" — which is *exactly* the forensic fact the row exists to record. Framed correctly, this is the feature, not the leak. |
| **(e) what an in-tenant reader cannot learn** — missed by the design | They cannot determine which tenant the UUID belongs to, whether it is a user at all, or anything about the person. Cross-tenant enumeration with that UUID is independently blocked. The residual signal is "a UUID outside our tenant exists" — negligible. |

**The two things that are actually wrong here, and must be fixed (documentation only):**

1. **Decision 7 stated rationale contradicts section 4.3 of the same document.** Decision 7 justifies `user_id` = target on the grounds that it "keeps the AC5 uniform `tenant_id + user_id + event_type` query shape valid across all three RBAC event types — one query answers everything that happened to this user access, denials included." But section 4.3 states — correctly, and it is the safer choice — that `ROLE_ASSIGNMENT_DENIED` is **outside** the AC5 `IN` set, so the AC5 query never returns denial rows. The stated rationale is therefore void. **Replace it with the rationale that does hold:** consistency with `RbacAuthEventAdapter:86` established "user_id is the subject, matching the LOCKOUT convention", which is a real, durable, single-convention argument and the reason not to make this event type the one exception.
2. **The forensic-ergonomics consequence should be recorded, not left implicit.** For a cross-tenant probe the forensically primary party is the **actor**, and after decision 7 the actor is reachable **only** through `JSON_UNQUOTE(JSON_EXTRACT(metadata,'$.attemptedBy'))` — an unindexed expression on a JSON column. "Show me everything this admin attempted" is therefore a full-scan-shaped query, while "show me everything done *to* this user" is indexed. That is an acceptable trade for a 3-point story with no reader, but Epic 7 will feel it, and it is the concrete cost of decision 7 that section 15 item 2 does not name.

**Required mitigation:** the two corrections above, plus one line forwarding to Epic 7: any `auth_events` viewer must (i) treat `roleName` as optional on denial rows (design section 4.2 already says this), (ii) not assume `user_id` is in the viewing tenant on a `ROLE_ASSIGNMENT_DENIED` row, and (iii) inherit the ADR 0011 section 7 standing HTML-escape-on-render obligation for `metadata`/`user_agent`, which now covers one more row type.

**Residual:** Low, accepted.

---

### [Low] T-D7 — Audit-volume amplification is real, cheapest via **T2** with published role ids, and correctly out of scope — but the accepted-risk record must state the right population, and it becomes a US-015 entry criterion

**Component:** C1/C5/C7. **STRIDE:** Denial of Service (storage amplification). **OWASP:** A04.

**Confirmed: no rate limiter exists on POST/DELETE `/api/v1/users/{userId}/roles`.** Verified independently of the design claim — `LoginRateLimitFilter` is scoped to the login/refresh paths only (the US-012 TB1 diagram, unchanged), `UserRoleController` carries no throttle, and US-012 Res. 10 explicitly declined it. So an authenticated caller **holding `user:write`** can generate `ROLE_ASSIGNMENT_DENIED` rows at request rate, into a table with **no retention, archival, or partitioning policy** (requirements section 8) and **no application-level reclamation path** (append-only triggers plus no `DELETE` grant — US-012 T-D5).

**Two refinements the design does not make:**

1. **The population is `TENANT_ADMIN`, not "unprivileged".** Section 15 item 3 "an unprivileged authenticated caller" is wrong for the same reason as T-R5. This is insider abuse by the tenant most privileged principal — precisely the bounding argument US-012 T-D5 used to accept the identical risk on the success paths. **Consistency with that accepted precedent is the reason this is Low, and the accepted-risk record should say so explicitly rather than resting on the wrong premise.**
2. **T2 is the cheap path, not T1.** A T1 row requires a *valid foreign* user UUID (unguessable UUIDv7; an unknown id yields 404 `USER_NOT_FOUND` and **no** row). A T2 row requires only a role id from another tenant — and the bootstrap tenant role ids are **low-entropy, sequential, and published** in `V5:11`, ADR-0014, and three threat models (US-012 T-I4). So `POST {roleId: 019f6839-1810-7000-8000-00000000000a}` against a target in the caller own tenant is a free, infinitely repeatable, one-row-per-request generator that needs no reconnaissance. Worth stating because it removes the "they would have to guess UUIDs first" comfort.

**Is STANDARD-lane routing (decision 5) sufficient mitigation for Gate 2?** **It is sufficient for the hazard it addresses, and it is not a mitigation for this one.** Lane routing governs only what happens to buffered events *during an `auth_events` outage*; it does nothing about steady-state row growth, and nothing about the T-D6 connection pressure. Design section 15 item 3 slightly conflates the two. The honest statement is: **decision 5 contains the blast radius of a denial flood to the lane that already absorbs `LOGIN_FAILURE` noise (correct, and the right call), while row growth remains an accepted, unmitigated, pre-existing risk inherited from US-012 Res. 10 / T-D5.** Accepting it again here is defensible for a 3-point story; ignoring the distinction is not.

**Verdict: accepted risk. Does NOT block Gate 2 and does NOT need a rate-limit story to ship.** Required record-keeping:
1. Restate section 15 item 3 with the correct population and the T2 cheap path, explicitly reconciling against US-012 T-D5 (the same obligation, accepted the same way, for the same reason).
2. **Make rate limiting on `/api/v1/users/{userId}/roles` a US-015 entry criterion**, jointly with T-D6 item 4 and the existing US-012 T-E9 entry criterion. US-015 is the merge that widens `user:write` beyond `TENANT_ADMIN`; at that point three separately-accepted Low risks (T-E9, T-D6, T-D7) go live together. One line in the US-015 entry gate covers all three.
3. Keep the US-012 T-D5 substitute detection: `nexus.rbac.permission_denied{reason}` per tenant is the correct probing-detection series (design section 9.3 already says so). No new counter.

**Residual:** Low today. Medium from the US-015 merge without a rate limiter.

---

### [Low] T-E14 — The `listActive` exclusion is presented as "structurally impossible" but is convention plus one build-blocking test; the missing-`RequestContext` barrier is softer than claimed

**Component:** C6. **STRIDE:** Elevation of Privilege (scope creep) / Repudiation. **OWASP:** A04.

Design decision 2 and section 2.4 claim two "independent barriers" make read-path emission structural: (a) the emission lives at `assign`/`revoke` call sites, never in the shared `verifySameTenant` helper; (b) `listActive` has no `RequestContext`, "so a `RbacAuditEvent` could not be constructed without a signature change".

**Barrier (b) does not hold as stated.** `RbacAuditEvent` (re-read, `:13-19`) accepts `null` for both `roleId` and `requestContext`, and both are null-tolerated downstream: `buildMetadataJson:117-129` null-checks `requestContext` and omits `roleId` when absent, and `record:88-89` null-checks `requestContext` for `ipAddress`/`userAgent`. So `recordDenial(actor, targetUserId, null, null, reason, null)` from `listActive` **compiles and produces a valid — if degraded — audit row**. The barrier is that a developer would have to pass two nulls, which is a *speed bump*, not a structure. Barrier (a) is real but weaker than it looks for the same reason: a DRY-minded refactor moving the emission into `verifySameTenant` — the obvious next move, since that helper is shared by all three verbs — would need `roleId` and `RequestContext` threaded in, and nulls satisfy the compiler.

**The actual control is the test**, and it is a good one: design section 12.1 row 7 adds `verifyNoInteractions(rbacAuditPort)` to `should_throwCrossTenantTarget_andNeverCallFindActiveAssignmentViews_when_listActiveTargetTenantMismatch`. Mechanical, build-blocking, named after the behaviour, and it fires on exactly the refactor described above. **That is sufficient** — the same conclusion US-013 T-03 reached about mechanical-versus-remembered controls, satisfied here rather than requested.

**Risk if it were removed:** a read denial emitting `ROLE_ASSIGNMENT_DENIED` would mislabel a `GET` as an assignment attempt (corrupting the trail semantics for the exact compliance reader it serves) and would make the trail floodable by every `user:read` holder — i.e. **every self-registered `MEMBER`**, a population orders of magnitude larger than T-D7. That would raise T-D6 and T-D7 from Low to a genuine near-unauthenticated DoS. That asymmetry is why the exclusion matters and why the pinning test must not be softened.

**Required mitigation (wording plus a task note, no design change):**
1. Change section 2.4 and decision 2 from "structurally impossible" / "could not be constructed" to the accurate claim: *the emission is deliberately confined to the two write call sites; the absence of `roleId`/`RequestContext` on `listActive` makes an accidental extension awkward but not impossible, and the `verifyNoInteractions(rbacAuditPort)` assertion is the binding control.* Overstating a control is how it gets traded away later.
2. `04-tasks.md` must flag that assertion as **load-bearing, do not delete** — the same treatment section 12.1 already gives the 409/404 negative assertions.
3. State in the new port method Javadoc (section 3.1 already says "never from a read path") the *reason*: an "assignment denied" event for a read is a semantic mislabel **and** widens the emitting population to every `user:read` holder.

**Residual after mitigation:** Low.

---

### [Low] T-I7 — The denial write is confirmed invisible to the caller; the one new side channel is that a 403 latency leaks audit-pipeline health (design section 15 item 6 / review item 6)

**Component:** C1/C3. **STRIDE:** Information Disclosure (side channel). **OWASP:** A01, A09.

**The design claim holds. Verified along four channels, not assumed:**

| Channel | Verification | Result |
|---|---|---|
| Status code and body | `GlobalExceptionHandler.handleInsufficientPermission:159-176` untouched; the **same exception instance** is rethrown so `requiredPermission`, `reason`, and message are byte-identical; `problem(FORBIDDEN,"RBAC_001",...)` unchanged | **No difference.** Wire contract bit-identical whether the audit write succeeded, failed, or was never attempted |
| Exception escape | `RbacAuthEventAdapter.record` `catch (Exception e)` wraps the entire body **including** `secureEventService.recordEvent`, so a `REQUIRES_NEW` commit-boundary failure is caught here and converted to ERROR plus counter | **A failed audit write can never turn a 403 into a 500.** Residual: an `Error` (e.g. OOM) is not caught — not attacker-steerable, noted only for completeness |
| Transaction visibility | TX2 commits independently; TX1 rolls back and had written nothing on any denial path (`registerPostCommitSideEffects` deliberately unused, verified `:343-355`) | **No observable side effect on the caller request** |
| Existence-oracle enrichment | A 403 now writes a row and a 404 does not — but the caller already receives a *definitive* 403-vs-404 answer (US-012 T-I4, accepted with reasoning endorsed) | **No new information.** The row is visible only to audit readers, of which there are none today |

**The one genuinely new residual, which section 15 item 6 does not identify:** the 403 path now performs a synchronous cross-transaction INSERT, so its latency is a function of **audit-pipeline health**. In the healthy case that is one extra round trip (a few ms, applied uniformly to T1/T2/T3, so it does not help discriminate between them). But when `auth_events` is degraded — statement timeout, lock wait, or T-D6 pool contention — the added latency is orders of magnitude larger. A caller who can trigger a 403 at will therefore has a **reliable, low-noise oracle for "the audit subsystem is impaired right now"**, and the natural next move is to time a privileged action into that blind window (the success-path audit write is best-effort too, per US-012 T-R3).

**Assessment: Low, accepted.** The oracle is available only to a `user:write` holder — who today already holds every permission in the tenant and has little left to escalate to — and the buffer plus `RBAC_AUDIT_WRITE_LOST` / `audit_write_failed` make the impairment loudly visible to operators at the same moment it becomes visible to the attacker. Constant-time padding of a 403 would be disproportionate and would itself be a DoS lever. **No design change.**

**Required mitigation:** one sentence in section 15 item 6 recording the channel and its acceptance, so it is not rediscovered as novel in the Phase-7 code audit. Rate limiting (the T-D7 forwarded obligation) narrows it as a side effect.

---

### [Low] T-T8 / T-S5 — The metadata-injection surface for the new `reason` key is **empty by construction**; the key-ordering claim is correct but the named test cannot detect an escaper failure; and the `outcome` parameterisation touches both success paths (design section 15 item 4 / review items 4 and 7-Spoofing)

**Component:** C1/C3. **STRIDE:** Tampering (audit-record integrity) / Spoofing (actor attribution). **OWASP:** A03, A08, A09.

**(1) Injection surface — narrower than the brief assumes, in the design favour.** The review brief supposes an attacker "can name a custom role anything before probing an assign against it". Verified against `RoleAssignmentService:98`: the T3 path is entered **only** when `RbacRoleNames.TENANT_ADMIN.equalsIgnoreCase(role.getName())`. Since T1/T2 rows carry no `roleName` at all (design section 0.1 item 2, re-verified — `resolveRoleInTenant:312-322` throws without returning the `Role`, so the call-site `catch` has no reference to it), **a denial row `roleName` is either absent or a case variant of `tenant_admin` — at most 4096 harmless strings, none of which can contain a quote, brace, or colon.** No injection payload can reach the new key neighbourhood in this story. (`uq_roles_tenant_name` under `utf8mb4_0900_ai_ci` further means one such row per tenant.)

**(2) The ordering claim is correct — and correctly *not* the primary control.** Confirmed by reading `buildMetadataJson:115-131`: inserting the `reason` block after the `roleName` block yields `traceId, roleId, roleName, reason, attemptedBy`. MySQL binary JSON keeps the **last** duplicate key (empirically established in US-012 section 0.1), so a hypothetical forged `reason` injected through `roleName` would land *before* the real one and lose. The primary control remains Jackson 3 RFC-8259 escaping (US-012 T-T5, verified still in place via the `tools.jackson` import). **US-012 T-T5 warning still applies verbatim and the design section 4.2 wording contradicts it:** "Key ordering is a control, not a style choice" overstates it. Ordering is correct, valuable **defense-in-depth for a broken escaper**, and it must not be described in a way that invites someone to relax the escaping.

**(3) The named test proves less than section 12.2 implies.** `should_keepRealReason_when_roleNameAttemptsDuplicateKeyInjectionOfReason` passes under **both** a working escaper (no duplicate key is ever produced) and a broken one (the duplicate lands before the real `reason` and loses). It is a characterisation test for the ordering property — worth having, and correctly named — but it is **not** an escaper-failure detector. The test that *is* one already exists and must be kept: the `traceId` injection case at `RbacAuthEventAdapterTest:129-164`, where a forged key lands **after** the legitimate `traceId` and would therefore **win** if escaping ever broke. Say so in `04-tasks.md` so the older test is not retired as redundant once the newer, more specific-sounding one lands.

**(4) Spoofing / positional transposition — the residual worth a test, not a design change.** After the widening, `record(...)` takes **four adjacent `String` parameters** (`outcome`, `actorFieldName`, `operation`, `reasonName`) and `recordDenial(...)` takes six positional values including two `UUID`s and a `String`. Any transposition compiles cleanly and produces a silently mislabelled audit row (`outcome="attemptedBy"`, a metadata key literally named `"DENIED"`, `attemptedBy` set to the target). This is the US-012 T-S3 positional-transposition residual, made denser. Two things make it acceptable: the actor and tenant values are still `actor.userId()`/`actor.tenantId()` on the proven T-S3 provenance chain (no client input can reach them), and the section 12.1 value-equal `RbacAuditEvent` matcher plus the section 12.2 literal field assertions catch a transposition mechanically.

**(5) The refactor one regression risk is already covered — keep it that way.** Parameterising the previously hardcoded `"SUCCESS"` (`:85`) changes both existing success call sites, so a mistake there would mislabel **every** successful role assignment and revocation. Grepped and confirmed the guardrails already exist: `RbacAuthEventAdapterTest:77` and `:101` assert `getOutcome()` equals `"SUCCESS"`, and `RoleAssignmentAuditIT:131` and `:160` assert the persisted `outcome`. **Required: `04-tasks.md` must list these four as load-bearing and untouchable**, alongside the negative assertions section 12.1 already protects. No new test needed.

**Assessment: mitigated as designed. No design change.** Required: the section 4.2 wording correction (2), plus the `04-tasks.md` notes (3) and (5).

**Residual:** Low — unchanged from US-012 T-T5, including its forward flag that a future story should constrain role-name character classes at creation time (lone surrogates can still fail an audit insert, leading to T-R3).

---

### [Low-Medium] T-T9 — Not a design defect, but staged on this branch: `./mvnw` is non-functional, a build cache was enabled by default, and the dependency-check CVSS gate was loosened from 9 to 9.5

**Component:** build/verification pipeline. **STRIDE:** Tampering (integrity of the verification evidence). **OWASP:** A08, A05.

Recorded because US-014 is a **test-and-evidence story**: its value is almost entirely the assertions in design section 12, and section 12.5 makes plain that `./mvnw verify` (Docker up, ITs included) is the required gate.

1. **`./mvnw` fails to launch:** `nexus-backend/.mvn/wrapper/maven-wrapper.properties` does not exist (`./mvnw: line 117: ./.mvn/wrapper/maven-wrapper.properties: No such file or directory`), and `git ls-files nexus-backend/.mvn` tracks only `extensions.xml`, `maven-build-cache-config.xml`, and `maven.config` — all three **newly staged on this branch** (`feature/US-014`, after the "CI Revamp" commits). The dependency scan for this review had to be run with the system Maven 3.9.11 instead. The project own documented gate command therefore does not currently run.
2. **A build cache is now enabled by default:** `.mvn/extensions.xml` adds the Maven build-cache extension and `maven-build-cache-config.xml` sets `<enabled>true</enabled>` with `mandatoryClean` commented out and `maxBuildsCached=3`. A build cache that restores a prior module state can report success **without executing** the new ITs — the exact failure mode that would make this story compliance evidence vacuous while the build stays green. `maven.config` additionally forces `-T 1C` (parallel builds).

3. **The OWASP dependency-check gate was loosened in the same staged change:** `git diff --cached nexus-backend/pom.xml` shows `<failBuildOnCVSS>` moved from **9** to **9.5** (alongside a welcome `bcprov-jdk18on` 1.81 -> 1.84 bump). CVSS **9.0-9.4 is still Critical**, so the build no longer fails on Critical-severity CVEs in that band. This is an **A06/A05 control weakening**, is unrelated to US-014's design, and was not caused by this review (the working tree is clean; only the index differs from `HEAD`) — but it is staged on the branch that will carry this story, so it would ship with it.

**Risk:** a Gate-5 or Gate-7 "green build" that never ran the five new `RoleAssignmentAuditIT` methods. For a story whose entire AC3/AC4/AC5 evidence is those methods, that is an integrity failure of the review chain rather than of the code.

**Required mitigation (not this story design change; raise with the branch/CI owner):**
1. Restore `.mvn/wrapper/maven-wrapper.properties` (and the wrapper jar if the repo pins one), or update `PROJECT.md`/`CLAUDE.md` to the actual invocation, so the documented gate is the executed gate.
2. For this story evidence run specifically, require `-Dmaven.build.cache.enabled=false` (or a `mvn clean verify`) and paste the Failsafe summary showing the new ITs **executed**, not restored — cached success is not evidence for a test-only story.
3. Consider `<mandatoryClean>true</mandatoryClean>` so cache entries can only be stored from clean builds.
4. **Restore `<failBuildOnCVSS>9</failBuildOnCVSS>`, or justify 9.5 explicitly in an ADR with the specific advisory that forced it and a dated expiry.** Silently widening the band in which a Critical CVE passes CI is the kind of change that should never be an unexplained one-character diff. If a specific 9.0-9.4 advisory is currently unfixable, suppress *that advisory* rather than raising the global threshold.

**Residual:** Low for the wrapper and cache items, fully closed by running the gate uncached once. **Medium for the CVSS threshold** until it is restored or justified, because it silently disables a shipped supply-chain control.

---

## 4. The six items the design handed over (section 15) — explicit verdicts

### 4.1 Item 1 — Cross-tenant subject placement: severity and accept/reject

**Severity: Low. Verdict: ACCEPT decision 7 as designed. Does not change the design; does not block Gate 2.** Do **not** force `user_id` to the actor: that would break the single "user_id is the subject" convention (`RbacAuthEventAdapter:86`, matching `LOCKOUT`) for one event type, a worse long-term outcome than a Low, reader-side placement quirk. Full reasoning — including the two grounds the design missed, and the two documentation errors that must be fixed (decision 7 rationale is void because section 4.3 excludes the type from the AC5 `IN` set; and the actor becomes reachable only through an unindexed JSON extract) — is **T-I6**.

### 4.2 Item 2 — Audit-volume amplification: confirmed, severity, and is STANDARD-lane routing enough?

**Confirmed: no rate limiter exists on POST/DELETE `/api/v1/users/{userId}/roles`** (verified independently — `LoginRateLimitFilter` is login/refresh-scoped, the controller carries no throttle, US-012 Res. 10 declined it).

**Severity: Low for storage growth; Medium for the connection-pool dimension the design did not price (T-D6).** **Verdict: no blocking follow-up. This ships without a rate-limit story.** The reachable population is `user:write` = `TENANT_ADMIN` only, which is exactly the bounding argument US-012 T-D5 used to accept the identical risk on the success paths; re-accepting it here is consistent, and inventing a rate-limit prerequisite for a 3-point extend/verify story would be disproportionate.

**Is STANDARD-lane routing sufficient mitigation?** **Sufficient for the buffer-eviction hazard, and not a mitigation for amplification at all** — the two must not be conflated. Lane routing governs only what happens to *buffered* events during an `auth_events` outage; it does nothing about steady-state row growth (no retention policy, no reclamation path) and nothing about pool pressure. **Required:** rate limiting on these endpoints becomes a **US-015 entry criterion** alongside the existing US-012 T-E9 criterion, because the US-015 merge is what widens `user:write` beyond `TENANT_ADMIN` and makes T-E9, T-D6, and T-D7 live simultaneously. See **T-D7** and **T-D6** item 4.

### 4.3 Item 3 — Priority-lane exclusion (decision 5): verified against ADR 0011, not accepted on faith

**Verdict: CONFIRMED — decision 5 is the correct security call. Every mechanical premise checks out; the stated rationale contains one factual error that must be corrected before it is appended to the ADR.**

Verified against ADR 0011 sections 1, 2, and 5 (read in full):

| Design premise | ADR 0011 says | Verdict |
|---|---|---|
| Priority lane capacity is 200 | Section 1: "Priority lane — capacity 200"; section 2: total 1000 split 200/800 | Confirmed |
| Overflow is drop-**newest**, per lane | Sections 1 and 2: "Drop-newest, per lane independently" | Confirmed — so a full priority lane **discards the arriving `LOCKOUT`**, which is exactly the claimed hazard |
| Admitting an attacker-reachable type reproduces T-D1 *inside* the protected lane | Section 1 and Alternatives: the two-lane split exists precisely because a `LOGIN_FAILURE` flood could evict `LOCKOUT` in a single FIFO | Confirmed — the analogy is exact, not rhetorical |
| The priority-lane residual is already acknowledged as bounded-but-real | Section 5: "the priority lane itself remains bounded at 200 and could theoretically saturate... accepted as **Low**" | Confirmed — and admitting a floodable type would convert that Low back toward the original High |
| Buffering only happens on write failure, so the hazard needs a concurrent audit-store outage | Section 1: `enqueue` is on the failure path only | Confirmed — correctly scoped by the design ("under a concurrent audit-store outage") |

**One argument in favour of decision 5 that the design does not make, and should:** ADR 0011 section 2 sets the priority-lane depth-warn at **any depth >= 1 sustained for 1 minute -> ticket**, and depth-critical at >= 180 -> **page**. Putting an attacker- or insider-floodable type in that lane would hand a `user:write` holder a **direct pager trigger** — an alert-fatigue DoS against the on-call rotation, on top of the eviction risk. That alone is disqualifying.

**The factual error to correct:** decision 5, the section 3.2 enum comment, and the section 14 ADR text all justify the exclusion on the basis that a denial is "attacker-triggerable at will by **unprivileged** probing" / "**any authenticated caller** can generate them in a loop". **False** — `user:write` is `TENANT_ADMIN`-exclusive (`V5:130-136`). Correct it before writing the ADR (T-R5 mitigation 2).

**The rationale that does hold, and should replace it** — the conclusion is unchanged and, on these grounds, stronger:
1. **A denial row is far cheaper per row than a success row.** `ROLE_ASSIGNED` requires a valid in-tenant target *and* role, no existing active assignment, and an actual state mutation — and a second identical attempt 409s and emits nothing, so sustained generation requires an assign-revoke-assign cycle (2 requests per 2 rows, with lock contention and the last-admin guard in the way). A T2 denial requires only a **published** foreign role id (`V5:11`) and produces **one row per request** with no valid state, no mutation, and no lock.
2. **Forensic value is asymmetric**, exactly as the design argues: a dropped denial loses one probe from a repetitive series; a dropped `ROLE_ASSIGNED` loses a unique, unrepeatable fact. Endorsed.
3. **The lane-membership rule of thumb the section 14 amendment proposes** — priority only if the emission rate is bounded by something an attacker does not control — is sound *and* would, read literally, also disqualify `ROLE_ASSIGNED`/`ROLE_REVOKED` (US-012 T-D5 established that an admin can loop assign-revoke indefinitely). Sharpen it to *cost and uniqueness per row*, not mere triggerability, so the amendment does not contain the seed of an argument for demoting `ROLE_ASSIGNED`.

**Accepted cost of the decision, correctly identified by the design:** during an outage a denial flood can now evict other STANDARD-lane events (`LOGIN_FAILURE`, `REGISTER`, `VERIFY`, `TOKEN_REFRESH_FAILURE`, and so on). That is the lane which already absorbs floods; the trade is right. The existing standard-lane depth-warn (>= 250 for 1 min) is the correct detector and no new alert is needed.

**Test coverage for the decision is adequate and well chosen:** the `EXCLUDE`-mode parameterised test plus `should_containExactlySixTypes` auto-assert non-membership, and the new explicitly named `should_returnFalse_when_isPriorityCheckedOnRoleAssignmentDenied` ensures a future "for consistency with ROLE_ASSIGNED" edit fails a test named after the decision. Keep both.

### 4.4 Item 4 — Metadata JSON injection via `roleName` and the key-ordering control: correctness and test adequacy

**Verdict: the ordering claim is CORRECT; the injection surface in this story is EMPTY by construction; the named test is a characterisation test, not an escaper-failure detector.** In this story a denial row `roleName` can only be absent (T1/T2) or a case variant of `tenant_admin` (T3 fires only on `equalsIgnoreCase(TENANT_ADMIN)`), so no payload can exist. The ordering property is nonetheless correct defense-in-depth and should be kept — but section 4.2 "key ordering is a control, not a style choice" must be softened to match the still-standing US-012 T-T5 warning that ordering is an accident of construction, not the primary control (Jackson 3 escaping is). Retain the `traceId` injection case at `RbacAuthEventAdapterTest:129-164` as the actual escaper-failure detector. Details, plus the positional-transposition and `outcome`-parameterisation residuals: **T-T8 / T-S5**.

### 4.5 Item 5 — Does the call-site `try/catch` close off all denial paths durably?

**Verdict: two of the three barriers are genuinely structural; the third ("no `RequestContext` on `listActive`") is not, and the binding control is a test.**

- **The 409/404 exclusion is structural.** The `catch` type is `InsufficientPermissionException`; `LastAdminRoleException`, `DuplicateRoleAssignmentException`, and `ResourceNotFoundException` are unrelated types. As the design says, this is enforced by the catch type rather than by a condition anyone can get wrong. A future widening to `AccessDeniedException` would be visible in review and would still admit no exception actually thrown on these paths.
- **"Silently swallowing the denial" is a compile error.** Verified by definite-assignment analysis: in `assign`, `Role role;` is read at `:98`, so a `catch` not ending in `throw`/`return` fails to compile; in `revoke`, `role` is read at `:189` with the same effect. This is a real, durable guarantee and the design is right to lean on it.
- **The `listActive` barrier is soft.** `RbacAuditEvent` tolerates a `null` `roleId` and a `null` `requestContext`, and both are null-handled downstream, so `recordDenial(actor, targetUserId, null, null, reason, null)` from a read path compiles. Section 2.4 "structurally unreachable" is an overstatement. The **real** control — mechanical, build-blocking, and adequate — is the section 12.1 row 7 `verifyNoInteractions(rbacAuditPort)` assertion. Keep it, mark it load-bearing, and correct the wording. Details: **T-E14**.

The most likely future regression is a well-intentioned DRY refactor moving the emission into the shared `verifySameTenant` helper (used by all three verbs), which the pinning test catches. That is the right control at the right cost for 3 points.

### 4.6 Item 6 — Is the denial write an oracle?

**Verdict: NO caller-visible oracle. Verified across status code, response body, exception escape, and transaction visibility — the wire contract is bit-identical whether the audit write succeeds, fails, or never runs, and a failed write can never turn a 403 into a 500 (`catch (Exception)` wraps the `REQUIRES_NEW` call).** The pre-existing 403-vs-404 existence oracle (US-012 T-I4, accepted) is unchanged and gains no information. **One new residual, accepted:** a 403 latency now tracks audit-pipeline health, giving a `user:write` holder an oracle for "the audit subsystem is impaired" and hence for a blind window. Low — the impairment is simultaneously loud to operators, and the population already holds every permission in the tenant. Details: **T-I7**.

### 4.7 Item 7 — Standard STRIDE pass on the new code paths

Delivered as section 2 component table and section 3 findings. Summary by category:

- **Spoofing** — actor attribution (`attemptedBy`, `tenant_id`) is `actor.*` on the proven US-012 T-S3 chain; no client input can reach it. New residual: positional transposition across four adjacent `String` parameters, covered by the section 12.1/12.2 assertions (**T-S5**, Low).
- **Tampering** — the row is immutable once written (append-only triggers verified, `INSERT,SELECT`-only grant unchanged). The metadata injection surface is empty in this story; ordering is correct defense-in-depth (**T-T8**, Low). Build- and supply-chain-pipeline integrity note (**T-T9**, Low-Medium).
- **Repudiation** — durability across TX1 rollback is real and correctly mechanised (`REQUIRES_NEW`, verified). Inherits T-R3/T-R4 unchanged, with a new `operation=deny` tag that usefully separates a lost denial from a lost assignment. **New: the trail omits `PERMISSION_ABSENT`, i.e. the T-E1 attempt (T-R5, Medium).**
- **Information disclosure** — no PII; no caller-visible change (**T-I7**); cross-tenant `user_id` placement accepted (**T-I6**).
- **Denial of service** — nested connection on an unrate-limited path (**T-D6**, Medium); unbounded append-only growth (**T-D7**, Low). Lane routing correctly contains the buffer dimension only.
- **Elevation of privilege** — **none introduced.** No new authorization decision point; every outcome bit-identical; the emission is strictly post-decision. The only EoP-adjacent risk is scope creep into the read path (**T-E14**, Low).

---

## 5. Threats considered and found adequately mitigated (no action)

| Threat | STRIDE | Why adequate (verified this session) |
|---|---|---|
| Denial row rolled back together with the denial (the failure AC4 exists to prevent) | R | `SecureEventService.recordEvent` is `@Transactional(REQUIRES_NEW)` (`:52-55`), invoked from a *different* bean so the proxy applies; TX1 is suspended, TX2 commits, and TX1 later rollback cannot affect it. The section 2.3 ordered invariant is correct, and the section 12.4 insistence on querying `auth_events` **after** `assertThatThrownBy` is the only assertion that proves it — a Mockito `verify` would not. Keep that requirement verbatim. |
| A failed denial audit write escapes and changes the response | D/I | `catch (Exception e)` in `record` wraps the entire body including the port call; converts to ERROR `RBAC_AUDIT_WRITE_LOST` plus `nexus.rbac.audit_write_failed{operation}`. Verified. |
| 409/404 paths emitting a denial event (audit-trail pollution, Risk R-2) | R | Enforced by the `catch` **type**, not a condition. Structural. |
| `GlobalExceptionHandler` coupling or misattributing another feature 403 (Risk R-3) | T/E | Resolved by construction — design section 13 pins zero diff to `GlobalExceptionHandler`, verified untouched. The right call. |
| Cache-invalidation lever on an attacker-triggerable path | T/D | Section 7 decision **not** to call `PermissionCachePort.evict` on a denial is a genuine security improvement: it denies an attacker a free cache-invalidation primitive. Pinned by the retained `verifyNoInteractions(permissionCachePort)` assertions (section 12.1). |
| SQL / JPQL / SpEL injection | T | No new query, no new repository method (`JpaAuthEventRepository` stays bare), no string-concatenated SQL. The AC5 query is a test-only parameterised literal. `@RequiresPermission` values remain compile-time constants. **None.** |
| Log injection (CRLF) via the new path | T | No new log statement (decision 9). The existing WARN uses SLF4J key-values, and the only tenant-controlled string on a denial row is `roleName`, which is a case variant of `tenant_admin`. |
| Deadlock between the T3 `FOR SHARE` lock and the audit INSERT | D | `auth_events` is never read or locked by the RBAC path — no lock cycle. Design section 0.1 item 3 and section 8.3 are correct. The *duration* concern is T-D6, not deadlock. |
| Schema / migration risk | A08 | Zero DDL; `ROLE_ASSIGNMENT_DENIED` (22 chars) and `"DENIED"` (6) fit `VARCHAR(64)`/`VARCHAR(20)` with no CHECK; the existing `GRANT INSERT, SELECT ON nexus.auth_events` covers the row; `ddl-auto=validate` unaffected. Verified against `V2:76-90`. |
| ArchUnit / layering regression | E/A05 | Re-verified: `DenialReason` is in `..common.security..` (not `org.springframework.security..`) and is already imported by `RoleAssignmentService:5`; `AuthEventType` never crosses the port; the new parameters are a record and an enum, so `rbac_application_methods_must_not_accept_principal_or_map` stays green. No new rule needed — the design section 3.5 table is accurate. |
| AC5 query contract drift | A08 | `ROLE_ASSIGNMENT_DENIED` is deliberately outside the AC5 `IN` set, so no existing or future consumer of that query changes behaviour. The `created_at`-strictly-increasing flake control in section 12.4 is well designed, and the note **not** to add `event_type` as a tie-break sort key is exactly right — it would mask a real ordering regression. |
| Feature-flag / kill-switch posture | E/D | `feature.nexus-us012-rbac-role-assignment.enabled=false` removes the controller bean and therefore all emission; there is deliberately no way to run the endpoints with denial auditing off. Fail-closed, and the right call. |
| A06 vulnerable components | A06 | `dependency:tree`: 198 artifacts, unchanged from the US-012 baseline, **zero new dependencies**. Dual Jackson majors persist (benign Boot-4 transition state); the adapter correctly injects the Jackson-3 Spring bean, so US-012 T-E13 is closed and stays closed. `npm audit` not applicable (zero frontend diff). |

---

## 6. Residual risk summary

| ID | Sev | Threat | Status / residual after required mitigations |
|---|---|---|---|
| **T-R5** | Medium | The trail omits `PERMISSION_ABSENT` — the T-E1 escalation attempt the story cites as its motivation is not audited | **Needs documentation mitigation** (correct section 15 item 6 **and** the ADR 0011 amendment text before it is appended) plus a forwarded audit-coverage obligation. Low once the claim matches the coverage. |
| **T-D6** | Medium | Inline `REQUIRES_NEW` holds 2 of 10 default pool connections on an unrate-limited path; 30s acquisition timeout; T3 extends a `FOR SHARE` hold | **Needs it priced in section 8.3, pool telemetry on the section 11 watch list, and a rollback trigger.** Low today; Medium from the US-015 merge without a rate limiter. |
| **T-I6** | Low | T1 rows pair the actor `tenant_id` with a foreign-tenant `user_id` in indexed columns | **ACCEPTED — decision 7 upheld.** Two documentation corrections required (decision 7 void AC5 rationale; the unindexed-`attemptedBy` forensic cost) plus an Epic 7 forward note. |
| **T-D7** | Low | Unbounded append-only growth from denial probing; no rate limiter, no retention policy; T2 is free via published role ids | **ACCEPTED**, consistent with US-012 T-D5. Restate with the correct (`TENANT_ADMIN`) population; **US-015 entry criterion** for rate limiting. |
| **T-E14** | Low | The `listActive` exclusion is convention plus one test, not "structurally impossible" as claimed | Low once section 2.4 and decision 2 are reworded and `04-tasks.md` marks `verifyNoInteractions(rbacAuditPort)` load-bearing. |
| **T-I7** | Low | A 403 latency leaks audit-pipeline health (new side channel); otherwise no caller-visible oracle — verified | **ACCEPTED.** One sentence in section 15 item 6. Narrowed as a side effect of the T-D7 forwarded rate limiting. |
| **T-T8 / T-S5** | Low | Ordering is defense-in-depth not a primary control; the named test cannot detect escaper failure; four adjacent `String` params invite transposition; `outcome` parameterisation touches both success paths | **Mitigated as designed.** Soften the section 4.2 wording; `04-tasks.md` must protect the existing `traceId`-injection test and the four `outcome` equals `SUCCESS` assertions. |
| **T-T9** | Low-Medium | `./mvnw` is broken in this tree, a build cache was enabled by default, and `failBuildOnCVSS` was loosened 9 -> 9.5 — all staged on this branch | Not a design defect. Restore the wrapper; run the evidence gate with the cache disabled; **restore the CVSS gate to 9 or justify 9.5 in an ADR with a dated expiry**. |
| *inherited* | Medium | **US-012 T-R3** — a commit-boundary audit failure is loud but lossy | Unchanged, and now also applies to denials with the useful `operation=deny` tag separation. Still live. |
| *inherited* | Medium | **US-012 T-R4** — lane assignment of role-change events | Unchanged for the success types; the US-014 routing decision is separately confirmed correct (section 4.3). |
| *inherited* | Low | **US-012 T-E9** — `user:write` alone can revoke `TENANT_ADMIN` | Unchanged; still a US-015 entry criterion, now joined by T-D6 and T-D7. |
| *inherited* | — | **US-011 T-02** — tenant-provenance invariant | **Unchanged and still load-bearing.** US-014 adds no second producer of authentication details. |

---

## 7. Verdict

### APPROVE FOR GATE 2 — no Blocker, no Critical, no High

The design is proportionate, well grounded in the actual code, and its central correctness claim — that an inline pre-throw `REQUIRES_NEW` write survives the caller rollback — **is real and was verified at the mechanism level**, not taken on faith. Three of its judgement calls deserve explicit endorsement:

- **Decision 5 (STANDARD lane) is the right security call**, confirmed against the actual ADR 0011 capacity, per-lane drop-newest policy, and depth-warn thresholds — with one extra argument in its favour (an attacker-triggerable **pager**) that the design did not make, and one factual premise that must be corrected before it is written into an ADR.
- **Decision 5 emission point (in the service, not `GlobalExceptionHandler`)** resolves Risk R-3 structurally rather than by mitigation, and the 409/404 exclusion is enforced by the `catch` **type** — one of the cleanest structural controls in the epic to date.
- **Not evicting the permission cache on a denial** (section 7) denies an attacker a free cache-invalidation lever. A genuine, unforced security improvement.

**Nothing here blocks Gate 2 or `/breakdown`.** The two Medium findings are a documentation-accuracy failure (T-R5) and an unpriced operational cost (T-D6); neither redirects the approach, and both are closed by edits measured in lines.

### (c) Required before `/breakdown` closes (ranked)

1. **T-R5 — correct the coverage claim in section 15 item 6 *and* in the section 14 ADR 0011 amendment text before it is appended.** "Any authenticated caller" / "unprivileged probing" is false: `user:write` is `TENANT_ADMIN`-exclusive. Highest priority because an ADR is durable and because Security and Compliance is this story persona — the trail must not be described as covering the T-E1 attempt when it structurally cannot. Add the forwarded audit-coverage obligation for `PERMISSION_ABSENT`.
2. **T-D6 — price the nested-connection cost in section 8.3** (pool 10, timeout 30s, nesting depth 2, saturation at ~5 concurrent denials; cross-reference the US-012 T-R3 pool warning and the loss of the D14 `afterCommit` property) and **add `hikaricp_connections_pending` to the section 11 watch list and rollback trigger**.
3. **T-I6 — replace decision 7 rationale** (it contradicts section 4.3, which excludes the type from the AC5 `IN` set) with the "user_id is the subject" convention, and record the unindexed-`attemptedBy` forensic cost plus the Epic 7 forward note.
4. **T-E14 — reword section 2.4 and decision 2** from "structurally impossible" to the accurate claim, and mark the section 12.1 row 7 `verifyNoInteractions(rbacAuditPort)` assertion as load-bearing in `04-tasks.md`.
5. **T-T8 — soften the section 4.2 "ordering is a control" wording** to defense-in-depth (per US-012 T-T5, still standing), and note in `04-tasks.md` that the `RbacAuthEventAdapterTest` `traceId`-injection case and the four `outcome` equals `SUCCESS` assertions must not be retired.
6. **T-D7 — restate section 15 item 3** with the correct population and the T2 / published-role-id cheap path, explicitly reconciling against US-012 T-D5, and add rate limiting to **US-015 entry criteria** alongside T-E9 and T-D6.
7. **T-I7 — one sentence** recording the audit-health timing channel as an accepted residual.
8. **T-T9 — raise with the branch/CI owner** (not a design change): restore the Maven wrapper, run this story evidence gate with the build cache disabled, and **restore `failBuildOnCVSS` to 9** (or justify 9.5 in an ADR with a dated expiry and a per-advisory suppression instead of a global threshold change).

### (b) Accepted residual risks with stated justification

**T-I6** (cross-tenant subject placement — decision 7 upheld) · **T-D7** (append-only growth, no rate limiter — consistent with US-012 T-D5, forwarded to US-015) · **T-I7** (audit-health timing channel) · the remaining **T-D6** exposure after telemetry (privileged, observable, bounded duration) · the inherited **T-R3**, **T-R4**, and **T-E9** residuals, unchanged.

### (a) Fully mitigated by the design as written — no action

Durability across rollback (`REQUIRES_NEW`, mechanism verified) · the 409/404 exclusion (enforced by catch type) · "swallow the denial" made a compile error (definite assignment) · no `GlobalExceptionHandler` coupling · no cache-eviction lever on a denial · no authorization change and no new authz decision point · no PII, no new crypto, no new dependency, no DDL, no new ArchUnit rule · injection surface empty by construction · AC5 query contract unaffected · fail-closed feature-flag posture · the well-designed `created_at` flake control in section 12.4.

### Gate 2 recommendation

**Approve. Proceed to `/breakdown` with items 1-8 folded into the design revision** (items 1 and 2 in the same pass, since item 1 changes text destined for an ADR and item 2 changes the rollout plan `/breakdown` will carry). Items 3-7 are wording and task-note changes that can land together. Item 8 is a branch-hygiene action for the CI owner, but it gates the *evidence* this story exists to produce, so it should not be deferred past Gate 5.

---

### Cross-references

- Design under review: `docs/features/US-014/03-design.md` (section 0 decisions 1-12 and section 0.1 refinements; sections 1-2 including the section 2.3 durability invariant; 3.1-3.5; 4.1-4.3; 5-11; 12.1-12.5; 13; 14 ADR amendment; 15 items 1-6)
- Requirements: `docs/features/US-014/01-requirements.md` section 7 Decisions 1-5 (binding), section 6 R-1..R-5, section 8 Gaps · Impact: `docs/features/US-014/02-impact.md` section 14
- Prior threat models: `docs/features/US-009/03b-threat-model.md` (**T-E1** — this story stated motivation; T-S2, T-R1, T-T1, T-I2, T-I3, T-D2) · `docs/features/US-012/03b-threat-model.md` (**T-R3**, **T-R4**, **T-T5**, **T-I4**, **T-D5**, **T-E9**, T-S3, T-E7, T-E8, T-E13 — all re-examined here) · `docs/features/US-011/03b-threat-model.md` (T-02 inherited unchanged) · `docs/features/US-013/03b-threat-model.md` (the T-03 mechanical-versus-remembered-control principle, applied in T-E14)
- ADRs: **0011** (sections 1, 2, 5 verified in full for section 4.3; section 7 render-time obligation now covers one more row type) · 0002, 0003, 0005, 0009, 0012, 0013, 0014, 0015, 0016
- Code and schema verified this session: `rbac/application/RoleAssignmentService.java` · `rbac/application/port/out/{RbacAuditEvent,RbacAuditPort}.java` · `rbac/interfaces/rest/UserRoleController.java` · `identity/infrastructure/audit/RbacAuthEventAdapter.java` · `identity/domain/AuthEventType.java` · `identity/application/service/SecureEventService.java` · `common/security/{DenialReason,InsufficientPermissionException}.java` · `common/web/GlobalExceptionHandler.java` (`:159-176`) · `db/migration/V2__identity_schema.sql` (`:73-103`) · `db/migration/V5__rbac_schema.sql` (`:107-136` seed) · `src/main/resources/application.yml` (`:22-33`) · `RbacAuthEventAdapterTest` and `RoleAssignmentAuditIT` (existing `outcome` and injection assertions) · `.mvn/**`
- Scans run: `mvn -o dependency:tree` — 198 artifacts, zero new dependencies (system Maven 3.9.11; `./mvnw` non-functional, see T-T9). `npm audit` not applicable — zero frontend diff.

### Notes on process

**Nothing in the repository was modified by this review.** No source file, test, configuration, or migration was touched; Bash was used only for the dependency scan and read-only inspection of `.mvn`. The only file written is this document.
