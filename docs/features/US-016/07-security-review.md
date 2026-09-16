# US-016 — Security Review (Phase 7 code audit)

**Reviewer:** Application Security Engineer (hostile-mindset code audit)
**Date:** 2026-09-16
**Branch:** `feature/US-016` (no commits; audit performed against `git diff HEAD` + untracked US-016 files, `origin/main` == HEAD == 76470e2)
**Standards:** `SECURITY.md` (repo root), OWASP Top 10 2021
**Cross-referenced:** `docs/features/US-016/03b-threat-model.md` (RC-8…RC-14, RES-1…RES-11), `03-design.md` rev 2, `docs/adr/0017-privilege-based-role-assignment-gate.md`, `docs/features/US-016/06-code-review.md`

**Verdict: APPROVED** — 0 Blocker, 0 High, 3 Medium, 4 Low. No exploitable authorization defect found. The three Mediums are detection-quality and DoS-bound gaps, not access-control gaps; they should be tracked, not merge-blocking.

---

## 0. Review attestation (standing policy — auth, crypto and PII are never approved silently)

- **Authorization / privilege gating — reviewed in depth. This is the story's substance.** See §1. No bypass found on any path I could construct.
- **Authentication — reviewed. No findings.** No authentication code added. Admin status is never derived from a JWT claim on either branch of the gate; `RoleAssignmentService` still accepts only `RoleChangeActor`/`UUID`/`RequestContext`. The T-S7 proof was extended to the new privilege branch by a real IT (`RoleAssignmentSecurityIT#should_return403WithNotTenantAdmin_when_staleJwtStillClaimsAdminAfterOutOfBandRevocation_forDangerousCustomRoleAssign`), which mints a token while the caller is a genuine admin, revokes out of band, and asserts 403 — verified present in the diff, not asserted from the design.
- **Tenant isolation — reviewed. No findings.** See §2. Every read, lock and write on the changed paths is scoped to `actor.tenantId()` or to an id already tenant-verified in the same transaction.
- **Audit / PII-in-logs — reviewed. No new PII exposure.** See §3.
- **Cryptography — reviewed. No findings.** No crypto, key material, randomness source or id generation introduced. No `Math.random` anywhere in the changed code (grepped). The one new binary conversion (`JpaUserRoleAssignmentAdapter#toBytes`) is a UUID→`BINARY(16)` layout conversion, not crypto, and fails **closed** if wrong (a mismatched bind makes `hasActiveAdminAssignment` return false ⇒ deny).
- **Secrets — reviewed. No findings.** Two new config keys (`nexus.rbac.denial-throttle.max-denials`, `.window-seconds`), both integers, both `${ENV:default}` placeholders, neither sensitive. No credential, token or connection string introduced or logged.
- **Dependencies — reviewed. No new dependency.** `RateLimitRoleChangeThrottleAdapter` imports only `jakarta.annotation`, `java.time`, `java.util.concurrent`, SLF4J, Spring, and the already-shipped `identity.application.port.out.RateLimitStore`/`RateLimitResult`. `RoleChangeThrottlePort` imports only `java.util.UUID`. `pom.xml` is byte-identical to `origin/main`. **US-016 takes on no new library.** (The pre-existing CVSS ≥ 9.5 transitives inherited from `main` are out of this story's scope and are not re-litigated here.)

---

## 1. Authorization / privilege gating — the hostile analysis

**The gate, as shipped** (`RoleAssignmentService.java:162-167`, `:296-315`, `:529-567`):

```java
boolean nameMatch  = isNamedTenantAdmin(role);                        // FR-3
boolean privileged = nameMatch || carriesDangerousPermission(role.getId());  // FR-1
if (privileged) requireActiveTenantAdmin(actor, targetUserId, role, USER_WRITE, op, nameMatch, ctx);
```

Attacks attempted and **not** found viable:

| Attack | Result |
|---|---|
| Short-circuit exploitation — craft input that skips M7 *and* clears `privileged` | **Not possible.** `\|\|` can only skip the read when `nameMatch` is true, i.e. when the gate applies anyway. |
| Confused deputy on `hasActiveAdminAssignment` (T-E22, both axes) | **Correct in code**: `(actor.userId(), adminRoleId-from-M8, actor.tenantId())` — never `targetUserId`, never `role.getId()`. Both axes are mechanically pinned by unit assertions (`verify(port, never()).hasActiveAdminAssignment(any(), eq(roleId), any())` **and** `…(eq(targetUserId), any(), any())`) at 10+ sites in `RoleAssignmentServiceTest`. RC-14 implemented. |
| Fail-open when the tenant has no seeded `TENANT_ADMIN` role | **Fails closed.** `adminRoleId.isPresent() && …` short-circuits before M5 (R-10/T-E18 precedent followed). |
| Dangerous-permission name spoofing (whitespace/case/unicode variants of `user:write`) | **Not reachable.** `permissions` is a fixed seeded catalogue; `nexus_app` holds `SELECT` only on it. `RbacDangerousPermissions.contains` is `equalsIgnoreCase`, matching the column's `utf8mb4_0900_ai_ci` collation. |
| Reserved-name squat (`tenant_admin`) to shadow M8 | **Not reachable.** `uq_roles_tenant_name` under a CI collation + `RbacRoleNames.RESERVED` (US-015 RC-1). |
| **Cache staleness bypass** (explicitly asked) | **Not reachable.** `permissionCachePort` is used *only* for `evict()` post-commit (`:196`, `:349`). The gate never reads the permission cache; both the dangerous-permission read (M7) and the admin check (M5) go to the DB inside the transaction. |
| **TOCTOU / partially-committed transaction** (explicitly asked) | **Not exploitable.** M7 is non-locking by deliberate design (D5, MC-1 — `permissions` is `SELECT`-only for `nexus_app`, so a `@Lock` would fail in production only). Both race directions are self-defeating: attach-between-read-and-write requires admin authority (AC11); detach-then-assign yields a role that confers nothing; on revoke, a stale "benign" read only permits an operation the caller was already authorized to perform a microsecond earlier. All reads and the write share one `@Transactional` boundary; the audit/evict side effects are `afterCommit`-only, with a documented inline fallback when no synchronization is active. |
| Bypass by reaching `user_roles` writes from elsewhere | **No alternative path.** `userRoleAssignmentPort.assign` has exactly one call site (`RoleAssignmentService:184`); `revoke` one (`:340`); both controllers carry `@RequiresPermission` (`UserRoleController:85,118,146`). |
| Ordering abuse: can a 409 precede the 403? | **No.** `assign()` gates before `hasActiveAssignment` (409 `RBAC_004`); `revoke()` gates before the AC5 lockout (409 `RBAC_002`). D1 as designed; this *removes* the pre-existing `RBAC_002` admin-roster oracle (T-I12). |

**RES-9 (caller-side admin test remains name-based) re-examined for exploitable inconsistency beyond what is already accepted.** The target-side test is privilege-based; the caller-side test is `hasActiveAdminAssignment` against the literal `TENANT_ADMIN` role id. The asymmetry is **fail-closed in both directions**: an admin-equivalent custom-role holder is *subject to* the gate and cannot *pass* it (an availability dead end, not an escalation), and there is no input that makes a non-admin read as an admin. I could construct **no** exploitable inconsistency beyond the accepted operational one. RES-9 is correctly carried, and `docs/story/2-rbac/US-017.md` exists with an id, pairing RES-3 and RES-9 as one Epic-3 question — the merge-checklist item the threat model required.

**Claimed-vs-actual cross-check against `03b-threat-model.md`.** Every RC is verifiable in the diff:

| Claim | Status in code |
|---|---|
| RC-8 (T-E21 mint-side holder signal) | **Shipped.** `RoleManagementService.attachPermission:190-191` (dangerous path only) → `holderCount` on `RoleAuditEvent`, `RBAC_DANGEROUS_PERMISSION_GRANTED_TO_EXISTING_HOLDERS` WARN, bounded `holders` bucket tag. Javadoc carries the "do not delete this signal" note on both sides. `DangerousPermissionHolderSignalIT` proves it end to end. RES-1 correctly split into (a)/(b) and **not** flipped to "closed". |
| RC-9 (index granularity, isolation, harness C, composed timer) | **Shipped.** M5 converted to a native query with `FORCE INDEX (fk_user_roles_role)` + an `EXPLAIN`-asserting IT; isolation-level assertion (MC-6); `LastAdminLockoutIT` harnesses A/B/C; `nexus.rbac.privileged_revoke_lock_hold{outcome}` composed timer stopped inside `afterCommit` (the earlier under-measurement bug was fixed). |
| RC-10 (throttle) | **Shipped** — with the scope caveats in **M-1** and **M-3** below. |
| RC-11 (precision + canary discriminator) | **Partially shipped.** The `privileged_role_change_blocked{operation, matchedOn}` counter and the page/ticket re-tiering landed. The canary discriminator did **not** — see **M-2**. |
| RC-12 (no adapter write capability over `role_permissions`) | **Shipped, preferred option.** M7's JPQL is hosted on the already-injected `JpaRoleRepository`; `JpaUserRoleAssignmentAdapter`'s constructor gained **zero** dependencies; the Javadoc states the property. |
| RC-13 (persist `operation`, fix the runbook) | **Shipped.** `recordRoleAssignmentDenied(event, reason, operation)` persists `metadata.operation`; the `audit_write_failed{operation="deny"}` tag is deliberately kept as a separate axis, documented in both the port and the adapter. Runbook §6 replaces the current-admin comparison with the point-in-time `ROLE_ASSIGNED` check and ships executable DBA SQL, with the two blind spots stated. |
| RC-14 (MC-3 both axes) | **Shipped** (see table above). |

---

## 2. Tenant isolation — verified query by query (A01)

| Call | Scoping |
|---|---|
| `verifySameTenant(targetUserId, …)` | 404 if unknown, 403 `CROSS_TENANT_TARGET` if `targetTenantId != actor.tenantId()` |
| `resolveRoleInTenant(roleId, …)` | 404 / 403 on `role.getTenantId() != actor.tenantId()` |
| `findActiveAssignmentRef(userId, roleId, tenantId)` | explicit `ur.tenantId = :tenantId` |
| `lockActiveAssignmentIds(tenantId, roleId)` (M1) | tenant-scoped |
| `findRoleIdByName(actor.tenantId(), TENANT_ADMIN)` (M8) | tenant-scoped |
| `hasActiveAdminAssignment(actor.userId(), adminRoleId, actor.tenantId())` (M5) | tenant-scoped in the native predicate |
| `findPermissionNamesForRole(roleId)` (M7) | **not** tenant-scoped — precondition only (see **L-1**); safe at its one call site, which tenant-verifies two statements earlier |
| `revoke(ref.id(), revokedAt)` (M6) | id-only, but `ref` was produced by a tenant-scoped read in the same transaction |
| `findActiveUserIdsForRole(role.id())` (M9, new runtime caller) | role id pins the tenant (`roles.tenant_id`); only `.size()` is used |
| Throttle key | `"RBAC_DENY:" + tenantId + ":" + actorUserId` — tenant- and actor-scoped, distinct namespace from `IP:` / `USER:` / `FORGOT_USER:`; no collision is constructible because both components are server-derived UUIDs |

Denial audit rows are always written under `actor.tenantId()`, never the target's, and carry `roleName = null` on the cross-tenant paths by construction — so a denial row can never leak another tenant's role name. Verified.

**A03 Injection:** no finding. All queries are JPQL/native with named parameters; the one new native query's only literal is the fixed `FORCE INDEX (fk_user_roles_role)` clause. No string concatenation of user input anywhere in the diff.

---

## 3. Sensitive data, logging and audit (A09)

**No PII added.** Every new log field and metric tag is a UUID, an integer, or a bounded constant: `operation ∈ {assign, revoke}`, `matchedOn ∈ {ROLE_NAME, DANGEROUS_PERMISSION}`, `outcome ∈ {denied, lockout, revoked, error}`, `privileged ∈ {true,false}`, `callerIsAdmin ∈ {true,n_a}`, `holders ∈ {0,1,2-10,>10}`, `holderCount` (int), `maxDenials`, `windowSeconds`. No email, display name, IP or token.

**Log injection (CRLF):** closed and inherited. The only tenant-controlled string reaching a new sink is `roleName`, bounded by `@Size(max=64)` + `@Pattern("^[A-Za-z0-9][A-Za-z0-9 ._-]*$")` on `CreateRoleRequest`, which excludes CR/LF/U+2028/U+2029; the encoder is structured key-value. US-016 adds no new free-text sink.

**Audit metadata:** built via Jackson `ObjectMapper` on a `LinkedHashMap` before any transaction opens; nulls are omitted, never serialised as JSON `null`. No JSON injection surface.

**Cardinality:** all new metric series are bounded (4 + 2 + 4, plus ≤4× and ≤2× multipliers on two already tenant-keyed counters). No unbounded dimension introduced.

---

## Findings

```
[Medium] Denial-throttle suppression window is an attacker-controlled blind spot for the page-severity
         dangerous-permission alert and for the durable denial audit row
File: nexus-backend/src/main/java/com/example/nexus/rbac/application/RoleAssignmentService.java:456-478
      (requireNotThrottled), interacting with :529-567 (requireActiveTenantAdmin)
OWASP: A09 Security Logging & Monitoring Failures (secondarily A04 Insecure Design)
Issue: requireNotThrottled() short-circuits at check 3.5, above the gate. A suppressed request therefore
       produces NO RBAC_PRIVILEGED_ROLE_CHANGE_BLOCKED WARN, NO
       nexus.rbac.privileged_role_change_blocked{operation,matchedOn} increment, and NO durable
       ROLE_ASSIGNMENT_DENIED row in auth_events. The only page-severity alert this story ships for the
       new gate, nexus_rbac_privileged_role_change_blocked_dangerous, is driven exclusively by that
       counter's matchedOn="DANGEROUS_PERMISSION" series.
       The throttle is keyed on (tenantId, actorUserId) — i.e. on the attacker themselves — so the
       attacker chooses when to enter the suppressed state. Burning ~6 cheap, low-severity denials first
       (matchedOn="ROLE_NAME" name-match denials, which only ticket via
       nexus_rbac_privileged_role_change_blocked_byname) puts the actor in the suppressed window, after
       which every DANGEROUS_PERMISSION attempt for the rest of the window is invisible to the page
       alert and leaves no durable audit row.
       The design's own triage assumption is the reverse ordering: runbook.md §3 step 2 reads "If any
       [preceding denial] carried matchedOn='DANGEROUS_PERMISSION', they already triggered the page
       alert — this throttle alert is the abuse/capacity signal, not the primary detection." That holds
       only if the dangerous attempts come first. Nothing forces that order.
Risk: An attacker gets a self-serve, deterministic suppression of the highest-severity detection signal
      and of the durable forensic record for attempted privilege escalation on the dangerous-permission
      path. NO access is gained — the gate still denies every suppressed request — so this is detection
      loss, not an authorization bypass. Residual detection: nexus_rbac_denial_throttle_engaged (ticket)
      and nexus_rbac_role_change_denied_not_admin (ticket; suppressed requests DO still increment
      nexus.rbac.permission_denied via GlobalExceptionHandler), so the event degrades from page to
      ticket rather than to silence.
Fix (cheapest first):
      (a) Alerting-only, zero code: promote nexus_rbac_denial_throttle_engaged to page, or add a
          composed rule `denial_throttled > 0 and on(tenantId) …_blocked{matchedOn="DANGEROUS_PERMISSION"}`;
          and correct runbook.md §3 step 2, which currently assumes the benign ordering.
      (b) Code: still emit the D15 counter for suppressed requests with an added bounded tag
          throttled="true" and matchedOn="UNKNOWN" (the gate has not run, so matchedOn is genuinely not
          known — do not run M7 to find out, that would defeat the throttle's purpose).
      Whichever is chosen, record the suppression window as an explicit, adversarially-reachable
      detection blind spot in 03b-threat-model.md §5 (RES-11) and monitoring.md §1.
```

```
[Medium] The gate-bypass canary has no reachable firing path — RC-11.2's required discriminator was
         implemented as a control-flow-inferred constant
File: nexus-backend/src/main/java/com/example/nexus/rbac/application/RoleAssignmentService.java:228-233
OWASP: A09 Security Logging & Monitoring Failures
Issue: .tag("callerIsAdmin", privileged ? "true" : "n_a") derives the tag from `privileged`, not from
       M5's own boolean result. "false" is therefore unemittable by construction, and the page alert
       nexus_rbac_gate_bypass_canary —
       increase(nexus_rbac_self_role_assignment_total{privileged="true", callerIsAdmin="false"}[5m]) > 0
       — can never fire. RC-11.2 asked for "a bounded tag recording the gate's own admin determination";
       what shipped records the gate's own *control flow*, which on the success path is tautologically
       "the gate passed".
       Both halves of RC-11.2 were nonetheless satisfied in effect: the canary cannot page on the Epic-3
       bootstrap happy path (it cannot page at all), and the legitimate shape was split out as
       nexus_rbac_admin_privileged_self_assignment (ticket).
Risk: The one page-severity runtime detective control for T-E22 (a future refactor passing
      targetUserId, or role.getId(), to hasActiveAdminAssignment — both compile, both fail OPEN) is
      inert. Such a bug makes M5 answer the wrong question, return true, let the gate pass, and emit
      callerIsAdmin="true" — silence. Detection then rests entirely on the MC-3/RC-14 unit assertions,
      which the same refactor would be updating. A page alert that cannot fire is worse than no alert:
      it creates false assurance in the runbook and in §0.3's attestation.
      Mitigating and worth stating: this is honestly self-disclosed in monitoring.md §2 and runbook.md
      §1 ("no known code path produces it today; treat any occurrence as maximally anomalous"). It is a
      known gap, not a hidden one.
Fix: Give the tag an INDEPENDENT second source or retire it. Cheapest independent source already
     exists: callerHoldsActiveTenantAdmin(actor) (the non-locking, name-based redaction helper,
     RoleAssignmentService:580) derives caller-admin status by a deliberately different mechanism (M4
     projection over role names) than M5 does (locking read keyed on an M8-resolved role id). Tagging
     callerIsAdmin from that helper on the self-assignment path would make a disagreement between the
     two mechanisms — which is exactly what T-E22's fail-open looks like — observable. Cost: one extra
     non-locking read on the self-assignment path only. If that cost is unacceptable, delete the alert
     and state plainly in 03b-threat-model.md that T-E22 has NO runtime detection and is guarded only
     by MC-3.
```

```
[Medium] The denial-throttle bound multiplies by replica count under the default in-memory store;
         §4.8's stated bound is unqualified
File: nexus-backend/src/main/java/com/example/nexus/identity/infrastructure/security/
      RateLimitRoleChangeThrottleAdapter.java:65, 103-145
      nexus-backend/src/main/java/com/example/nexus/identity/infrastructure/security/
      InMemoryRateLimitStore.java (default: @ConditionalOnProperty matchIfMissing = true)
OWASP: A04 Insecure Design / A05 Security Misconfiguration (bound weaker than documented)
Issue: The adapter's Javadoc records the per-JVM caveat for the *throttled-until transition map* under
       the Redis store (RES-11). It does not record that with the DEFAULT store
       (nexus.security.rate-limit.store-type unset ⇒ InMemoryRateLimitStore) the *denial count itself*
       is also per-JVM. In an N-replica deployment the effective bound is max-denials × N fully
       processed denials per window, not the documented 5 per 60 s. Design §4.8 and monitoring.md §3
       both state the bound without this qualification, and §4.8 is the document that justifies
       accepting T-D10, T-D11, T-R9 and RES-8 at Low "because D14 bounds them".
Risk: Each of those fully-processed denials costs a durable auth_events row, a REQUIRES_NEW second
      connection borrow, and — on the revoke name-match path — acquisition of M1's FOR UPDATE lock over
      every active TENANT_ADMIN row in the tenant, held across M8 + M5 + that nested audit write. At N
      replicas the composed T-D10/T-D11 pressure a single user:write holder can generate is N× what the
      threat model costed. Authenticated, so attribution exists; per-tenant blast radius; no wrong
      authorization outcome.
Fix: (a) Qualify the bound in 03-design.md §4.8 and monitoring.md §3: "per replica under the default
     in-memory store; cluster-wide counting requires nexus.security.rate-limit.store-type=redis, and
     even then the throttled-until transition is per replica (RES-11)".
     (b) State in the deployment/runbook docs that any multi-replica environment must either set
     store-type=redis or divide max-denials by the replica count.
     (c) Optional: add the replica dimension to the RES-11 entry in 03b-threat-model.md §5.
```

```
[Low] M7's new query is the only read on these paths without a defense-in-depth tenant predicate
File: nexus-backend/src/main/java/com/example/nexus/rbac/infrastructure/persistence/
      JpaRoleRepository.java:66-71 (findPermissionNamesByRole)
OWASP: A01 Broken Access Control (defense in depth)
Issue: Every sibling read in JpaUserRoleRepository carries a redundant tenant predicate with an explicit
       rationale ("r.tenantId cross-check — defense-in-depth against a drifted user_roles.tenant_id
       leaking a role across tenants"). M7 takes a bare roleId and relies entirely on a Javadoc
       precondition (correctly documented per RC-12.4, and correctly satisfied at its single call site).
Risk: Low today — the one caller tenant-verifies two statements earlier. The exposure is a second
      caller added later that does not: the method would then answer "is this arbitrary role dangerous?"
      across tenant boundaries, feeding an authorization decision.
Fix: Add the same redundant predicate the neighbours use, at no extra index cost:
     SELECT p.name FROM RolePermission rp, Permission p, Role r
     WHERE rp.id.permissionId = p.id AND rp.id.roleId = r.id
       AND r.id = :roleId AND r.tenantId = :tenantId
     and thread actor.tenantId() through UserRoleAssignmentPort#findPermissionNamesForRole. If the
     bare-id shape is kept deliberately, say so in the port Javadoc as a decision rather than only as a
     precondition.
```

```
[Low] Throttle denial returns 403 RBAC_001 / NOT_TENANT_ADMIN, deviating from SECURITY.md §8's
      429 + Retry-After rate-limit contract, and mislabels the reason for a newly-promoted admin
File: nexus-backend/src/main/java/com/example/nexus/rbac/application/RoleAssignmentService.java:477
OWASP: A05 Security Misconfiguration (standards deviation, documentation gap)
Issue: SECURITY.md §8 specifies "On exceed: 429 + Retry-After; do not reveal remaining attempts" for
       rate limiting. This throttle returns 403 with reason NOT_TENANT_ADMIN. The choice is defensible
       and arguably better — it avoids creating a new oracle (a 429 would confirm to the attacker that
       their probing registered), keeps exactly one 403-producing path (design §4.8's filter-vs-service
       argument), and the design states the reasoning. But it is an unrecorded deviation from the
       platform standard, and the reason value is factually wrong in one edge case: an actor who
       accrued denials and was then legitimately granted TENANT_ADMIN is told NOT_TENANT_ADMIN for up
       to window-seconds.
Risk: Standards drift (the next author reads SECURITY.md §8 and implements a 429 for a comparable
      throttle, producing two contradictory contracts), plus operator confusion on the newly-promoted-
      admin case, which is not the same collateral RES-11 documents (RES-11 covers benign-role
      changes).
Fix: Add one line to SECURITY.md §8 recording the service-layer exception and why (no-oracle,
     single-403-path); add the newly-promoted-admin case alongside RES-11's benign-role collateral in
     runbook.md §3 step 3.
```

```
[Low] Off-by-one: max-denials = 5 permits 6 fully processed denials before suppression
File: nexus-backend/src/main/java/com/example/nexus/identity/infrastructure/security/
      RateLimitRoleChangeThrottleAdapter.java:124-140 (with InMemoryRateLimitStore#tryConsume)
OWASP: A09 (documentation accuracy)
Issue: isThrottled() is evaluated at the start of a request; the denial that trips the bound is itself
       fully processed (WARN + D15 counter + durable audit row) before recordDenial() reports the
       transition. So the documented "after N denials … every subsequent request returns 403" is
       actually N+1 fully processed denials. Runbook §3 step 2 tells on-call to expect "≤ max-denials
       durable ROLE_ASSIGNMENT_DENIED rows"; they will find max-denials + 1.
Risk: None to the control. Triage friction only.
Fix: One word in 03-design.md §4.8 / monitoring.md §3 / runbook.md §3, or compare against
     maxDenials - 1.
```

```
[Low] nexus-backend/.mvn/jvm.config added with no design, task or PR trace
File: nexus-backend/.mvn/jvm.config (new, untracked)
OWASP: A08 Software & Data Integrity Failures (build-toolchain hygiene)
Issue: -Xmx4096m -XX:+UseParallelGC -XX:TieredStopAtLevel=1 for the Maven JVM. Not listed in
       03-design.md §15's otherwise exhaustive file manifest, not in 04-tasks.md, no rationale
       anywhere. Already raised in 06-code-review.md; repeated here only because an unexplained
       build-toolchain change riding on an authorization-boundary PR is exactly the shape a reviewer
       should not wave through. Contents are benign (build JVM only; does not affect the shipped
       artifact or runtime).
Risk: Low. Review-surface hygiene; a future reader cannot evaluate whether it was needed.
Fix: One-line comment in the file stating the trigger, or drop it from this branch.
```

---

## OWASP Top 10 checklist (SECURITY.md §12)

| | Result |
|---|---|
| **A01 Broken Access Control** | **Pass.** Gate verified sound on every path constructed; object-level and tenant checks on every read/lock/write; 404-before-403 and 403-before-409 orderings preserved. One defense-in-depth gap (L-1). |
| **A02 Cryptographic Failures** | **Pass.** No crypto introduced. No `Math.random`. |
| **A03 Injection** | **Pass.** Named parameters throughout, including the one new native query; no concatenated user input. |
| **A04 Insecure Design** | **Pass with findings.** Threat model exists, was adversarial, and every RC is traceable into the diff. M-1 and M-3 are design-level gaps in the *bound* and the *detection*, not in the gate. |
| **A05 Security Misconfiguration** | **Pass with findings.** Two new integer properties, env-overridable, safe defaults, no `enabled` flag by deliberate decision (D10). L-2 (standards deviation), M-3 (default store weakens the documented bound). |
| **A06 Vulnerable Components** | **No delta from this story.** `pom.xml`/`package*.json` byte-identical to `origin/main`; the new code adds no library. The pre-existing CVSS ≥ 9.5 transitives are a branch-wide dependency-upgrade concern outside this story's scope. |
| **A07 Identification & Authentication Failures** | **Pass.** No authentication code; stale-JWT freshness property preserved and newly proven on the privilege branch. |
| **A08 Software & Data Integrity** | **Pass with L-4.** No deserialization of untrusted data; no new artifact source. |
| **A09 Logging & Monitoring Failures** | **Findings M-1, M-2, L-3.** Audit coverage itself is strong: `operation` is now persisted durably (RC-13), denial rows survive, the PRIORITY-lane exclusion is documented as load-bearing. The gaps are in *alerting reachability* and the *suppression window*. |
| **A10 SSRF** | **n/a.** No outbound URL constructed anywhere in the diff. |

---

## Verdict

**APPROVED.**

The authorization change itself is correct, symmetric across both verbs, fail-closed at every branch, tenant-isolated end to end, free of injection, and free of new PII exposure or new dependencies. I could not construct a bypass, a confused-deputy, a TOCTOU, a cache-staleness, or a partial-commit attack against it. The documentation discipline ("replace the note, never delete it") is followed, and the residual that survives (RES-1(b) / T-E21) is honestly carried rather than quietly closed, with a real detective control (D13) and a named successor story (US-017) behind it.

The three Medium findings are all on the *detection and cost-bounding* layer, not the authorization layer. None is exploitable for access. **M-1 and M-2 should be tracked and resolved before the staging soak that `monitoring.md` §4 already blocks rollout on** — the soak is the natural place to validate both, and M-1 is fixable in alerting alone. **M-3 must be resolved before any multi-replica deployment.**
