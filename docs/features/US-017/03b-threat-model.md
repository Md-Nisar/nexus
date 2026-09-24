# US-017 — STRIDE Threat Model: Tenant-wide admin-equivalent lockout protection and a privilege-based caller-side admin test

_Output of Phase 3 Step B (`/security-review` in threat-model mode). **Gate 2 deliverable.** Adversarial STRIDE analysis of `03-design.md` (Revision 1) and `docs/adr/0018-admin-equivalent-lockout-and-caller-side-privilege-test.md`. Feeds `/breakdown` (Phase 4) and discharges the inputs listed in `02-impact.md` §5.5 and `03-design.md` §13._

**Epic:** EPIC-002 (RBAC Foundation) · **Story:** US-017 · **Reviewer:** Application Security Engineer · **Status:** **Gate 2 CLOSED (2026-09-18).** All 13 items accepted, all three escalated decisions (RC-15, RC-16, RC-20) correctly resolved, and the four mechanical fold-ins §9.4 held closure on are confirmed landed — see **§9.7**. No decision returned to the Architect; no new threat found; no Blocker. Revision 1 verdict (conditional pass, RC-15…RC-22) is superseded by §9.

---

## 0. Scope, verification basis, and headline result

**Scope.** The design in `docs/features/US-017/03-design.md` — D1–D21 — and ADR-0018 D1–D8. Specifically: the two-predicate split (D1/D2), the port discipline for the new reads (D3/D4), the distinct-holder lockout invariant (D5), the single-statement union lock (D6), the RES-10 closure claim (D7), the lock/caller-read containment claim (D8), fail-closed posture (D9), the live health query (D10/D11/D12), `detachPermission`'s new gate (D13), the canary re-derivation (D14), the new signals (D15), the audit posture (D16), the unchanged redaction (D17), the relocated mint-side asymmetry (D18), the no-new-flag rollout (D19/D20), and the AC8 precedence discharge (D21).

US-012's `RoleAssignmentService`, US-014's audit pipeline, US-015's `RoleManagementService` / `RbacDangerousPermissions`, US-016's privilege gate / denial throttle / bypass canary, and the `nexus_app` grant set are in scope **as trust dependencies**. US-016's **RES-1(b) / T-E21** (the attach-after-assign pre-positioning primitive) is in scope as the other end of the one escalation path this story materially *amplifies* — see T-E27.

**The load-bearing fact for this document.** This is the **first authorization loosening in this epic**. Every prior RBAC story removed capability; FR-3 grants administrative capability to a population that does not have it today, and it does so on a code path with **no backstop above or below it**: `TenantAwarePermissionEvaluator` performs a flat `permissions[]` membership test and cannot express the gate, and `nexus_app`'s grants cannot express it either. Every Elevation finding below descends from that, exactly as it did in US-015 and US-016.

### 0.1 Verification basis — code, schema, config and grants re-read this session, not trusted from the design doc

| # | Claim under test | Verified how | Result |
|---|---|---|---|
| 1 | `user:write ∈ RbacDangerousPermissions.NAMES` — the basis of D2's vacuity proof | `rbac/domain/RbacDangerousPermissions.java:13` | **Confirmed.** `NAMES = {role:write, user:write, tenant:write}`. Both verbs sit behind `@RequiresPermission("user:write")` and `RoleAssignmentService` re-asserts `USER_WRITE` on every denial, so a symmetric ANY caller test is **provably vacuous**. D2 reason 1 is correct and is the single most important decision in this design |
| 2 | The caller-side test is name-based today | `RoleAssignmentService.java:537-575` | **Confirmed.** M8 `findRoleIdByName(tenantId, TENANT_ADMIN)` → M5 `hasActiveAdminAssignment(actor.userId(), adminRoleId, tenantId)`; empty M8 ⇒ deny **without** calling M5 (R-10/T-E18). D9's fail-closed posture is an extension of shipped behaviour, not an invention |
| 3 | The lockout guard is row-counted and name-only today | `RoleAssignmentService.java:304-339` | **Confirmed.** `nameMatch && lockedActiveAdminIds.size() <= 1 && lockedActiveAdminIds.contains(ref.id())`. D5's row-vs-holder correction is real, not theoretical |
| 4 | The lock-hold timer participates only on the name-match path | `RoleAssignmentService.java:310-317, 398-411` | **Confirmed**, including the Javadoc sentence that D15 must correct |
| 5 | The D14 denial throttle runs **before** any lock or read | `RoleAssignmentService.java:158` (assign), `:299` (revoke) | **Confirmed.** This is the only bound on T-D13 below, and the design does not name it as such |
| 6 | `detachPermission` has **no** admin gate, and its `findPermission` read is enrichment placed **after** the delete | `RoleManagementService.java:245-266` | **Confirmed.** D13's claim that moving the read up costs **zero** extra statements on the ordinary path is accurate |
| 7 | `attachPermission` already emits a holder-count signal on the dangerous path (US-016 D13/RC-8) | `RoleManagementService.java:176-191, 220-239` | **Confirmed.** `findActiveUserIdsForRole(role.id()).size()`, carried on the audit event, a WARN when `> 0`, and a bounded `holders` bucket tag. **This is the existing control T-E27's required mitigation extends** — it does not have to be built from nothing |
| 8 | The mint-side gate is name-based and fail-closed | `RoleManagementService.java:334-355` | **Confirmed.** M8 + M5, empty ⇒ deny. D18/RES-13's description of the relocated asymmetry is factually accurate — its *safety* argument is not (T-E28) |
| 9 | The health indicator injects a **full `JpaRepository`** directly, not a port | `RbacZeroActiveAdminsHealthIndicator.java:38-42`; `JpaUserRoleRepository.java:15` (`extends JpaRepository<UserRole, UUID>`) | **Confirmed — and it is a finding.** The detection control holds `save`/`delete`/`deleteAll` over `user_roles`. Same shape as US-016 **T-T13**, which was rated Medium for `role_permissions`. D12 re-affirms and widens this coupling without re-examining it (**T-T14**) |
| 10 | Today's health query wraps the name in `UPPER()` and carries the `ur.tenantId = r.tenantId` cross-check | `JpaUserRoleRepository.java:225-234` | **Confirmed.** D12's drop of `UPPER()` is correct hygiene; §8.2's retention of the cross-check on **both** new queries is correct and load-bearing (T-S1) |
| 11 | **`/actuator/health` already has a 30-second cache TTL, added for this exact indicator** | `application.yml:88-96` — the comment names `07-security-review.md M-2`, `permitAll`, "no rate limit", and "an anonymous caller looping this endpoint forces an unbounded number of those scans" | **Confirmed — and it refutes D10.** D10's decisive argument is *"**Zero staleness** — which is the decisive property for a control whose purpose is catching a bypass."* The shipped response is up to **30 s** stale by configuration. The TTL is a *load-bearing security control* that the design neither mentions nor protects (**T-D16**) |
| 12 | A widened DOWN cannot take the application down | `application.yml:99-106` (liveness/readiness groups include only `livenessState`/`readinessState`); `nexus-backend/Dockerfile:27` (`/actuator/health/liveness`) | **Confirmed safe.** Recorded as a *positive* so a future story does not sweep `rbacZeroActiveAdmins` into a probe group and convert D11's widened DOWN population into an outage |
| 13 | `/actuator/health/**` is `permitAll`; `show-details: when-authorized` | `config/SecurityConfig.java:78`; `application.yml:87` | **Confirmed.** FR-6's count-only discipline remains necessary for the same reason as M-1 |
| 14 | Seeded role and permission ids have a clear high bit, so `UUID.compareTo` coincides with `BINARY(16)` byte order **today** | `V5__rbac_schema.sql:107-136` (`019f6839-…`, `00000000-…`) | **Confirmed, with a caveat.** `UUID.compareTo` compares `mostSigBits` as a **signed** long; MySQL compares `BINARY(16)` **unsigned**. The two agree only while the top bit is clear — true for UUIDv7 until ≈ year 6429 and for every seeded id. D6's "ascending" port contract must name the ordering (**T-D15** part 3) |
| 15 | M10's stated bound is real | `RoleManagementService.java:79, 104` — `nexus.rbac.max-roles-per-tenant` default 500, enforced at role creation | **Confirmed.** §8.5's 500 × 7 = 3 500-row bound on M10 is a real cap, not an assumption |
| 16 | A `role:write`-only caller cannot list a role's permissions | `RoleController.java:120-121` — `GET /{roleId}/permissions` requires `role:read` | **Confirmed.** Necessary input to D13's oracle analysis (**T-I14**) |
| 17 | A tenant-created role can never be named `TENANT_ADMIN` | `RbacRoleNames.java:22` (`RESERVED`) | **Confirmed.** The name half of both predicates cannot be squatted (US-016 T-T12 remains closed) |
| 18 | No dependency manifest delta on this branch | `git diff --stat main...HEAD -- '*pom.xml' '*package.json' '*package-lock.json'` → empty | **Confirmed.** Per the US-015/US-016 precedent, `./mvnw dependency:tree` is **deferred to the Phase 7 code audit** — there is no code and no manifest change to scan at Gate 2. Recorded rather than silently skipped |
| 19 | `npm audit` (frontend) | Run this session | **27 pre-existing findings (1 critical, 7 high, 16 moderate, 3 low)** — all in the Angular build/toolchain graph (`tar`, `undici`, `qs`, …). **Not attributable to US-017**, which touches zero frontend files (impact §4, re-verified). Recorded here so the Phase 7 audit inherits the baseline; a dependency-hygiene task is warranted independently of this story and must respect the known npm-Windows lockfile prune trap |

### 0.2 Headline result

**This is a strong design and it closes what it sets out to close.** Three calls in particular are, in my judgement, correct and well argued from code rather than convention:

- **D2 (two predicates)** is the right answer to the impact analysis's Critical finding. The vacuity proof is sound, I re-verified it from `RbacDangerousPermissions.java:13`, and the "asymmetric predicates for asymmetric failure modes" reasoning is the correct engineering frame. **I attack it directly in §3 (T-E30) and it survives** — no role can be crafted that passes ALL-three without being a genuine administrative stand-in, because minting an ALL-three role requires a literal `TENANT_ADMIN` at every step (AC11).
- **D5 (distinct holders, not rows)** catches a defect that a "straightforward per-role extension" would have shipped, and the exclusion-of-`ref.id()` formulation covers three edge cases structurally rather than by ordering rules.
- **D7 (close RES-10 rather than inherit it)** is the honest call. Widening M11's range without touching `assign()` would have shipped a known, widened deadlock, and the design says so plainly instead of re-accepting a risk that no longer holds.

**Eight things still need to change, and three of them change what this story is allowed to claim.**

1. **The design never mentions US-016's RES-1(b) / T-E21, and FR-3 materially amplifies it** (**T-E27, High**). The standing pre-positioning primitive — self-assign a benign custom role today, be silently escalated when an administrator attaches a dangerous permission tomorrow — previously yielded admin-equivalent *permissions* but could never pass the caller gate. After FR-3 it yields **caller-side administrative capability**, and from there literal `TENANT_ADMIN` in one self-assignment. The register entry that owns this risk has an Epic-3 hard expiry and this story changes its payoff without re-rating it.
2. **D18/RES-13's safety argument is defeated in one step** (**T-E28, Medium**). "The mint side staying narrower is the safe direction" is true as a direction and false as a containment: a fully admin-equivalent caller can self-assign literal `TENANT_ADMIN` (which FR-3 newly permits), and then attach and detach dangerous permissions at will. RES-13 must be re-worded so no future reader treats the mint-side gate as a boundary it is not.
3. **M10 is one input with three fail-open consequences** (**T-E29, Medium**). An over-broad M10 result simultaneously (a) widens the caller-qualifying set so the gate passes wrongly, (b) inflates the lockout's holder set so a tenant *can* be zeroed, and (c) blinds the canary that exists to notice (a). RES-18 names only (c) and rates it Low. The compensating controls listed are unit tests — which is precisely the class of assurance a canary exists to backstop.
4. **D7's justification is factually wrong about who reaches the lock** (**T-D13, Medium**). *"These are rare, already-admin-gated administrative operations on an endpoint family deliberately left un-rate-limited precisely because only privileged principals reach it."* On `assign()`, M11 is acquired **before** the caller gate (design §6.2 rows 4.5 and 5), so **any `user:write` holder — including the exact non-admin attacker US-016 was written about — can force a tenant-wide exclusive lock, held across M5b and an inline `REQUIRES_NEW` audit write, on a verb that takes no lock at all today.** The real bound is US-016's D14 denial throttle, which the design does not name.
5. **D7's total-order proof covers one index** (**T-D15, Medium**). The claim is proved over `fk_user_roles_role`. The `INSERT`'s insert-intention locks in `uq_user_role_active` and `fk_user_roles_user`, and M6's update of the **STORED generated** `active_key`, are outside M11's region; they are serialised for *privileged × privileged* pairs by the M11 conflict, but the *privileged × benign* case is argued away through `fk_user_roles_role` only. Harness C has no benign thread. This is the same defect class US-016 found in D2 (T-E23) and it is worth catching twice.
6. **D16 is the right decision resting on an unresolved precondition** (**T-R10, Medium**). I concur that a lockout block must not be widened into `ROLE_ASSIGNMENT_DENIED`. But "WARN-only is sufficient" inherits US-015 RES-10's and US-016 RES-6's **unresolved log-retention question**, and there is an attack-adjacent scenario (a compromised sole-admin account repeatedly attempting to destroy the tenant's last admin access) whose *only* record is that WARN.
7. **D10's decisive argument is false** (**T-D16, Low-Medium**). "Zero staleness" is contradicted by a 30-second actuator cache TTL that exists specifically to bound an anonymous amplification of this indicator, and that the widened two-query/four-table form makes **more** load-bearing.
8. **D20 step 3's DBA sweep is a detection step with no forensic step** (**RC-21, Medium**). The population it enumerates may have been zeroed *maliciously* — before US-016's gate shipped, `revoke()` had no admin check at all — and the sweep as specified produces a list with no attribution, no evidence retention, and no stated action if it is non-empty at deploy time.

**None is a Blocker.** I could construct no way to turn US-017's own controls against themselves: no ordering trick defeats 403-before-409, no short-circuit skips the gate while clearing `privileged`, the ALL ⊆ ANY containment genuinely holds, and the self-revocation proof (§6.3) survives re-derivation. On every path I could construct, US-017 is strictly stronger than the status quo for the *target* and *detection* sides. **Verdict: conditional pass** — Gate 2 may close once RC-15…RC-22 are folded into `03-design.md`; **RC-15, RC-16 and RC-20 are Architect decisions, not editorial ones.**

### 0.3 Explicit review attestation (standing policy — auth, crypto and PII are never approved silently)

- **Authentication — reviewed. No findings.** US-017 adds no authentication code and no authentication-adjacent surface. It consumes `RoleChangeActor` (JWT-only provenance, `RbacControllerSupport.resolveActor`, unchanged) from the RS256-validated token. The story's one authentication-relevant property is **negative and it is preserved**: administrative status is never derived from a JWT claim. M5b inherits M5's non-negotiable contract verbatim (`UserRoleAssignmentPort.java:35-42` → design §4.3) — a fresh, transactional, **locking** `FOR SHARE` read — and §11.3 mandates extending `RoleAssignmentSecurityIT`'s stale-JWT out-of-band-revocation proof to the new predicate. **One point of emphasis for `/breakdown`:** the *canary* helper (D14) is deliberately non-locking and must never be substituted for M5b; MC-G is the control, and it must assert the negative on **both** verbs. See **T-S8**.
- **Authorization — reviewed in depth; this is the story's entire substance, and this is the first loosening in the epic.** Covered by T-E27 through T-E31, T-D13, T-I14 and T-I15. Specifically reviewed and **confirmed sound**: D2's vacuity proof; the ALL ⊆ ANY containment that makes D8's proof work; the fail-closed-on-empty-caller-set branch (D9, R-10/T-E18 lineage); 403-before-409 (design §6.2 rows 5/6) and 404-before-403 (row 3); §6.3's re-derived self-revocation proof; the impossibility of minting an ALL-three role without a literal `TENANT_ADMIN` (AC11 + `RbacRoleNames.RESERVED`); D13's removal of an attachment-existence oracle; D21's discharge of the AC8 precedence question. Specifically **not** approved: the claim that the relocated mint-side asymmetry is a containment (**T-E28**), and the treatment of M10 as an ordinary read (**T-E29**).
- **Cryptography — reviewed. No findings.** US-017 introduces no cryptographic code, no key material, no new randomness source and no new id generation. It adds no `Math.random`; the backend still has none. Every id on the new read paths is a pre-existing UUIDv7 from `UuidV7IdGenerator` (`SecureRandom`-backed, ADR-0005). The new reads return `(UUID, String)` pairs, `(UUID, UUID)` pairs and a boolean; none is a secret, none is compared in a timing-sensitive way, and none feeds a decision a timing side channel could usefully influence — the gate's outcome is already disclosed by the HTTP status. **One cryptography-adjacent note that is not a crypto finding:** D6's "ascending" ordering contract is expressed over `UUID`, whose Java ordering is **signed** on `mostSigBits` while MySQL's `BINARY(16)` comparison is **unsigned**; they coincide for every id in the system today (verification item 14) but the contract must say which order it means (T-D15 part 3).
- **PII — reviewed against the organisation's no-PII rule. No new exposure.** Every field added by this story is a UUID, an integer, a bounded enum-like constant, a role name or a permission name: `matchedOn` (`ROLE_NAME`|`DANGEROUS_PERMISSION`), `callerMatchedOn` (`ROLE_NAME`|`ALL_DANGEROUS_PERMISSIONS`), `operation` (`assign`|`revoke`), `adminEquivalentRoleCount`, `lockedRowCount`, and `RBAC_DANGEROUS_PERMISSION_DETACH_BLOCKED`'s `{tenantId, roleId, roleName, permissionId, permissionName, actorUserId}`. No email, no display name, no IP beyond the pre-existing `RequestContext` triple. The health detail remains **count-only** (FR-6); tenant ids stay in the WARN. **One inherited caveat, recorded not filed:** `roles.name` is tenant-controlled free text under US-015 D6's allow-list (`^[A-Za-z0-9][A-Za-z0-9 ._-]*$`), which permits a personal name, so a role called `Jane Doe Admin` lands in the new WARN markers. Unchanged from `ROLE_ASSIGNED`'s existing handling (US-015 T-I9, closed: the allow-list excludes CR/LF/U+2028/U+2029 and the encoder is structured), and **US-017 adds no new sink** — every new field is either an existing field shape or a bounded constant. **Log injection (CRLF): closed, inherited.**
- **Secrets — reviewed. No findings.** No credential, token, connection string or configuration value is introduced, read or logged. D19 adds no feature flag and no property. The one configuration value this review *depends* on — `management.endpoint.health.cache.time-to-live` — is not a secret and is covered by T-D16.

**Severity scale** (consistent with US-012 §0.3, US-015 §0.2, US-016 §0.2): **Blocker** / **Critical** / **High** / **Medium** / **Low**.

**Threat ID numbering** continues the epic's STRIDE-lettered sequence. US-009 allocated T-S1–S2, T-T1–T4, T-R1–R2, T-I1–I3, T-D1–D2, T-E1–E6; US-012 extended to T-S4, T-T7, T-R4, T-I5, T-D5, T-E13; US-015 to T-S6, T-T11, T-R7, T-I9, T-D9, T-E20; US-016 to T-S7, T-T13, T-R9, T-I13, T-D12, T-E26. **US-017 therefore begins at T-S8, T-T14, T-R10, T-I14, T-D13, T-E27.** Required-change numbering continues US-016's RC-8…RC-14 at **RC-15**. Residual-risk numbering continues `03-design.md` §12.3's RES-12…RES-18 at **RES-19**.

---

## 1. Trust boundaries and data flow

```
[ Internet / hostile client — holds a VALID token for a tenant member with `user:write`
  (and possibly `role:write`), but NO active TENANT_ADMIN assignment and NO fully
  admin-equivalent role. Claims may be up to ~30 min stale (US-015 T-I8). ]
        |  POST   /api/v1/users/{userId}/roles                    {roleId}
        |  DELETE /api/v1/users/{userId}/roles/{roleId}                     + Bearer JWT
        |  DELETE /api/v1/roles/{roleId}/permissions/{permissionId}         <-- NEW GATE (D13)
        v
=== TB1: network -> app ==================================================
  CorrelationIdFilter -> LoginRateLimitFilter  ** login/refresh ONLY — NOT these paths **
  -> JwtAuthenticationFilter (RS256 verify; MDC userId/tenantId)
        |  ** NO endpoint rate limit on any of the three verbs (US-012 posture, inherited) **
        v
=== TB2: filter chain -> dispatcher ======================================
  @ConditionalOnProperty feature.nexus-us012-rbac-role-assignment.enabled (false in prod)
  @ConditionalOnProperty feature.nexus-us015-rbac-role-management.enabled (false in prod)
        |  ** flag-off is an AVAILABILITY lever, not a security one (D19, US-016 T-E20) **
        v
=== TB3: dispatcher -> method-security proxy =============================
  @RequiresPermission("user:write") / ("role:write") -> TenantAwarePermissionEvaluator
        == FLAT Set.contains on the JWT permissions[] claim. ZERO admin-status check.  ==
        == Cannot express either predicate. The gate is 100% service-layer logic.      ==
        == user:write and role:write are THEMSELVES in RbacDangerousPermissions.NAMES  ==
        ==   -> an ANY caller test would be vacuous here. This is D2's whole point.     ==
        v
=== TB4: interfaces -> application (Spring-Security-free boundary) =======
  UserRoleController / RoleController -> RoleChangeActor(userId, tenantId)  <-- JWT-only
        v
  RoleAssignmentService @Transactional        ** THE COMPONENT THIS STORY CHANGES **
    assign():   [1][2] verifySameTenant / resolveRoleInTenant  404/403 + inline denial audit
                [3.5] D14 denial throttle      ** the ONLY bound on T-D13 **
                [4]   nameMatch? --no--> M7    ** NON-LOCKING **
                [4.5] if privileged: M10 (NON-LOCKING, tenant-scoped) + M8
                                     M11 ** FOR UPDATE over the ascending role-id IN-list **
                                        ^^ NEW ON assign(). ACQUIRED BEFORE THE GATE.  ^^
                                        ^^ reachable by ANY user:write holder (T-D13)  ^^
                [5]   M5b ** FOR SHARE, contained in M11's X region (D8) ** -> 403
                [6]   M2 duplicate 409 -> INSERT -> M4a
                      ** INSERT's insert-intention locks land in uq_user_role_active and
                         fk_user_roles_user — OUTSIDE M11's region (T-D15) **
                [7]   post-commit: evict, ROLE_ASSIGNED, self_role_assignment{privileged,
                      callerIsAdmin}  ** canary re-derived from M10's set (RES-18/T-E29) **
    revoke():   [1][2][3] as above, incl. M3 -> 404   ** 404 stays before 403 **
                [3.5] throttle   [4] nameMatch/M7   [4.5] M10 + M8 + M11 (X)
                [5]   M5b -> 403       ** 403 stays before 409 **
                [6]   widened lockout: DISTINCT user_id of locked rows MINUS ref.id() empty
                      -> 409 RBAC_002   ** self-revocation only, proof re-verified §6.3 **
                [7]   M6 UPDATE revoked_at  ** mutates the STORED generated active_key **
        v
  RoleManagementService.detachPermission @Transactional   ** NEW GATE (D13) **
    resolveRoleInTenant -> requireMutableRole -> findPermission (MOVED UP)
      -> if dangerous: M8 + M5 (name-based, D18) -> 403
      -> DELETE role_permissions (0 rows -> 404)
        ** closes the ONLY runtime path that can flip a role out of admin-equivalence **
        ** but the gate's own population is reachable in one self-assign (T-E28) **
        v
=== TB5: app -> MySQL as `nexus_app` (least-privilege) ===================
  permissions       SELECT               <-- ** M10 touches this: @Lock here fails in PROD only **
  roles             SELECT, INSERT       <-- roles.name is IMMUTABLE at runtime
  role_permissions  SELECT, INSERT, DELETE  <-- ** the guard's input is MUTABLE (D13/§7.5) **
  user_roles        SELECT, INSERT, UPDATE(revoked_at)  <-- M11 FOR UPDATE, M5b FOR SHARE
  auth_events       INSERT, SELECT
        v
=== TB6: denial side effects — INLINE, inside the doomed transaction ====
  recordDenial -> RbacAuthEventAdapter -> SecureEventService(REQUIRES_NEW)
     ** borrows a SECOND pooled connection while M11's tenant-wide X lock is held **
     ** on BOTH verbs now, over N role ranges instead of one (T-D13) **
  WARN RBAC_PRIVILEGED_ROLE_CHANGE_BLOCKED / RBAC_LAST_ADMIN_REVOCATION_BLOCKED
  ** the lockout WARN is the ONLY record of a blocked lockout — no durable row (D16/T-R10) **
        v
=== TB7: detection — /actuator/health, permitAll, 30s TTL ===============
  RbacZeroActiveAdminsHealthIndicator -> JpaUserRoleRepository ** DIRECT, not via the port **
     ** injected as a full JpaRepository: save/delete over user_roles (T-T14) **
     ** 2 queries over 4 tables per evaluation; bounded ONLY by the 30s cache TTL (T-D16) **
     ** excluded from liveness/readiness groups — a widened DOWN cannot kill the pod (good) **
        v
=== TB8: OUT-OF-BAND — the boundary this story still does not own =======
  US-015 POST /api/v1/roles/{roleId}/permissions   (attach: AC11, literal-name-gated)
     ** attach of the THIRD dangerous permission silently converts every existing holder
        into a caller-qualifying administrator. The holder-count signal fires; it does NOT
        say "this role just became caller-qualifying" (T-E27) **
        v
=== TB9: token mint — the staleness boundary ============================
  RoleResolutionService fingerprint misses permission edits -> ~30 min (US-015 T-I8)
     ** but the CALLER-side gate is a live DB read, so FR-3's grant is effective IMMEDIATELY,
        unlike the permission-side escalation it rides on **
```

**Components under analysis.**
**C1** `UserRoleController` / `RoleController` + DTOs (unchanged — re-verified as a boundary) ·
**C2** `RoleAssignmentService.assign()` — the new union lock and the widened caller gate ·
**C3** `RoleAssignmentService.revoke()` — the widened lockout, the union lock, and the AC5 interaction ·
**C4** `rbac.domain.RbacAdminEquivalence` + `RbacDangerousPermissions.carriesAny/carriesAll` (D1/D2) ·
**C5** `UserRoleAssignmentPort` M10 / M11 / M5b contracts (D3, D4) ·
**C6** `JpaUserRoleAssignmentAdapter` / `JpaRoleRepository` / `JpaUserRoleRepository` ·
**C7** the `nexus_app` privilege / InnoDB locking boundary (D6, D7, D8, §7.5) ·
**C8** `RoleManagementService.attachPermission` / `detachPermission` (D13, D18) ·
**C9** `RbacZeroActiveAdminsHealthIndicator` + `/actuator/health` (D10, D11, D12) ·
**C10** observability: the re-derived canary, the new counters, the WARN markers, the alerts and runbooks (D14, D15, D16) ·
**C11** trust dependencies and rollout — US-016 RES-1(b)/T-E21, the D14 throttle, `RbacRoleNames.RESERVED`, D19/D20.

---

## 2. Component-by-component STRIDE table

Legend: **✅** addressed by the design as written · **⚠️** partially addressed, gap identified · **❌** not addressed, change required · **n/a** not applicable.

### C1 — `UserRoleController` / `RoleController` + DTOs (unchanged)

| | Threat | Verdict |
|---|---|---|
| **S** | Caller forges actor or tenant via body/path | ✅ Unchanged. `RoleChangeActor` is JWT-only; `assignedBy` is always `actor.userId()` (T-S3 discipline). No DTO change (§6.1) |
| **T** | Wire-contract drift from the new 403 on `detachPermission` | ✅ Verified: the 403 body is unchanged field-for-field; `GlobalExceptionHandler` sets only `code`, `traceId`, `requiredPermission`; `reason` is never wire-visible. No new error code, no new `DenialReason` (ADR-0017 D3 upheld) |
| **R** | — | n/a (unchanged) |
| **I** | New status-code oracle on `detachPermission` (404 → 403) | ✅ **T-I14, Low — net improvement.** The 403 is emitted whether or not the pairing exists, so it *removes* an attachment-existence oracle; and "this permission id is dangerous" is a global fact already disclosed by the attach-side AC11 gate. Verified against `RoleController.java:120-121` |
| **D** | Unthrottled denial generation | ⚠️ **T-D13, Medium.** Inherited from US-016 T-D10 and **bounded** by the shipped D14 throttle — but the denial path's cost per request grows materially (a second verb, an N-range lock, one more read) and the design's own justification denies that non-privileged callers reach it |
| **E** | `@RequiresPermission` silently unenforced | ✅ Inherited and mechanically closed by US-015 D8's ArchUnit rules. No new handler, no new annotation, no new endpoint |

### C2 — `RoleAssignmentService.assign()` (new union lock + widened caller gate)

| | Threat | Verdict |
|---|---|---|
| **S** | Admin status derived from a stale JWT rather than the DB | ✅ **T-S8, Low.** M5b inherits M5's locking-read contract verbatim; the canary helper is explicitly non-locking and explicitly excluded from authorization (MC-G). §11.3 extends the stale-JWT IT to the new predicate |
| **T** | Caller-qualifying role set mutated between M10 and M5b | ✅ Ruled on by §7.5: `REPEATABLE READ` snapshot; a later attach is not protected (RES-16), a later detach fails safe. Both directions checked and both hold |
| **R** | The new *grant* of capability leaves no durable record of **which predicate** admitted the caller | ⚠️ **T-R11, Low.** `privileged_role_change_allowed{operation, callerMatchedOn}` (D15) is the only signal, and it carries no tenant or actor dimension; the durable `ROLE_ASSIGNED` row does not record how the caller qualified. See RC-16 part 3 |
| **I** | Target-role privilege oracle | ✅ Unchanged from US-016 RES-8 (T-I10). The 403-vs-201 channel is identical; the population that receives 201 widens, which is the story's point |
| **D** | **A tenant-wide X lock acquired before the authorization decision, on a verb that takes no lock today** | ❌ **T-D13, Medium** |
| **E** | **A symmetric ANY caller test would be vacuous** | ✅ **Correctly identified and correctly rejected (D2).** Re-verified from code. MC-B plus four untouched 403 ITs make it mechanical, not reviewed |
| **E** | A role crafted to pass ALL-three without being a genuine administrator | ✅ **T-E30, Low — attacked and survived.** Minting an ALL-three role requires three AC11-gated attaches, each of which requires an active literal `TENANT_ADMIN`; `RbacRoleNames.RESERVED` blocks name squatting. **But the predicate's *implementation* has a fail-open shape** (a count-based `carriesAll` over a list with duplicates) — RC-18 |
| **E** | Fully admin-equivalent caller self-assigns literal `TENANT_ADMIN` | ⚠️ **T-E28, Medium.** Newly permitted, legitimate under D2's own definition, and it silently defeats D18/RES-13's "the mint side stays narrower" containment claim |
| **E** | Escalation survives the gate entirely | ❌ **T-E27, High.** US-016 RES-1(b)/T-E21's standing primitive, amplified by FR-3 and unmentioned in the design |

### C3 — `RoleAssignmentService.revoke()` (widened lockout + union lock + AC5)

| | Threat | Verdict |
|---|---|---|
| **S** / **T** | As C2 | ✅ / ✅ |
| **R** | A blocked lockout leaves no durable record | ⚠️ **T-R10, Medium.** D16's decision is right; its precondition (log retention ≥ `auth_events` retention) is the one US-015 RES-10 and US-016 RES-6 both refused to leave implied |
| **I** | 409 `RBAC_002` discloses tenant admin-roster state | ✅ Closed and **strengthened**. 403-before-409 is preserved by construction (§6.2 rows 5/6), and §6.3's re-derived proof shows 409 is reachable only by the sole admin-equivalent holder revoking their own last such assignment — they learn nothing they did not already know |
| **I** | Row-vs-holder confusion leaks/permits a zeroing | ✅ **D5 is correct and MC-D pins it.** The one-user-two-roles case is the naive extension's failure and the design names it |
| **D** | Lock-hold and blast-radius amplification on the denial path | ❌ **T-D13, Medium** (composed successor to US-016 RES-4+RES-5) |
| **D** | Unbounded locked/materialised set | ⚠️ **T-D14, Medium** (design rates it RES-17, Low). Reachable from the denial path and inflated by exactly the RES-1(b) shape (a widely-held role that an admin made dangerous) |
| **D** | **Cross-index cycle with a benign role change** | ❌ **T-D15, Medium.** D7's total order is proved over one index; harness C has no benign thread |
| **E** | AC5's guard becomes unreachable or over-permissive | ✅ **T-E31, Low.** §6.3's proof re-derived independently and it holds; the guard is not dead code and §11.1 correctly keeps the synthetic-state unit test |
| **E** | Fail-open when the tenant's admin-equivalent set resolves empty or wrong | ⚠️ **T-E29, Medium.** Empty ⇒ deny is right (D9). **Over-broad ⇒ fail open on three axes at once** |

### C4 — `rbac.domain.RbacAdminEquivalence` / `RbacDangerousPermissions` (D1, D2)

| | Threat | Verdict |
|---|---|---|
| **S** / **R** | — | n/a |
| **T** | Policy drifts between call sites | ✅ **The design's strongest structural call after D2.** One domain type, two named predicates, one permission set, three consumers of the target-side predicate (lock set, holder count, `privileged`). FR-7 is satisfied by construction. The explicit "never substitute one for the other" Javadoc plus ADR-0018's follow-on rule is the right belt-and-braces |
| **T** | **The ALL-three combinator is implemented in a way that fails open** | ❌ **T-E30 part 2, Low-Medium.** `carriesAll` must be a **distinct, case-insensitive set** test. A `count of dangerous names in the list >= 3` implementation returns `true` for `["user:write","user:write","user:write"]`. M10 cannot produce duplicates today (`pk_role_permissions` + `uq_permissions_name`), so this is latent, not live — which is exactly when it should be pinned |
| **T** | Case/accent handling diverges from the DB | ⚠️ **T-T15, Low.** Java uses `equalsIgnoreCase`; the SQL half of FR-2 uses `utf8mb4_0900_ai_ci`, which is **accent-insensitive** as well. Unreachable today (the 7-row catalogue is `SELECT`-only), but it is a second, divergent implementation of the same predicate — the exact thing D1 exists to prevent (RC-18 part 2) |
| **I** | — | n/a. Neither predicate is a secret |
| **D** | Unbounded input | ✅ Bounded at 7 per role by the fixed catalogue |
| **E** | ANY substituted for ALL at a future call site | ✅ Mechanically guarded by MC-B plus the four untouched 403 ITs, and documented in three places (D2, §4.2's Javadoc replacement, ADR-0018 follow-on rule 1). This is well done |

### C5 — `UserRoleAssignmentPort` M10 / M11 / M5b (D3, D4)

| | Threat | Verdict |
|---|---|---|
| **T** | Dangerous-permission **policy** leaks into infrastructure and drifts | ✅ **ADR-0017 D2 upheld, not argued against.** M10 returns `(roleId, permissionName)` pairs; the service applies the domain predicate; only role **ids** go back. The extra round trip is the right price, and the design says so explicitly rather than quietly optimising it away |
| **T** | A future `@Lock` on M10 → production-only rejection | ✅ Port Javadoc forbids it in capitals; **MC-A** extends the shipped SQL-capture control to M10 **and** FR-2's two queries. Correct and not optional |
| **T** | Injection (JPQL / native) | ✅ **OWASP A03 clean.** M10 and M11 are parameterised comma-join JPQL; M5b is native with named binds including a parameterised `IN (:roleIds)` collection of `byte[]`. No concatenation anywhere. `UuidV7Converter` handles JPQL binds; the adapter converts explicitly for the native query, mirroring shipped M5 |
| **I** | Managed entity escapes and is load-mutate-saved | ✅ M10 and M11 return records; M5b returns entities but the adapter inspects only `.isEmpty()` — the same shipped discipline as M5, and the port Javadoc must carry the same warning |
| **I** | M11 has no `Role` join, so tenant containment rests on two separate facts | ⚠️ **T-I16, Low.** The role-id set is tenant-derived **and** `ur.tenantId` is a residual predicate, so a drifted `user_roles.tenant_id` row is invisible to both tenants ⇒ under-counted holders ⇒ spurious 409 ⇒ **fail safe**. The inverse (a foreign-tenant *user* holding a correctly-tenanted row) would over-count and is **not** excluded by M11 — unreachable through the application (`verifySameTenant` precedes every insert) and unchanged from shipped M1. Record, do not fix |
| **D** | Unbounded results | ⚠️ M10 is bounded (500 × 7, verified). **M11 is not** — T-D14 |
| **E** | **M10 is a single input to three independent decisions** | ❌ **T-E29, Medium** |
| **E** | Write capability leaks into `RoleAssignmentService` | ✅ **Confirmed at the application layer.** `RoleManagementPort` is still not injected; the service constructor is unchanged; `createRole`/`attachPermission`/`detachPermission` remain unreachable |

### C6 — `JpaUserRoleAssignmentAdapter` / `JpaRoleRepository` / `JpaUserRoleRepository`

| | Threat | Verdict |
|---|---|---|
| **T** | Adapter gains write capability over `role_permissions` | ✅ **US-016 RC-12's fix is preserved and extended.** M10 is hosted on the already-injected `JpaRoleRepository`; `JpaRolePermissionRepository` is still not injected; the adapter's constructor gains **zero** dependencies. D3/D4 apply the lesson rather than re-learning it |
| **T** | De-sargonised `UPPER(name)` | ✅ Dropped by D12, consistent with M8's shipped discipline and `uq_roles_tenant_name` under `utf8mb4_0900_ai_ci` |
| **T** | A `@Lock`-annotated constructor-expression projection silently fails to emit `FOR UPDATE` | ✅ **Named in the design (§4.6) rather than discovered at implementation time**, with MC-A asserting the emitted clause. Good practice; keep the stated fallback (select the entity, map in the adapter) |
| **I** | Cross-tenant leakage through the wider join surface | ✅ Both FR-2 queries carry `ur.tenantId = r.tenantId`; M10 is driven by `r.tenantId`. T-S1 discipline preserved on every new statement |
| **D** | Plan instability across IN-list cardinalities | ❌ **Part of T-D15.** MC-C as written asserts `key = fk_user_roles_role`; it must assert it for **varying** IN-list cardinalities, because the total-order argument depends on plan *stability*, not on one fixture's plan |
| **E** | Hardcoded policy names in a repository | ✅ Preserved: FR-2's names arrive as bind parameters from `rbac.domain` via the indicator; nothing is hardcoded in the repository |

### C7 — the `nexus_app` privilege / InnoDB locking boundary (D6, D7, D8, §7.5)

| | Threat | Verdict |
|---|---|---|
| **T** | Locking read on a `SELECT`-only table → production-only failure | ✅ Identified, ruled on (§7.5), and made mechanical (MC-A extended to every new statement). The design is explicit that this is *why* M10 cannot be locking, which is the correct framing |
| **T** | The guard's own input is mutable at runtime | ✅ **D13 closes the only runtime mutation path** and §7.5 rules explicitly on which side of the commit wins. This is the best answer available under the grant set, and the design correctly refuses the impossible one (locking `role_permissions`) |
| **D** | Deadlock between two privileged transactions in one tenant | ✅ **D7's mechanism is sound for this pair.** They conflict at M11 and serialise there; subsequent acquisitions cannot interleave |
| **D** | **Deadlock between a privileged and a *benign* transaction, through a different index** | ❌ **T-D15, Medium** |
| **D** | Serialisation cost of the new `assign()` lock | ⚠️ Accepted for legitimate traffic (correctly); **not** accepted for the denial path, where the design's reachability premise is wrong — **T-D13** |
| **D** | Isolation-level dependency | ✅ Retained and asserted (MC-6). §7.5's snapshot ruling and D6's serialisation claim both depend on `REPEATABLE READ` and both say so |
| **E** | Containment of the caller read inside the X region | ✅ **D8 is correct, and elegantly so.** ALL ⊆ ANY ⊆ lock set means every index record M5b requests is already exclusively held by the same transaction. The `FORCE INDEX` is retained and MC-C re-derives the `EXPLAIN`. This is the single change that makes the widened design *safer* than the shipped one |

### C8 — `RoleManagementService.attachPermission` / `detachPermission` (D13, D18)

| | Threat | Verdict |
|---|---|---|
| **T** | A `role:write` holder flips a role out of admin-equivalence mid-check | ✅ **Closed by D13** for the `role:write`-only population — the concrete answer to impact R3 |
| **R** | The new detach denial leaves no durable record | ⚠️ **T-R12, Low.** Mirrors attach, which writes none either (§9.1 is explicit). Consistent, and the WARN carries every field; inherits the same retention question as T-R10 |
| **I** | 404 → 403 becomes an attachment-existence oracle | ✅ **T-I14, Low — the opposite.** Verified: the 403 is returned whether or not the pairing exists, so the oracle that exists **today** (404 = not attached, 204 = attached) is *removed* for dangerous permissions |
| **I** | 403 reveals that a permission id is dangerous | ✅ Already disclosed by the attach-side AC11 gate; the catalogue is global, fixed and `SELECT`-only. No new channel |
| **D** | Two extra statements on the dangerous path | ✅ Admin-only, rare, correctly costed (§8.5). The ordinary path is **+0** because the `findPermission` read moved rather than being added — verified against `RoleManagementService.java:255-266` |
| **E** | The gate over-fires and blocks legitimate detaches | ✅ Keyed on the detached permission being dangerous, not on "is this the last dangerous permission" — broader, simpler, strictly safer, and symmetric with attach. §11.3 includes the "ordinary permission by a non-admin ⇒ 204" negative case |
| **E** | **The mint-side gate's population is reachable in one step from the caller-side predicate** | ❌ **T-E28, Medium.** RES-13's framing ("the mint side staying *narrower* is the safe direction") reads as a containment; it is not one |
| **E** | **Attaching the third dangerous permission silently converts existing holders into administrators** | ❌ **T-E27, High.** The shipped holder-count signal fires but does not say *that* |

### C9 — `RbacZeroActiveAdminsHealthIndicator` + `/actuator/health` (D10, D11, D12)

| | Threat | Verdict |
|---|---|---|
| **T** | The detection control holds write capability over `user_roles` | ⚠️ **T-T14, Low-Medium.** It injects `JpaUserRoleRepository`, a full `JpaRepository`, so it holds `save`/`delete`/`deleteAll`. `user_roles` has a no-DELETE trigger and a column-scoped `UPDATE` grant, so a stray delete/update is blocked at the DB — but `INSERT` is granted, so a stray `save` **executes**. Pre-existing from US-012, but D12 re-affirms and widens the coupling without re-examining it. This is US-016 T-T13's shape, one component over |
| **T** | Two divergent implementations of one predicate | ⚠️ **T-T15, Low.** Java `RbacAdminEquivalence.isAdminEquivalent` vs. the SQL `r.name = :n OR EXISTS(… p.name IN :names)`. The *set* propagates automatically (D12 passes `NAMES`); the **combinator** does not. A future ANY→something change updates one and not the other — with no test that would notice |
| **R** | — | n/a |
| **I** | Cross-tenant disclosure through the widened DOWN population | ✅ **FR-6 preserved.** Count-only in the detail, ids in the WARN, `show-details: when-authorized`, `permitAll` path. The count's *meaning* widens (a `MEMBER` of any tenant learns how many tenants platform-wide have zero admin-equivalent holders) — unchanged in kind, recorded as **RES-20**, Low |
| **I** | The `issue` string enumerates the dangerous permission set | ✅ Low and already public — the set is inferable from the 403 behaviour of both gates. Accepted |
| **D** | **Anonymous cost amplification: two queries over four tables on a `permitAll` endpoint** | ⚠️ **T-D16, Low-Medium.** **Already mitigated by a shipped 30 s cache TTL** added by `07-security-review.md` M-2 for this exact indicator — which makes D10's "zero staleness" claim **false** and, worse, makes it an argument a future engineer could use to remove the TTL |
| **D** | A widened DOWN takes the application down | ✅ **Verified safe.** Liveness/readiness groups include only `livenessState`/`readinessState`; the Dockerfile probes `/actuator/health/liveness`. Record it so a future story does not sweep this indicator into a probe group |
| **E** | A tenant with **no** admin-equivalent role stays invisible (D11/RES-14) | ✅ Correct call. It is a provisioning defect, not a lockout, and reporting it would turn a rare page into a bootstrap-routine one. Accepted as written |

### C10 — observability: canary, counters, WARNs, alerts, runbooks (D14, D15, D16)

| | Threat | Verdict |
|---|---|---|
| **I** | Detection regression: the canary pages on a now-legitimate operation | ✅ **D14 identifies and fixes the regression the fix would otherwise have created**, keeps the two mechanisms separate, keeps the alert PromQL byte-identical, and mandates an acceptance IT. This is the design doing exactly what US-016 R5/R8/M-2 were written to force |
| **I** | **The canary and the gate now share one input** | ❌ **T-E29 / RES-18, Medium** (design rates it Low). A canary that shares the gate's primary input cannot detect the gate's most dangerous failure mode |
| **R** | Operators act on stale alert meanings | ✅ §9.5's eight mandatory doc edits are correctly scoped and correctly made non-optional, including the two **pre-existing** drifts in US-012's runbook. Fixing those while in there is right |
| **R** | The lockout block has no durable record | ❌ **T-R10, Medium** |
| **D** | Metric cardinality | ✅ All bounded and counted in the design (2, 4, ≤12, 1 series). `admin_equivalent_lock_set_size` is untagged — correct |
| **I** | New signals carry PII | ✅ None (§0.3). Every added field is a UUID, an int, a role name under the CR/LF-excluding allow-list, or a bounded constant |
| **R** | The only signal showing FR-3's loosening being exercised carries no tenant/actor dimension | ⚠️ **T-R11, Low.** `privileged_role_change_allowed{operation, callerMatchedOn}` tells you *that* a non-`TENANT_ADMIN` administrator acted, never *which tenant* — so Success Metric 5 and any post-deploy investigation start from a metric with no path to a subject. The WARN/INFO side must carry it |

### C11 — trust dependencies and rollout (D19, D20)

| | Threat | Verdict |
|---|---|---|
| **E** | US-016 **RES-1(b) / T-E21** interacts with FR-3 | ❌ **T-E27, High.** Not mentioned anywhere in the design or ADR-0018 |
| **E** | The D14 denial throttle bounds the new lock acquisition | ⚠️ True, and **unstated**. The design's only reachability argument is the (wrong) "only privileged principals reach it". RC-20 part 1 |
| **E** | Flag-off as a rollback lever | ✅ **D19 is correctly reasoned**, including the genuinely new observation that FR-3's "off" position is *incoherent* rather than safe, and that a percentage rollout of an authorization gate is strictly worse than either state. §10.3's "flag-off is not a security rollback" caveat is right |
| **E** | `MEMBER` amplification | ✅ Still closed. `RbacRoleNames.RESERVED` + AC7-before-AC11 means `MEMBER` can never carry a dangerous permission, so it can never become admin-equivalent under **either** predicate. Re-verified this session |
| **D** | The pre-deploy sweep leaves a known-bad population unremediated at deploy | ⚠️ **RC-21, Medium.** Detection without forensics, evidence retention, or a stated action on a non-empty result |
| **I**/**E** | ~30-min permission staleness (US-015 T-I8) | ⚠️ **Direction reversed by this story, and worth stating.** For US-016 the staleness was a *detection window* before an escalation became effective. FR-3's caller gate is a **live DB read**, so a user who becomes fully admin-equivalent can act as an administrator on the **next request**, not the next mint. The 30-minute cushion that used to sit in front of T-E21's payoff is gone. Feeds T-E27 |

---

## 3. Identified threats

Each entry: what an attacker achieves · existing mitigation in the design · required mitigation · residual.

---

### T-E27 — FR-3 amplifies US-016's standing pre-positioning primitive (RES-1(b) / T-E21) from "admin-equivalent permissions" to "administrator" · **High** · ❌ change required

**The design does not mention T-E21 or RES-1(b) anywhere.** That register entry is owned, has a review date of 2026-11-27 and a **hard expiry at Epic 3 kickoff**, and US-017 changes its payoff without re-rating it. This is the same failure mode US-016's own Gate 2 caught (RC-8) and it is worth catching twice, because the discipline is precisely what keeps a risk register honest across stories.

**The chain, re-verified end to end in code this session.**

| Step | Actor | Mechanism | Gate today | Gate after US-017 | Signal |
|---|---|---|---|---|---|
| 1 | any `user:write` holder (**non-admin**) | `POST /users/{self}/roles` for every benign custom role in the tenant | **None — correct by design.** `privileged` is false | unchanged | `self_role_assignment{privileged="false"}` — "benign self-service; ticket at most" |
| 2 | *(wait)* | — | — | — | — |
| 3 | an active `TENANT_ADMIN` | attaches `role:write`, then `user:write`, then `tenant:write` to role **R** (three legitimate AC11-gated actions) | AC11 passes each time | unchanged | `dangerous_permission_granted{permission, holders}` ×3 + `RBAC_DANGEROUS_PERMISSION_GRANTED_TO_EXISTING_HOLDERS` WARN ×3 (`RoleManagementService.java:220-231`, verified) |
| 4 | the attacker | *nothing* | **Holds `role:write`+`user:write`+`tenant:write`. Cannot pass `requireActiveTenantAdmin` — 403 on every privileged assign/revoke** | **Now passes `isFullyAdminEquivalent` — full caller-side administrative capability, on the next request, from a live DB read** | none |
| 5 | the attacker | `POST /users/{self}/roles {TENANT_ADMIN}` | **403** | **201** — they are now a literal `TENANT_ADMIN` (T-E28) | `self_role_assignment{privileged="true", callerIsAdmin="true"}` — **no page**, because the re-derived canary correctly says the caller *was* admin-equivalent |

**What the attacker achieves.** Before US-017: admin-equivalent *permissions*, effective at the next token mint (≤ ~30 min), with no ability to administer role assignments. After US-017: **the administrator role itself**, effective on the next request, with no race, no collusion, no privilege they did not already hold, and no gate evaluation at the moment the capability was conferred. Step 5 additionally unlocks the mint side (attach/detach of dangerous permissions), which D18 records as *not* granted to this population.

**Reachability.** Unchanged from T-E21 — it is available to every `user:write` holder in every tenant, permanently, and it regenerates every time an administrator attaches a dangerous permission. **Only the payoff changes, and it changes by a lot.** The trigger is also now *observable to the attacker*: the target-role privilege oracle (US-016 RES-8 / T-I10) lets them poll for the moment R becomes dangerous.

**Existing mitigation in the design.** None — the threat is not named. Existing mitigation **in code**: US-016's D13 holder-count signal on `attachPermission` (verified, `RoleManagementService.java:186-239`), which fires a WARN and a bucketed metric when a dangerous permission is attached to a role with existing holders. That control was built for exactly this threat and it is the right place to extend.

**Why the existing signal is not sufficient as-is.** It answers *"how many users did this attach silently escalate?"* It does **not** answer *"did this attach just make the role a caller-qualifying administrator?"* — which is the new, materially more serious event. The administrator performing the third attach has no way to know that the role crossed the ALL-three threshold, and neither does the operator triaging the WARN. Three separate WARNs, minutes or weeks apart, do not compose into that fact for a human.

**Required mitigation (RC-15).** Three parts; the first two are documentation and mandatory, the third is a small, cheap code addition on an already-instrumented admin-only path.

1. **Record T-E21 / RES-1(b) in `03-design.md` §12.3 and in ADR-0018's "what this ADR does not close"** as amplified-by-this-story, with the chain above. Do not create a new entry that competes with the existing one — cite RES-1(b), carry its owner, its 2026-11-27 review date and its Epic-3 hard expiry forward, and state that US-017 increases its impact without changing its likelihood.
2. **Correct §4.2's Javadoc replacement text.** As drafted it says RES-3 and RES-9 are closed and RES-13 is relocated. It must also say, in the same paragraph, that the attach-after-assign path (RES-1(b)) now confers *caller-side* administrative capability — otherwise the next reader of that method concludes the surviving escalation path is unaffected by this change.
3. **Extend the shipped `attachPermission` signal to report the threshold crossing.** On the dangerous path, `attachPermission` already performs one bounded read (`findActiveUserIdsForRole`). Add one more bounded read on that same path — `findPermissionNamesForRole(role.id())`, the shipped M7, after the attach — and when `RbacAdminEquivalence.isFullyAdminEquivalent(role.name(), names)` becomes true, emit a **distinct** WARN (`RBAC_ROLE_BECAME_FULLY_ADMIN_EQUIVALENT`) carrying `{tenantId, roleId, roleName, holderCount, grantedBy}` and a bounded counter `nexus.rbac.role_became_fully_admin_equivalent{holders}`. One extra bounded query on a rare, admin-only path; no schema change; no new port method. Alert it at **ticket** severity with `holderCount > 0` escalated to **page** — that combination is the exact signature of a mass silent promotion to administrator, and it is the only moment at which anyone can see it.

**If part 3 does not ship in US-017, it must be a named successor story with an id before US-017 merges** — the same verification condition US-015 imposed on US-016 and US-016 imposed on itself, applied for the same reason. Silence is not acceptable here specifically because US-017 is the story that increases the payoff.

**Residual after mitigation: High → Medium** if part 3 ships; **High, explicitly re-accepted with the inherited owner and Epic-3 expiry** if it does not. Recorded against **RES-1(b)**, not a new entry.

---

### T-E28 — D18/RES-13's "the mint side stays narrower" is a direction, not a containment · **Medium** · ❌ wording and detection change required

**The claim under test.** ADR-0018's *what this ADR does not close* and `03-design.md` RES-13: *"a fully admin-equivalent caller can assign and revoke privileged roles but cannot attach or detach dangerous permissions. The mint side staying **narrower** is the safe direction, and moving it is a separate decision."*

**The one-step defeat.** A fully admin-equivalent caller:

1. `POST /api/v1/users/{self}/roles {roleId: TENANT_ADMIN}` — `nameMatch` is true ⇒ `privileged` ⇒ `requireActiveTenantAdmin` ⇒ **passes** under D2 ⇒ `hasActiveAssignment` false ⇒ **201**. Verified reachable against the shipped flow (`RoleAssignmentService.java:162-192`) with only the gate's predicate changed.
2. They now hold an active literal `TENANT_ADMIN` assignment ⇒ `verifyCallerIsActiveTenantAdmin` (`RoleManagementService.java:334-355`) passes ⇒ they may attach and detach dangerous permissions at will, including on the roles that feed the lockout guard's own input.

**What this does and does not mean.** It is **not** a privilege escalation: D2 defines an ALL-three holder as a full stand-in for `TENANT_ADMIN`, so gaining the literal role grants nothing the predicate did not already assert. **It is a correctness problem in the risk record**, and it matters for three concrete reasons:

- §7.5's "Change 1 — D13 closes the mechanism" is stated as *"After D13, that requires an active literal `TENANT_ADMIN`."* The true population is "an active literal `TENANT_ADMIN`, **or** anyone who can become one in a single request." For the TOCTOU analysis the conclusion is unchanged (both populations are administrators), but the sentence as written will be read by the next story as a boundary.
- RES-13 is presented as a *mitigating* asymmetry. A future reviewer deciding whether to widen the mint side will read "the safe direction" and conclude there is a control to preserve. There is not.
- **It is invisible.** Under D14's re-derived canary, this self-assignment emits `self_role_assignment{privileged="true", callerIsAdmin="true"}` — correctly, since the caller *is* admin-equivalent — so the page does not fire. The single most sensitive operation FR-3 newly permits (a non-`TENANT_ADMIN` principal promoting themselves to `TENANT_ADMIN`) produces **no distinguishable signal at all**. `privileged_role_change_allowed{operation="assign", callerMatchedOn="ALL_DANGEROUS_PERMISSIONS"}` increments — but it carries no target-role and no tenant dimension, so it cannot answer "who just became an admin, where".

**Existing mitigation.** None beyond the `ROLE_ASSIGNED` durable audit row, which does record it but is not alerted on and does not record *how the caller qualified*.

**Required mitigation (RC-16).** All three parts are cheap and none changes a decision:

1. **Re-word RES-13 and ADR-0018's follow-on note.** Replace "the safe direction" containment framing with the accurate one: *the mint side is narrower by construction but is reachable in one self-assignment by any fully admin-equivalent caller, so it bounds nothing; it is recorded for definitional consistency, not as a control.* Do the same for §7.5's Change 1 sentence.
2. **Emit a dedicated signal for the promotion.** At `requireActiveTenantAdmin`'s pass point the design already computes `callerMatchedOn`. When `callerMatchedOn == ALL_DANGEROUS_PERMISSIONS` **and** the target role is the literal `TENANT_ADMIN`, emit a WARN `RBAC_ADMIN_MINTED_BY_NON_NAMED_ADMIN` with `{tenantId, actorUserId, targetUserId, roleId}` and alert it at **ticket** severity (**page** when `targetUserId == actor.userId()`). Zero new queries — every value is already in hand.
3. **Give `privileged_role_change_allowed` a subject in the logs.** The counter's tags stay as designed (bounded); the accompanying INFO/WARN must carry `tenantId` and `actorUserId` so the metric has a triage path (**T-R11**).

**Residual after mitigation: Low, accepted** — the capability is definitionally correct; what was missing was the record and the signal.

---

### T-E29 — M10 is a single input with three simultaneous fail-open consequences, and the canary that would notice shares it · **Medium** · ❌ change required

The design records this partially, as **RES-18**, rated **Low**, scoped to the canary only: *"the two mechanisms now share one input (`fullyAdminEquivalentIds`, from M10), so an M10 bug makes both wrong together and the canary silent."* That is the third consequence. There are three.

**Trace an over-broad M10 result** — a tenant-scoped read returning `(roleId, permissionName)` pairs that include a role's permissions incorrectly (a mis-joined `rp.id.roleId`, a missing `r.tenantId` predicate, a future `LEFT JOIN`, a pagination default, a duplicate row):

| Consumer | Correct behaviour | Behaviour with an over-broad M10 | Direction |
|---|---|---|---|
| `callerSet` = `fullyAdminEquivalentIds ∪ namedAdminRoleId` (D2, the gate) | a `user:write`-only caller is denied | a role the caller holds is wrongly classified ALL-three ⇒ **M5b returns true ⇒ 403 becomes 201/204** | **fail OPEN** — the vacuity bug by a different route |
| `lockSet` / `locked` holders (D5, the lockout) | holders = distinct users of genuinely admin-equivalent roles | benign roles' holders are counted ⇒ `remaining` non-empty ⇒ **the 409 does not fire ⇒ the tenant is zeroed** | **fail OPEN** — the exact outcome FR-1 exists to prevent |
| `callerHoldsActiveAdminEquivalentRole` (D14, the canary) | disagrees with the gate when the gate is wrong | consumes the **same** set ⇒ agrees ⇒ `callerIsAdmin="true"` ⇒ **no page** | **silent** |

So a single defect in one new read produces a wrong authorization decision, a wrong business-rule decision, and a silent detector, **together**. The design's own §7.2 correctly identifies an under-broad M10 as fail-safe (more locking, spurious 409) and D9 correctly makes an *empty* result fail closed. The **over-broad** direction is not analysed anywhere.

**Existing mitigation in the design.** For (a) and (b): M10's repository and delegation tests, the `RbacAdminEquivalence` domain unit tests, MC-D. For (c): the same, plus "the canary's name half remains fully independent" and one runbook sentence. All four are **unit-level tests of the components in isolation** — which is exactly the assurance class the canary exists to backstop, per `07-security-review.md` M-2's own reasoning. Note that the name half's independence does not help: in the scenario above the caller qualified via the over-broad *id*, so the name half is simply `false` and the id half carries the decision.

**Required mitigation (RC-17).** Two parts.

1. **Give the canary an independent derivation of ALL-three.** The canary runs only on the self-assignment path (`targetUserId == actor.userId()`), which is rare, and only post-commit. Replace the `roles.fullyAdminEquivalentIds().contains(a.roleId())` test with a **second, independently-implemented** answer to the same question — a single non-locking query on `JpaUserRoleRepository`, driven off `fk_user_roles_user`, of the shape *"does this user hold an active assignment of a role that carries all three of these permission names, in this tenant?"* expressed in SQL (`GROUP BY … HAVING COUNT(DISTINCT p.name) = 3`). That gives the canary: a different index, a different statement, a different combinator implementation, and **no shared input with the gate** beyond the permission names themselves. Cost: one bounded read on a rare path. This restores the property M-2 bought and that RES-18 concedes was lost.
   *Acceptable fallback if the extra read is refused:* keep the shared input but add a runtime disagreement check — compare M10's ALL-three classification of the caller's own roles against M7-per-role for those roles, and emit `RBAC_ADMIN_EQUIVALENCE_RESOLUTION_DISAGREEMENT` on mismatch. This is strictly worse (it only catches M10 vs. M7 divergence, not a shared misunderstanding) and should be recorded as such.
2. **Add MC-H — an M10 ↔ M7 equivalence integration test.** Over a fixture matrix of a tenant's roles (none / one / two / all three dangerous permissions; zero-permission role; the literal `TENANT_ADMIN`; a foreign-tenant role), assert that the partition computed from **one** M10 call equals the partition computed by calling the shipped, separately-tested **M7 per role**. M7 is already covered by US-016's tests and is the incumbent; making the new bulk read prove itself against it is the cheapest possible bound on the single most load-bearing new statement in this story.

**Re-rate RES-18 from Low to Medium** and restate it over all three consumers, not the canary alone.

**Residual after mitigation: Low.**

---

### T-E30 — Can a role be crafted that passes ALL-three without being a genuine administrator? · **Low** · ✅ attacked, survived; one implementation trap must be pinned

This is the brief's first question and D2's central claim, so I attacked it directly rather than accepting the design's argument.

**Part 1 — the minting question: could a non-administrator produce an ALL-three role?** No, on every path I could construct:

- **Name half.** A tenant-created role can never be named `TENANT_ADMIN` — `RbacRoleNames.RESERVED` (verified, `RbacRoleNames.java:22`), enforced at creation, and `uq_roles_tenant_name` under `utf8mb4_0900_ai_ci` collapses every case and accent variant onto the seeded role. US-016 T-T12 remains closed.
- **Permission half.** Each of the three attaches is AC11-gated on an **active literal `TENANT_ADMIN`** (`RoleManagementService.java:176-179`), fail-closed on an unseeded tenant. `role_permissions` has no other application writer, `roles` has no `UPDATE`/`DELETE` grant, and `permissions` is `SELECT`-only — so the permission set of a role cannot be changed except through attach/detach.
- **Seed half.** `TENANT_ADMIN` carries all 7 permissions and satisfies both predicates; `MEMBER` carries only `user:read` and can never carry more (AC7 runs before AC11, and `MEMBER` is reserved). No seeded role becomes caller-qualifying by accident.

⇒ **Every ALL-three role in the system was created by a literal `TENANT_ADMIN`, deliberately, in three separate audited actions.** D2's "closest permission-shaped statement of *this role is a full stand-in for `TENANT_ADMIN`*" holds. The one *systemic* way an ALL-three role acquires an unintended holder is T-E27, which is a pre-positioning problem, not a predicate problem.

**Part 2 — does ALL-three miss a case ANY would have caught?** Yes, and it is the intended trade (RES-12): a role carrying `role:write` + `user:write` but not `tenant:write` is arguably admin-equivalent and cannot administer. **This fails closed** — a 403 for someone who arguably should pass. It creates an operational dead end (a tenant whose only privileged principals hold such a role still cannot administer role assignments), which is the availability cost D2 reason 3 knowingly accepts. I concur: the alternative direction fails open, and the remedy (an explicit marker column) is correctly out of scope. **No change required; RES-12 as written is accurate.**

**Part 3 — the implementation trap, which is where this finding lives.** `carriesAll` has a fail-open shape that `carriesAny` does not:

```java
// FAILS OPEN on a duplicate-bearing collection:
//   ["user:write","user:write","user:write"]  ->  3  ->  true
permissionNames.stream().filter(RbacDangerousPermissions::contains).count() >= 3
```

M10 cannot produce duplicates today (`pk_role_permissions (role_id, permission_id)` plus `uq_permissions_name`), so this is latent rather than live — which is exactly when it is cheap to pin and expensive to discover. A `containsAll` implementation has the opposite trap: it is **case-sensitive**, which fails *closed*, but silently, and would make the caller gate deny a legitimate `Role:Write` variant.

**Required mitigation (RC-18 part 1).** `carriesAll` must be specified and implemented as: *for each of the three names, does the collection contain a case-insensitive match?* — i.e. a per-name `anyMatch`, never a count and never `containsAll`. Extend **MC-B** with three assertions, named as regression tests in their Javadoc:
- `["user:write","user:write","user:write"]` ⇒ `carriesAll` is **false**;
- `["Role:Write","USER:write","tenant:WRITE"]` ⇒ `carriesAll` is **true**;
- `[null, "user:write", …]` and `[]` ⇒ no throw; `[]` ⇒ false (mirrors the shipped null-safe `contains`).

**Residual after mitigation: Low.**

---

### T-D13 — The union lock is acquired before the authorization decision on **both** verbs, and D7's reachability premise is wrong · **Medium** · ❌ change required

**Attack.** A non-admin holding `user:write` issues, in a loop, `POST /api/v1/users/{self}/roles {roleId: <any admin-equivalent role in the tenant>}`. Per design §6.2, each request:

1. passes the 404s (the attacker enumerates roles with `role:read`, or simply targets the seeded `TENANT_ADMIN`);
2. passes the D14 throttle (until its bound is reached);
3. computes `privileged` (M7);
4. issues **M10**, then **M8**;
5. acquires **M11 — a `FOR UPDATE` lock over every active assignment of every admin-equivalent role in the tenant**, in ascending order;
6. issues **M5b**;
7. calls `recordDenial`, which borrows a **second pooled connection** for a `REQUIRES_NEW` transaction and commits it — **while the tenant-wide X lock is still held**;
8. throws 403, rolls back, releases.

**What the attacker achieves.** For the duration of steps 5–8, every privileged role change in the tenant blocks: every other privileged `assign()` and `revoke()` (they conflict at M11 by D7's own design), and — because D7 makes the lock *total across both verbs* — the serialisation is now complete rather than partial. This is US-016's **T-D11** (rated Medium as the composed RES-4+RES-5) with three amplifications: a **second verb** that takes no lock at all today, a lock set of **N role ranges instead of one**, and **one extra read (M10)** inside the request but before the lock.

**Why this is a finding and not just an inherited risk.** D7's cost paragraph says:

> *"Justified because these are rare, already-admin-gated administrative operations on an endpoint family US-012's threat model deliberately left un-rate-limited **because only privileged principals reach it**; the denial path is already rate-bounded by D14."*

The first clause is **false for the path that matters**. Per the design's own §6.2, check 4.5 (M11) precedes check 5 (the gate), so the lock is acquired by callers who are about to be denied — the exact non-admin population US-016's gate exists to deny. The second clause is **true and is the actual mitigation**, and it is stated as an aside rather than as the control it is. A reviewer or a future story reading D7 would conclude the lock is only reachable by administrators and, for example, relax the throttle.

Note what is *right* here and must not be changed: M11 **must** be acquired before M5b, or D8's containment proof collapses and the S→X ordering hazard ADR-0017 D4 was written to prevent comes back. The fix is not to reorder; it is to state the real reachability and the real bound, and to measure it.

**Existing mitigation.** US-016 D14's per-`(tenantId, actorUserId)` denial throttle, verified to run **before** any lock (`RoleAssignmentService.java:158`, `:299`). Its known limits carry over unchanged: **per-replica** under the default in-memory store (US-016 **RES-11(c)** — effective bound is `max-denials × replicas`), and a suppressed request emits no signal (**RES-11(b)**, mitigated by promoting `nexus_rbac_denial_throttle_engaged` to page).

**Required mitigation (RC-20 parts 1–3).**
1. **Correct D7's cost paragraph.** State plainly: *M11 is acquired before the authorization decision on both verbs, so any `user:write` holder can force its acquisition; the bound is D14's denial throttle, and that bound is per-replica under the default store.* Cite US-016 RES-11(c) and the runbook's `store-type=redis` guidance as a deployment prerequisite for this design, not as background.
2. **Extend the lock-hold timer's coverage to the denial path on `assign()`.** D15 already adds `operation` and the `denied` outcome exists; make it explicit that `{operation="assign", outcome="denied"}` is a **new, first-class series** and give it a runbook entry — it is the only direct measurement of this threat.
3. **Re-rate the composed residual.** US-016's RES-4+RES-5 composite (Medium) does not disappear; it widens. Record it as **RES-19** in §12.3 with the composed shape and the throttle as its named bound, rather than letting a reader infer that D7's serialisation cost is only a legitimate-traffic concern.

**Residual after mitigation: Medium → Low**, bounded by D14 and now measured.

---

### T-D14 — M11's locked and materialised set is unbounded **and reachable from the denial path** · **Medium** · ⚠️ re-rate and bound

The design records this as **RES-17**, **Low**: *"a tenant where a dangerous custom role has very many holders locks and materialises all of them… the rows must be locked for correctness regardless."*

**The correctness argument is right.** You cannot count distinct holders race-free without locking the rows. I have no alternative to propose and I am not asking for one.

**Two things make Low the wrong rating.**

1. **It composes with T-D13.** The cost is not paid only by legitimate administrators; it is paid, up to `max-denials` times per window per actor per replica, by **any `user:write` holder**, on a request that will be denied. A tenant with a widely-held dangerous custom role therefore has an amplification factor: one cheap HTTP request ⇒ an exclusive lock over, and Java-side materialisation of, every one of that role's active assignment rows.
2. **The population that makes it large is created by the story's own worst case.** The way a tenant ends up with a dangerous role held by thousands of users is precisely T-E27's step 3 — an administrator attaching `user:write` to a broadly-assigned role. RES-17 and RES-1(b) are the same scenario read two different ways, and neither entry points at the other.

**Existing mitigation.** `nexus.rbac.admin_equivalent_lock_set_size` (D15) — a `DistributionSummary` with no tags, giving a p99. Good instrument; **no threshold, no alert, no operator action**.

**Required mitigation (RC-20 part 4).** Keep the design as-is; add three cheap things:
- an alert on `admin_equivalent_lock_set_size` p99 crossing a threshold captured during the §10.3 step-2 soak, at **ticket** severity, with a runbook entry whose remediation is "split the dangerous custom role's holder population, or move the permission to a narrower role";
- a `monitoring.md` note tying it to the lock-hold timer, so a p99 lock-set growth and a p99 lock-hold growth are triaged as one symptom;
- a cross-reference between RES-17 and RES-1(b) in both directions.

**Re-rate RES-17 Low → Medium.**

**Residual after mitigation: Low.**

---

### T-D15 — D7's total-acquisition-order claim is proved over one index; the privileged × benign pair is not covered, and harness C has no benign thread · **Medium** · ❌ change required

**I agree with D7's decision and with its rejection of every alternative.** Working through it independently:

- **Making the order total across both verbs is the correct fix**, and it is the *only* one that eliminates RES-10's cycle at the root rather than narrowing its window. The alternative (leave `assign()` unlocked) genuinely does ship a widened deadlock, and §7.3's demonstration that harness C's own shipped fixture reproduces it is convincing.
- **A single IN-list statement beats a loop of N locks**, for the reasons given: one acquisition point, one plan, no dependence on a caller remembering to sort or on there being no early return between acquisitions.
- **A total order does not require identical lock sets.** This is the subtle step and it is correct: if every transaction acquires in ascending `role_id` order, a transaction holding a lock at `role_id = B` has already passed every element of *its own* set below `B`, so it cannot later request a lock at `role_id = A < B` that another ascending transaction holds. Differing sets do not break it. I could not construct a cycle among M11 statements.
- **D8's containment (ALL ⊆ ANY ⊆ lock set) is genuinely elegant** and makes the caller read free of new acquisitions.

**Where the proof is short — three places.**

**(1) The claim is proved over `fk_user_roles_role` only.** A privileged transaction does not take only M11's locks. It also takes, outside M11's index region:
- `assign()`'s `INSERT` → insert-intention locks in **`uq_user_role_active`** (on the STORED generated `active_key`) and in **`fk_user_roles_user`**, plus a gap in the clustered index;
- `revoke()`'s M6 `UPDATE revoked_at` → because `active_key` is a **STORED** generated column with a unique index (verified under US-016 §0.1 against `V5__rbac_schema.sql:60-90`), this mutates an indexed column and therefore takes locks in `uq_user_role_active`.

For **privileged × privileged** the design's argument is not containment but **mutual exclusion** — only one such transaction is past M11 at a time — and that is sound. For **privileged × benign** the design argues:

> *"A benign assign/revoke takes no M11 lock and touches `role_id` ranges that are, by definition, not in any lock set — so it cannot cycle with a privileged transaction **through `fk_user_roles_role`**."*

The qualifier is in the design's own sentence and it is doing all the work. A benign `assign(benignRole)` for user U and a privileged `revoke(adminRole)` from user U both touch `uq_user_role_active` and `fk_user_roles_user`, where `role_id` disjointness buys nothing (`active_key` ordering is unrelated to `role_id`, and `fk_user_roles_user` is keyed on the user). I could not construct a concrete cycle — the benign transaction acquires no lock the privileged one requests *first*, on the orderings I could enumerate — but "I could not construct one" is not the standard §7 sets for itself, and this interaction is **new**: today the privileged transaction's X region is one role range and the benign path was analysed against it; after D7 the privileged transaction holds a tenant-wide region for materially longer and on a second verb.

**(2) Harness C cannot exercise it.** As reshaped by D7, harness C's threads are `assign(TENANT_ADMIN)`, `assign(dangerousCustomRole)`, `revoke(TENANT_ADMIN)`, `revoke(dangerousCustomRole)` and a denied non-admin `revoke` — **every one of them privileged**. It therefore proves exactly the case D7's mutual-exclusion argument already covers, and nothing about the case the argument leaves to a per-index inspection. This is the same structural gap US-016 found in harness A (homogeneous, cannot test the cross-method claim it was cited for).

**(3) The "ascending" contract does not say which ascending.** `List.sort` on `UUID` uses `UUID.compareTo`, which compares `mostSigBits` as a **signed** long; MySQL compares `BINARY(16)` **unsigned**. They agree for every id in the system today (verification item 14: seeded ids are `019f6839-…`/`00000000-…`, and UUIDv7's top bit stays clear until ≈ year 6429), so this is latent. But MC-E as specified — "assert the list passed to M11 is sorted ascending" — would pass with a comparator that does not match the database's order, giving **false assurance about the exact property D6 rests on**. Relatedly, the real guarantee comes from the *plan*: an ascending range scan on `fk_user_roles_role` acquires in index order regardless of the IN-list's order, so the Java sort is belt-and-braces — and the belt is the plan. MC-C asserts `key = fk_user_roles_role` for one fixture; **plan stability across IN-list cardinalities is what the argument actually needs**, because a 1-element and a 40-element IN-list can be costed differently and a full-scan fallback would acquire in primary-key order.

**Required mitigation (RC-20 parts 5–7).**
5. **Restate D7's rule per index.** Say: *totally ordered with respect to `fk_user_roles_role` acquisitions; acquisitions in `uq_user_role_active`, `fk_user_roles_user` and the clustered index are serialised for privileged × privileged pairs by the M11 conflict, and are unchanged-in-kind from the shipped design for privileged × benign pairs.* That is defensible and it is what the analysis supports; the current unqualified phrasing is not.
6. **Add a benign thread to harness C** — `assign(benignRole)` and `revoke(benignRole)` against the same users the privileged threads touch, same `CyclicBarrier` shape, same "any unexpected exception type fails loudly" rule. This is one fixture addition to a harness that is being reshaped anyway and it is the only empirical evidence for the claim in part 5.
7. **Pin the ordering and the plan.** Specify in M11's port Javadoc that "ascending" means **unsigned byte-wise order of the 16-byte representation**, matching `BINARY(16)`; have MC-E assert that comparator, not `UUID.compareTo`. Extend **MC-C** to assert `key = fk_user_roles_role` for IN-lists of size 1, 2 and ≥ 20. A plan mismatch remains an Architect-level escalation, not a test to relax.

**Residual after mitigation: Low.** Note that D7's own exit gate (harness C green over ≥ 5 runs) remains the right instrument — RC-20 only makes it test the case it is being cited for.

---

### T-R10 — A blocked lockout has no durable record, and the compensating control inherits an unresolved retention precondition · **Medium** · ❌ change required (to the record, not the decision)

**I concur with D16's decision** and want that on the record before the dissent: `LastAdminRoleException` is a business-rule conflict, not an authorization denial; `RbacAuditPort.recordRoleAssignmentDenied`'s Javadoc scopes `ROLE_ASSIGNMENT_DENIED` to *"the two 403 authorization denials"*; widening it would falsify a shipped contract and change the `auth_events` population US-014's alerting is tuned on. Routing a 409 through the denial lane would be the wrong fix and the design is right to refuse it.

**Where I dissent: "the event is fully observable today via the WARN plus, now, a dedicated counter" is not sufficient on its own, for two reasons the design does not address.**

**Reason 1 — the retention precondition is the one this epic has twice refused to leave implied.** US-015 **RES-10** resolved an identical shape by requiring *either* a durable record *or* a written mandate that the WARN be **retained at least as long as `auth_events`, with the figure named**. US-016 **RES-6** was re-rated Medium and resolved the same way. `auth_events` is append-only and never pruned by this application; application logs go to a platform whose retention nobody has cited in any document in this epic. D16 reuses the "the WARN carries it" argument without reusing the condition that made that argument acceptable twice before.

**Reason 2 — there is an attack-adjacent scenario, and the brief asks for it.** I stress-tested D16's "an authorized actor made a mistake" framing against §6.3's proof (which I re-derived and which holds: the 409 is reachable only by the tenant's sole admin-equivalent holder revoking their own last such assignment). Three scenarios:

- **Reconnaissance by an unauthorized caller:** *not reachable.* 403 precedes 409 (§6.2 rows 5/6), so a non-admin learns nothing. D16 is safe here and this is worth stating, because it is the scenario one would reach for first.
- **Destructive sequence by a compromised/hostile administrator:** an actor who has become fully admin-equivalent (T-E27) revokes the tenant's other administrators one by one — each of those **is** durably audited as `ROLE_REVOKED` — until only they remain; the final self-revoke 409s. Here D16 is fine: the durable trail of the attack exists, and the 409 is merely where it stopped.
- **The one that matters: a compromised sole-admin account used for destruction.** The attacker's every attempt to remove the tenant's last admin access is **blocked**, so there is **no** `ROLE_REVOKED`, **no** `ROLE_ASSIGNMENT_DENIED`, and no durable row of any kind. A repeated, deliberate attempt to destroy a tenant's administrative access leaves **only WARN lines and a counter**. If logs are retained for 30 days and `auth_events` forever, then for any investigation older than the log window, the attempt is indistinguishable from "nothing happened" — and the counter (bounded Prometheus retention, no actor dimension) cannot attribute it.

This is not an argument for `ROLE_ASSIGNMENT_DENIED`. It is an argument that "WARN-only" must come with the same written condition the epic imposed twice.

**Required mitigation (RC-19).** Pick one, in writing, in `03-design.md` §9.4 and `monitoring.md`:
1. **Preferred, cheapest:** mandate that `RBAC_LAST_ADMIN_REVOCATION_BLOCKED` (and, for consistency, `RBAC_PRIVILEGED_ROLE_CHANGE_BLOCKED` and the new `RBAC_DANGEROUS_PERMISSION_DETACH_BLOCKED`) be **retained at least as long as `auth_events`**, with the figure **named**, not implied. This is US-015 RES-10's own resolution and it requires no code.
2. **Alternative:** add a bounded `actorUserId`-free durable record via a distinct, correctly-named event type rather than overloading `ROLE_ASSIGNMENT_DENIED`. Larger; not recommended for this story.

Additionally: add a **ticket**-severity alert on `nexus.rbac.last_admin_lockout_blocked` firing **repeatedly for the same tenant within a window** — a one-off is an offboarding mistake, three in ten minutes is not. The counter D15 adds makes this free.

**Residual after mitigation: Low.** **Compliance sign-off is still required** (design §13 item 1) — but on the corrected posture, not the current one.

---

### T-D16 — D10's "zero staleness" is false, and the control that actually bounds the widened query is unmentioned · **Low-Medium** · ❌ correction required

**Verified.** `application.yml:88-96`:

```yaml
    health:
      show-details: when-authorized
      # 07-security-review.md M-2: /actuator/health/** is permitAll and carries no rate limit,
      # and US-012's rbacZeroActiveAdmins indicator runs a cross-tenant roles scan on every hit.
      # Without a cache TTL, an anonymous caller looping this endpoint forces an unbounded number
      # of those scans. A short TTL bounds the amplification to the platform's normal
      # health-check cadence without weakening the signal …
      cache:
        time-to-live: 30s
```

**Two consequences.**

1. **D10's decisive argument is factually wrong.** It reads: *"**Zero staleness** — which is the decisive property for a control whose purpose is catching a bypass (requirements Edge Case 7 is answered by construction, not by a staleness budget)."* The shipped staleness is **up to 30 s plus the poll cadence**. The *decision* (live query, no materialisation, no cache of our own) is still correct — 30 s is immaterial for a control whose remediation is DBA-level — but the argument as written is an argument a future engineer could cite to **remove the TTL**, which is a shipped security control added by a prior security review for this exact indicator.
2. **The widened query makes that TTL more load-bearing, not less.** Today: one query over two tables. After FR-2: **two queries over four tables**, one of which joins `user_roles` — the largest RBAC table — across all tenants. On a `permitAll`, un-rate-limited endpoint. The 30 s TTL is what turns an anonymous amplification primitive into a bounded background cost, and the design neither mentions it nor protects it.

**Existing mitigation.** The TTL itself (shipped, effective), plus `show-details: when-authorized` (so an anonymous caller gets status only, not the count), plus — verified as a positive — the exclusion of this indicator from the liveness/readiness groups and the Dockerfile's use of `/actuator/health/liveness`, so a widened DOWN **cannot** take a container out of service.

**Required mitigation (RC-22).** Three sentences and one test, no design change:
1. Replace D10's "zero staleness" wording with the accurate claim: *no **application-maintained** staleness — the data is read live on every evaluation; the actuator's shipped 30 s response cache is the only staleness, it is deliberate, and it is a security control.*
2. Add a line to §8.2 and to `monitoring.md`: *`management.endpoint.health.cache.time-to-live` bounds an anonymous cost-amplification path (07-security-review M-2) and becomes more load-bearing under FR-2's two-query, four-table form. Do not remove or lengthen the poll cadence without re-running that analysis.*
3. Record the liveness/readiness exclusion as a **protected property** in the same place, so a future story does not add `rbacZeroActiveAdmins` to a probe group and convert D11's widened DOWN population into an outage. A cheap config-assertion test (the health groups contain only the state indicators) would make it mechanical.

**Residual after mitigation: Low, accepted** as **RES-21**.

---

### T-T14 — The detection control holds write capability over `user_roles` · **Low-Medium** · ⚠️ record or narrow

**Verified.** `RbacZeroActiveAdminsHealthIndicator` injects `JpaUserRoleRepository` **directly, not through a port** (`:38-42`), and that interface `extends JpaRepository<UserRole, UUID>` (`JpaUserRoleRepository.java:15`) — so the indicator holds `save`, `saveAll`, `delete`, `deleteById`, `deleteAll`, `deleteAllInBatch` over `user_roles`.

**Why it is worth a line.** This is US-016 **T-T13**'s exact shape — *"the design hands a component unrestricted write authority over precisely the rows its new logic reads"* — which was rated **Medium** there and fixed by RC-12. The mitigating difference here is real and should be claimed: `user_roles` has the `trg_user_roles_no_delete` trigger and a column-scoped `UPDATE (revoked_at)` grant, so a stray delete or a multi-column update is rejected **by the database**. But `INSERT` is granted, so a stray `save` from this component **would execute** — creating a role assignment from a health check.

**Why now.** The coupling is pre-existing (US-012), but **D12 re-affirms it in writing as a deliberate decision** and widens the component's responsibilities (two queries, four tables, a domain-set parameter). A decision that is re-affirmed is a decision that gets re-reviewed.

**Required mitigation (RC-22 part 4).** Cheapest first:
1. **Preferred:** declare a narrow read-only interface — `interface ZeroAdminTenantReader { List<UUID> findTenantsWithAnAdminEquivalentRole(…); List<UUID> findTenantsWithActiveAdminEquivalentHolders(…); }` — have `JpaUserRoleRepository` also extend it, and inject **only the reader** into the indicator. Zero query changes, zero behaviour change, and it removes the capability. This is US-016 RC-12's own fallback shape applied one component over.
2. **Fallback:** keep the injection and state explicitly in D12 and in the indicator's Javadoc that it holds write capability over `user_roles` and must never use it — so the property is stated where a future maintainer would otherwise remove it.

**Residual after mitigation (option 1): none. (Option 2): Low, accepted** as **RES-22**.

---

### T-I14 — `detachPermission`'s 404 → 403 narrowing · **Low** · ✅ verified: it removes an oracle and creates none

Because the brief asks specifically whether the 403-vs-404 split lets a caller probe attachment state, I enumerated the full response matrix for a caller holding `role:write` but **not** `role:read` and **not** `TENANT_ADMIN`, against a role in their own tenant:

| `permissionId` | Attached? | Today | After D13 | Leak? |
|---|---|---|---|---|
| unknown to the catalogue | — | 404 | 404 | unchanged |
| known, **dangerous** | **yes** | 204 (detach succeeds!) | **403** | — |
| known, **dangerous** | **no** | 404 | **403** | — |
| known, benign | yes | 204 | 204 | unchanged |
| known, benign | no | 404 | 404 | unchanged |

**The dangerous rows are now indistinguishable from each other**, so the attachment-existence oracle that exists **today** for dangerous permissions is *removed*. The design claims this and the claim is correct.

**The one thing the 403 does disclose** — "this permission id names a dangerous permission" — is a **global, fixed fact** about a 7-row `SELECT`-only catalogue, and it is already disclosed by the attach-side AC11 gate to the same caller with the same permission. `GET /api/v1/roles/{roleId}/permissions` requires `role:read` (verified, `RoleController.java:120-121`), so this caller genuinely cannot enumerate a role's permissions — but that is unchanged by D13.

**The materially more important property, which the design should claim and does not:** today a non-admin `role:write` holder can **successfully detach a dangerous permission** (row 2, `204`). D13 turns a successful privilege-affecting mutation into a 403. That is not a "behavioural narrowing"; it is the closure of the mutation path §7.5 depends on, and §12.2 item 4 undersells it by listing only the status-code change.

**Required.** None to the decision. One sentence in §12.2 item 4 and in the release notes: the break that matters is that a non-admin can no longer detach a dangerous permission **at all**, not that an unattached one now 403s.

**Residual: none.**

---

### T-E31 — The widened AC5 guard's reachability proof · **Low** · ✅ re-derived independently and it holds

I re-derived §6.3 rather than accepting it, because it is the premise D16 rests on.

1. To reach the lockout, the caller passed the gate ⇒ M5b returned true ⇒ the caller holds an active assignment of some role in `callerSet = fullyAdminEquivalentIds ∪ namedAdminRoleId`.
2. `callerSet ⊆ lockSet` (ALL ⊆ ANY, plus M8's id is in both) ⇒ that assignment row is in M11's locked result — **provided M11 and M5b see the same rows**, which they do: same table, same `tenantId`, same `revoked_at IS NULL`, and M5b's predicate is M11's restricted by `user_id`. Verified against the design's §4.6 query pair.
3. ⇒ the caller is an element of the distinct-holder set.
4. The guard fires iff removing the row `ref.id()` empties that set ⇒ the set was exactly `{caller}` **and** `ref` is one of the caller's own rows.
5. ⇒ `targetUserId == actor.userId()`. ∎

**The dependency, correctly stated by the design:** step 2's "same rows" requires that no admin-equivalent assignment can be *created* between M11 and M5b — guaranteed by M11's next-key/gap locking under `REPEATABLE READ`, and by nothing else. MC-6 asserts the isolation level and §7.5 states the snapshot ruling. Both are present. Good.

**A consequence worth stating that the design does not:** the guard is now *stronger* than a lockout check — the caller must be a member of the very set being protected, so no third party can ever drive a tenant to the boundary. Say so, for the same reason US-016 T-E24 required it: to stop a future reader concluding the guard is dead code and deleting it. §11.1's retention of the synthetic-state unit test is exactly right.

**Required.** One sentence in §6.3. No behaviour change.

**Residual: Low.**

---

### T-S8 — Caller admin status on the new predicate · **Low** · ✅ closed

The attack (a caller whose qualifying assignment was revoked out of band but who holds an unexpired JWT) is US-012 T-E7, closed on the new path by construction: the gate's only determination is **M5b**, a fresh locking `FOR SHARE` read on the caller's own rows, and `RoleChangeActor` carries no role or permission data, so there is nothing stale to read. The port Javadoc reproduces M5's non-negotiable contract verbatim. §11.3 mandates extending `RoleAssignmentSecurityIT`'s out-of-band-revocation IT to the new predicate — the right proof at the right level.

**Two notes for `/breakdown`, neither a finding:**
- The design now has **three** similarly-named caller helpers: M5b (the gate, locking), `callerHoldsActiveAdminEquivalentRole` (the canary, non-locking), and `callerHoldsActiveTenantAdmin` (`listActive`'s redaction, non-locking). MC-G is the control and it must assert the negative on **both** verbs, not at class level — `listActive` legitimately calls the third one.
- The freshness IT must exercise revocation of the **ALL-three custom role**, not only of `TENANT_ADMIN`; revoking the literal role would leave the new predicate untested.

**Required.** None.

---

### T-T15 — Two divergent implementations of one predicate (Java vs. SQL) · **Low** · ⚠️ pin it

D12 is, in my judgement, **the right call**: the indicator injects the repository directly, does not go through the port, and already passes `RbacRoleNames.TENANT_ADMIN` this way — so D3's port-binding rule genuinely does not apply to it, and the names still originate in `rbac.domain`. Forcing the indicator through the port to satisfy a rule about the port would be cargo-culting.

**The residual risk the brief asks about is real but narrower than "a second definition of admin-equivalent".** What crosses into SQL is the **set** (`RbacDangerousPermissions.NAMES`), which propagates automatically — add a fourth dangerous permission and both sides update. What does **not** propagate is the **combinator**: `isAdminEquivalent`'s `name OR ANY` is written twice, once in Java and once as `r.name = :n OR EXISTS(… p.name IN :names)`. A future change to the combinator (ANY → something, or "and the role is not a system role") updates one side and not the other, with **no test that would notice** — and the two controls would then protect and detect different populations, which is precisely the FR-7 violation the story was written to prevent.

Two smaller divergences, both currently unreachable, both worth one sentence: Java uses `equalsIgnoreCase` while `utf8mb4_0900_ai_ci` is **accent**-insensitive as well; and the SQL half sees only roles with at least one attached permission plus the name match, which matches the Java half's behaviour exactly *because* D9 routes the name half through M8 — a correspondence that is currently incidental rather than asserted.

**Required mitigation (RC-18 part 2) — MC-I.** One integration test, over a fixture matrix of roles in one tenant (zero permissions; one dangerous; two dangerous; all three; only benign; the literal `TENANT_ADMIN` with no permissions; a case-variant permission name), asserting that **the set of tenants the indicator reports** equals **the set of tenants for which no role passes `RbacAdminEquivalence.isAdminEquivalent` with an active holder**, computed in Java from the same fixture. That is a direct, cheap equivalence proof between the two implementations, and it fails the moment the combinator drifts.

**Residual after mitigation: Low, accepted** as **RES-23**.

---

### T-R11 — FR-3's loosening is measured without a subject · **Low** · ⚠️ add the dimension to the log

`nexus.rbac.privileged_role_change_allowed{operation, callerMatchedOn}` is, as D15 correctly says, *"the only signal that shows FR-3's loosening actually being exercised"* and the basis for Success Metric 5. Its four series are correctly bounded. But it carries **no tenant and no actor dimension**, and the design's stated operator action is *"a step change in it is worth a ticket"* — a ticket whose first investigative step has nowhere to go.

Metrics are the wrong place for ids and the design is right to keep them out. **Logs are the right place**, and this is the one signal that has no log companion: the gate's *denial* path emits a rich WARN, and its *pass* path emits only a counter.

**Required (folded into RC-16 part 3).** On the gate's pass point, when `callerMatchedOn == ALL_DANGEROUS_PERMISSIONS` (i.e. only for the newly-admitted population, not for every admin action), emit an INFO/WARN carrying `{tenantId, actorUserId, targetUserId, roleId, roleName, operation}`. That makes T-E28's promotion signal and Success Metric 5 both actionable, at the cost of one log line on a rare path.

**Residual: Low, accepted.**

---

### T-I15 / T-I16 / T-R12 — three Low items recorded for completeness

- **T-I15 — the health count's meaning widens.** Any authenticated principal of any tenant can read `affectedTenantCount` (`show-details: when-authorized`, `/actuator/health/**` `permitAll`). FR-6's count-only discipline is preserved and correct, but the count now aggregates a larger population, so a `MEMBER` of one tenant learns slightly more about the platform's overall state. Unchanged in kind; no tenant is identified. **Accepted as RES-20, Low.**
- **T-I16 — M11 carries no user-tenant check.** A row whose `user_id` belongs to another tenant but whose `tenant_id` and `role_id` are correct would be counted as a holder, potentially permitting a zeroing. Unreachable through the application (`verifySameTenant` precedes every insert, verified at `RoleAssignmentService.java:148`) and unchanged from shipped M1; the inverse case (a drifted `user_roles.tenant_id`) fails **safe**. **Recorded, not fixed.** Adding a `users` join would widen the lock and is the wrong trade.
- **T-R12 — the new detach denial writes no durable audit row.** Consistent with attach, which writes none either (§9.1 is explicit about this), and the WARN carries every field. Inherits T-R10's retention condition; no separate action.

---

## 4. Verdict on each of the design's claimed-closed items and each §13 stakeholder flag

Requested explicitly by the brief; each is CONFIRMED, CONFIRMED-WITH-CONDITIONS, or DISPUTED, with the finding that carries the disagreement.

| # | Design claim | Verdict | Basis |
|---|---|---|---|
| **1** | **D2** — the caller-side predicate is ALL-three and a symmetric ANY test would be vacuous | **CONFIRMED** | Vacuity proof re-verified from `RbacDangerousPermissions.java:13` and the controllers' `@RequiresPermission`. I attacked the predicate directly (**T-E30**): no ALL-three role can exist without three AC11-gated attaches by a literal `TENANT_ADMIN`, and `RbacRoleNames.RESERVED` blocks the name half. The ALL-three test does **not** miss a case that matters — the case it misses (`role:write`+`user:write`, no `tenant:write`) fails **closed**, which is RES-12 and is correctly accepted. **One implementation trap must be pinned** — RC-18.1 |
| **2** | **D5** — distinct holders, not rows, excluding `ref.id()` | **CONFIRMED** | The row-vs-holder defect is real in shipped code (`RoleAssignmentService.java:328`), the corrected predicate covers Edge Cases 1–3 structurally, and MC-D pins it. The set arithmetic in the service (rather than `SELECT DISTINCT … FOR UPDATE`) is the right call for the stated reasons |
| **3** | **D6** — one statement, one lock, ascending IN-list | **CONFIRMED as a decision; the ordering contract is under-specified** | A single statement beats a loop, and "a total order does not require identical sets" is correct and is the subtle step. But "ascending" is not defined against the database's collation of `BINARY(16)`, and the guarantee actually rests on plan stability across IN-list cardinalities, which MC-C does not assert — **T-D15 parts 3, RC-20.7** |
| **4** | **D7** — RES-10 is **closed**, not re-accepted, by a total acquisition order across both verbs | **CONFIRMED as the right decision · the proof is one index short, and the cost paragraph is factually wrong** | Making the order total is the only fix that eliminates the cycle at the root, and §7.3's demonstration that harness C's own fixture reproduces the widened cycle is convincing. Two gaps: the order is proved over `fk_user_roles_role` while `uq_user_role_active` / `fk_user_roles_user` / the clustered index are covered only for privileged × privileged pairs, and harness C has **no benign thread** to test the remainder (**T-D15**); and "only privileged principals reach it" is false — M11 is acquired before the gate on both verbs (**T-D13**). **Neither overturns D7.** The empirical exit gate is the right instrument and the refusal to pre-approve a retry policy is correct |
| **5** | **D8** — the caller read is contained in the X region, so ADR-0017 D4's proof is extended not replaced | **CONFIRMED** | ALL ⊆ ANY ⊆ lock set is exactly right, and it makes the containment property *free* rather than argued. The `FORCE INDEX` retention and MC-C's re-derivation are the correct mechanical backing. This is the change that makes the widened design safer than the shipped one |
| **6** | **D9** — fail closed on empty; propagate (500) on throw | **CONFIRMED** | Empty caller set ⇒ deny **without a read** follows the R-10/T-E18 precedent exactly. A throwing M10 rolls the transaction back before any write on both verbs, so 500 is genuinely fail-closed. The observation that the lock set always contains M8's id and the target role id — so FR-4's name path never depends on M10 — is a good property and correctly claimed. **What is missing is the over-broad direction** — **T-E29** |
| **7** | **D10/D11** — live query, no cache, no materialisation; drive off tenants that have an admin-equivalent role | **CONFIRMED as decisions · one stated argument is false** | Rejecting the materialised flag is right (a new table, an unmanaged `GRANT`, a write on four paths, and a security control reading a stale flag). D11's invisible-tenant choice is right and correctly recorded as RES-14. **"Zero staleness" is false** — a 30 s actuator cache TTL is shipped, was added by a prior security review for this exact indicator, and becomes more load-bearing under the widened query (**T-D16**) |
| **8** | **D12** — the indicator may pass the name set because it does not go through the port | **CONFIRMED as legal and correct · the divergence risk is narrower than feared but real** | D3 binds the port; the indicator injects the repository directly and already passes the role name this way. The *set* propagates automatically; the **combinator** does not, and nothing would notice the drift (**T-T15**, RC-18.2 adds MC-I). Separately, the direct injection hands the detection control write capability over `user_roles` (**T-T14**) |
| **9** | **D13** — symmetric detach gate, keyed on the detached permission, 404 → 403 | **CONFIRMED, and under-claimed** | The gate closes the only runtime path that can flip a role out of admin-equivalence. The full response matrix (**T-I14**) confirms the 403 **removes** an attachment-existence oracle and creates none; "this id is dangerous" is global and already disclosed by the attach gate. §12.2 item 4 should say that the break that matters is that a non-admin can no longer detach a dangerous permission **at all** |
| **10** | **D14** — the canary is re-derived without collapsing the two mechanisms | **CONFIRMED on the mechanism · DISPUTED on the residual's rating and scope** | Keeping a second, independent mechanism, keeping the PromQL byte-identical, and mandating an acceptance IT is exactly right, and the design deserves credit for catching a detection regression it would otherwise have caused. But RES-18 rates the shared input **Low** and scopes it to the canary; the same input also drives the gate and the lockout, and an over-broad result fails **open** on both (**T-E29**). RC-17 gives the canary an independent derivation |
| **11** | **D16** — no durable audit row on a lockout block | **CONFIRMED as a decision · CONDITIONAL on a retention mandate** | I concur that `ROLE_ASSIGNMENT_DENIED` must not be widened, and §6.3's proof (re-derived, **T-E31**) supports the "authorized actor made a mistake" framing for the ordinary case. **Dissent:** the compensating control inherits US-015 RES-10's and US-016 RES-6's unresolved retention question, and a compromised sole-admin account repeatedly attempting to destroy the tenant's last admin access leaves **only** a WARN — **T-R10 / RC-19** |
| **12** | **D18 / RES-13** — the mint-side asymmetry is relocated, and the narrower mint side is "the safe direction" | **DISPUTED as a containment · CONFIRMED as a direction** | A fully admin-equivalent caller self-assigns literal `TENANT_ADMIN` in one request (newly permitted by FR-3) and is then a mint-side administrator. Not an escalation — but RES-13 as written reads as a control, and the promotion produces **no distinguishable signal** (**T-E28 / RC-16**) |
| **13** | **D19/D20** — no new flag; merge behind existing flags, soak, pre-deploy DBA sweep | **CONFIRMED on the flag · PARTIALLY CONFIRMED on the rollout** | D19's reasoning is the best in the document: FR-3's "off" position is *incoherent*, not safe, and a percentage rollout of an authorization gate is strictly worse than either state. §10.3's step-2 exit criteria are unusually good (canary acceptance test run deliberately, ≥5 harness-C runs, baselines captured). **Step 3's sweep is detection without forensics** — **RC-21** |
| **14** | **D21** — Gap 7 (AC8 self-assignment precedence) is discharged; there is no precedence to resolve | **CONFIRMED** | One actor-agnostic gate; self-assignment is gated identically to third-party assignment; the only self-specific behaviour is the post-commit canary counter. Verified against the shipped flow. **One consequence D21 does not draw** and T-E28 does: the most sensitive *self*-assignment FR-3 newly permits is the one to literal `TENANT_ADMIN` |
| **15** | **§13 item 1 — Compliance sign-off on D16** | **CONCUR WITH CONDITIONS** — see T-R10/RC-19. Send to Compliance with the retention mandate attached, not as drafted |
| **16** | **§13 item 2 — Security sign-off on D18/RES-13** | **CONCUR ON THE DIRECTION, DISSENT ON THE FRAMING** — see T-E28/RC-16. The asymmetry is acceptable; its description as a safety property is not |
| **17** | **§13 item 3 — PM/Security on D7's scope and contention** | **CONCUR** — see T-D13/T-D15. The serialisation cost is the right trade and the alternative is worse; the reachability statement and the per-index proof must be corrected, and harness C needs a benign thread |

---

## 5. Residual risk register

Continues `03-design.md` §12.3's numbering. Ratings are mine and override the design's where they differ. Owners and review dates mirror the treatment RES-1(b), RES-3 and RES-9 received in US-016.

| # | Residual | Severity (design → mine) | Why accepted | Compensating control | Owner / review |
|---|---|---|---|---|---|
| **RES-1(b)** *(inherited from US-016, **amplified by this story**)* | **Standing pre-positioning primitive.** Any `user:write` holder may self-assign a benign custom role and be silently escalated when an administrator later attaches dangerous permissions to it. **US-017 raises the payoff from "admin-equivalent permissions, effective at the next mint" to "caller-side administrator, effective on the next request, and literal `TENANT_ADMIN` one self-assignment later"** (T-E27) | High → **High (impact increased, likelihood unchanged)** | Gate 1 decided against backfill, not against forward detection. US-017 does not create the primitive but materially increases what it is worth | US-016 D13's shipped holder-count signal on `attachPermission` (verified in code) **+ RC-15.3**: a distinct WARN + counter when an attach makes a role **fully** admin-equivalent, paged when `holderCount > 0`. If RC-15.3 does not ship, a named successor story id before merge | **Md Nisar Ahmed (accountable, inherited from US-015 §4.5 → US-016 RES-1).** Review **2026-11-27**; **hard expiry Epic 3 kickoff** — inherited unchanged |
| **RES-12** | The caller-side predicate is narrower than "admin-equivalent" (`role:write`+`user:write`, no `tenant:write` ⇒ cannot administer) | Low → **Low (unchanged)** | Fails **closed**. Verified in T-E30 part 2. The remedy (an explicit marker column) is a migration and its own decision | `privileged_role_change_blocked{matchedOn}` and the new `privileged_role_change_allowed` show both populations | Architect; Security accepted |
| **RES-13** | **The mint-side asymmetry is relocated, not eliminated** — and it is **not a containment**: reachable in one self-assignment (T-E28) | Low-Med → **Medium** | Definitionally correct (an ALL-three holder *is* an administrator), so not an escalation. Re-rated because the register currently describes it as a safety property | **RC-16**: re-word RES-13 and §7.5 Change 1; add `RBAC_ADMIN_MINTED_BY_NON_NAMED_ADMIN` WARN + alert | Architect (wording) + Security (§13 item 2 sign-off, on the corrected text) |
| **RES-14** | A tenant with **no** admin-equivalent role stays invisible to FR-2 | Low → **Low (unchanged)** | Correct: a provisioning defect, not a lockout; reporting it would page during every tenant bootstrap | Recorded as an explicit decision (D11) rather than an accident of query syntax | Architect; SRE informed |
| **RES-15** | `listActive`'s `assignedBy` redaction stays literal-name-based, so a fully admin-equivalent caller may revoke a role but not see who granted it | Low → **Low (unchanged)** | A disclosure decision (O-10/T-I5) whose population was never analysed for this predicate. Fails toward **less** disclosure | MC-G keeps the redaction helper out of every authorization path | Architect; Epic 3 |
| **RES-16** | Admin-equivalence is evaluated against the transaction's snapshot; a role that *becomes* admin-equivalent mid-flight is unprotected by that transaction | Low → **Low (unchanged)** | Correct ruling. The attach requires an administrator; a locking read on `permissions` is impossible in production (MC-A); the detective control is the backstop on the next poll | FR-1 and FR-2 shipping together is the mitigation, and the design says so | Architect |
| **RES-17** | **M11's locked/materialised set is unbounded**, **and is reachable from the denial path** by any `user:write` holder (T-D14) | Low → **Medium** | The rows must be locked for correctness; no alternative exists under this schema. Re-rated for reachability and for the composition with RES-1(b), which is what makes the set large | `admin_equivalent_lock_set_size` **+ RC-20.4**: a soak-derived p99 threshold, a ticket alert, a runbook action, and a cross-reference to RES-1(b) | Architect + SRE. Threshold captured at §10.3 step 2; review at first production GA |
| **RES-18** | **The canary and the gate share one input (M10)** — restated: an over-broad M10 fails **open** on the caller gate **and** on the lockout, **and** silences the canary (T-E29) | Low → **Medium** | The shared input is a real loss of the property `07-security-review.md` M-2 bought; unit tests are not a substitute for a runtime canary | **RC-17**: independent SQL derivation for the canary (preferred) or a runtime disagreement check (fallback); **MC-H** M10 ↔ M7 equivalence IT | Security (owns the canary) + Architect. Review at Phase 7 code audit |
| **RES-19** *(new)* | **Lock-hold and blast-radius amplification on the denial path, both verbs** (T-D13) — a tenant-wide X lock over N role ranges, acquired before the authorization decision, held across M5b and a `REQUIRES_NEW` audit write on a second connection, by a caller who will be denied | — → **Medium** | Reordering is not available: M11 must precede M5b or D8's containment proof collapses. The bound is D14's throttle, which is real and shipped | **RC-20.1–3**: correct D7's reachability statement; name D14 as the bound including its per-replica caveat (US-016 RES-11(c)); make `{operation="assign", outcome="denied"}` a first-class timer series with a runbook entry | Architect + Ops (multi-replica `store-type=redis` guidance is a deployment prerequisite, not advice) |
| **RES-20** *(new)* | **The health count's population widens** — any authenticated principal of any tenant reads a platform-wide count of tenants with zero admin-equivalent holders (T-I15) | — → **Low** | Inherent to leaving the indicator on the aggregate endpoint; no tenant is identified, and FR-6's count-only discipline is preserved unchanged | `show-details: when-authorized`; ids remain in the WARN only; `RbacZeroActiveAdminsHealthIndicatorTest`'s disclosure assertions are the standing proof | Security; accepted |
| **RES-21** *(new)* | **The widened health query's cost is bounded by a config value the design does not mention** (T-D16) — `management.endpoint.health.cache.time-to-live: 30s`, on a `permitAll` endpoint, now fronting two queries over four tables | — → **Low** | The TTL is shipped and effective; 30 s of staleness is immaterial for a control whose remediation is DBA-level | **RC-22.1–3**: correct D10's "zero staleness"; record the TTL as a security control in `monitoring.md`; record the liveness/readiness exclusion as a protected property, ideally with a config assertion | Architect + SRE |
| **RES-22** *(new, avoidable)* | **The detection control holds write capability over `user_roles`** (T-T14) — a full `JpaRepository` injected directly into the health indicator | — → **Low-Medium** | Pre-existing, and partly backstopped by the DB (no-DELETE trigger, column-scoped UPDATE) — but `INSERT` is granted, so a stray `save` executes. D12 re-affirms the coupling in writing | **RC-22.4**: inject a narrow read-only interface (preferred — removes the residual entirely), or state the property in D12 and the indicator's Javadoc | Architect |
| **RES-23** *(new)* | **Two implementations of one predicate** (T-T15) — the ANY combinator exists in Java and in SQL; the *set* propagates, the *combinator* does not | — → **Low** | D12's asymmetry is legally and architecturally correct; the residual is drift, not layering | **RC-18.2 / MC-I**: an equivalence IT asserting the indicator's reported population equals the Java predicate's classification over a fixture matrix | Architect; Security accepted |
| **RES-11** *(inherited from US-016)* | Denial-throttle side effects: benign-role collateral (a), attacker-ordered suppression blind spot (b), per-replica bound (c) | Low → **Low (unchanged), but now load-bearing** | Unchanged in mechanism. Elevated in *importance*: after D7 the throttle is the only bound on RES-19, so (c)'s per-replica caveat becomes a deployment prerequisite rather than guidance | `nexus_rbac_denial_throttle_engaged` at page severity; runbook §3's `store-type=redis` instruction — **must be cited from D7** (RC-20.1) | Security (alerting) + Architect/Ops |
| **RES-6** *(inherited from US-016)* | Denial-record discriminability and the unresolved **log-retention** question | Med → **Medium (unchanged, and now also covers the lockout WARN)** | Resolving it requires an Ops decision this story cannot make alone | **RC-19**: name the retention figure in writing for all three WARN markers, per US-015 RES-10's resolution | Architect + **Ops** (retention is not an Architect-only decision) |
| **RES-10** *(inherited from US-016)* | Pre-existing `assign` × `revoke` lock cycle | Low (inherited) → **CLOSED by D7, conditionally** | Closed at the root by the total acquisition order — **conditional on** the empirical exit gate. If reshaped harness C is not green over ≥5 runs, this entry reverts to an open, **widened** High and the story returns to Gate 2, exactly as §12.3 states | Harness C with the `assign(TENANT_ADMIN)` thread restored **+ RC-20.6's benign thread**; MC-C, MC-E, MC-6 | Architect. **Closure evidence is a merge checklist item** |
| **RES-24** *(new, found at Phase 7 code audit, `06-code-review.md` H-1, 2026-09-24 — not caught at Gate 2)* | **D5's lockout guard and D10–D12's health indicator both checked the ANY-admin-equivalent population, not the caller-qualifying (D2) population.** A tenant could retain an ANY-only holder (one dangerous permission, e.g. `tenant:write` alone) while losing its last caller-qualifying holder — after which no one in the tenant could ever pass the caller gate again, while both the lockout guard and the health indicator kept reporting healthy. This is exactly the "tenant locked out of administration" outcome FR-1/FR-2 exist to prevent, reached through the gap between the two admin-equivalence predicates this story itself introduces (D1/D2) | — → **High (found and fixed same-day, before merge)** | **CLOSED, not merely mitigated.** `ActiveAssignmentHolder` gained a `roleId` field; the lockout guard's distinct-holder check and both `ZeroAdminTenantReader` queries were re-scoped from `isAdminEquivalent`/`carriesAny` to `isFullyAdminEquivalent`/`carriesAll` — the same predicate D2's caller gate already uses. M11's lock set itself is unchanged (still the broader ANY population, for deadlock-freedom) — only the in-Java/in-SQL population each control counts against was narrowed | New regression tests at both layers: `AdminEquivalentLockoutIT#should_blockSelfRevoke_when_onlyRemainingHolderIsAnyQualifyingButNotCallerQualifying_H1` and `RbacZeroActiveAdminsHealthIndicatorIT#should_report_down_when_theOnlyCallerQualifyingRoleIsAnAnyOnlyHolderAndTheNamedAdminIsZeroed_H1`, plus the re-scoped `AdminEquivalenceSqlJavaEquivalenceIT` (MC-I) fixture matrix | Md Nisar Ahmed. Closed same-day; no review-date carry-forward needed |
| **RES-25** *(new, found at Phase 7 code audit, `07-security-review.md` M-1, 2026-09-24 — not caught at Gate 2)* | **The re-derived gate-bypass canary (D14/D24) read the caller's M4/M12 state AFTER the assign() INSERT committed, not before.** On a self-assignment where the target role is itself fully admin-equivalent (literal `TENANT_ADMIN` or ALL-three), the post-commit read sees the row the request just created, making `callerIsAdmin="false"` structurally unreachable for exactly that population — the one the canary most needs to catch a bypass for. This shape already existed on `main` pre-US-017 (US-016's name-only `callerHoldsActiveTenantAdmin`, also post-commit); US-017 widened its blast radius to every ALL-three target | — → **Medium (found and fixed same-day, before merge)** | **CLOSED.** The M4/M12 read now runs before the INSERT, captured into `callerWasAdminBeforeThisAssignment` and carried into the post-commit runnable — correctly reflecting the caller's pre-request state. MC-G unaffected (the read still never authorizes anything) | `RoleAssignmentServiceTest#should_readCanaryStateBeforeTheInsert_notAfter_when_selfAssigningATenantAdminRole_M1` — an `InOrder` proof that the read happens before the INSERT, with a realistic "caller held nothing before" stub correctly producing `callerIsAdmin=false` | Md Nisar Ahmed. Closed same-day; no review-date carry-forward needed |

---

## 6. Cross-references to prior threat models

| Prior threat | Status after US-017 |
|---|---|
| **RES-3** (US-016) — lockout and health indicator cover only the literal `TENANT_ADMIN` | **Closed end to end**, by FR-1 (preventive, tenant-wide, distinct-holder) and FR-2 (detective, same population). The two halves are the same predicate by construction (D1), which is what FR-7 asked for |
| **RES-9 / T-E26** (US-016) — admin-equivalent custom-role holders are gated but can never pass the gate | **Closed for `assign()`/`revoke()`**, with a deliberately narrower predicate. **Not closed on the mint side** — carried as RES-13, whose framing must be corrected (T-E28) |
| **RES-10 / T-D12** (US-016) — pre-existing `assign` × `revoke` cycle | **Closed by D7**, conditional on harness C's restored thread. The design was right that inheriting it was not available |
| **RES-1(b) / T-E21** (US-016) — attach-after-assign pre-positioning | **Not closed, and materially amplified** (T-E27). The owner, review date and Epic-3 hard expiry carry forward unchanged |
| **T-E16 / T-E17** (US-015) — propagate-side and revoke-side escalation | **Still closed.** The four 403 tripwires are named as a hard non-regression contract (§5.2) and MC-B backs them. **This is the single most important thing not to break in implementation** |
| **T-E7** (US-012) — admin status must be a live locking read, never a JWT claim | **Preserved on the new predicate** (T-S8). M5b inherits M5's contract verbatim; the freshness IT is extended |
| **T-E14** (US-015) — the non-locking-read trap on an admin gate | **Correctly distinguished again.** M10 is non-locking *because it must be* (`permissions` is `SELECT`-only) and §7.5 rules on the consequence rather than waving at it |
| **T-E18 / R-10** (US-015) — fail closed on an empty lookup | **Precedent followed exactly.** Empty caller-candidate set ⇒ deny **without a read** (D9) |
| **T-E23** (US-016) — a lock proof stated at the wrong granularity | **Recurs, one level up** (T-D15). US-016's proof was short on index-record granularity; US-017's is short on which indexes the claim covers. Worth noticing that this is now a pattern on this code path |
| **T-D10 / T-D11 / RES-4+RES-5** (US-016) — unthrottled denial amplification and lock-hold on the denial path | **Widened to a second verb and N role ranges** (T-D13/RES-19). The D14 throttle built in response to US-016 is what keeps this bounded — and D7 must say so |
| **T-T13 / RC-12** (US-016) — an adapter gaining write capability over the table its gate reads | **Applied correctly to the adapter** (D3/D4: zero new constructor dependencies) **and missed one component over** — the health indicator holds a full `JpaRepository` over `user_roles` (T-T14) |
| **T-R8 / RES-6** (US-016), **T-R7 / RES-10** (US-015) — the log-retention question | **Re-encountered a third time** (T-R10). The epic has now twice resolved this shape by naming a retention figure; D16 must do the same |
| **T-I10 / RES-8** (US-016) — target-role privilege oracle | **Unchanged, and now more useful to an attacker**: it is the polling mechanism by which a pre-positioned attacker detects that role R has become dangerous (T-E27) |
| **T-I5** (US-012) — `assignedBy` redaction | **Untouched** (D17/RES-15), and MC-G keeps the three similarly-named helpers from being confused |
| **T-T12** (US-016) — reserved-name squat / collation bypass | **Still closed**, re-verified: `RbacRoleNames.RESERVED` plus `uq_roles_tenant_name` under `utf8mb4_0900_ai_ci` |
| **T-D4 / M-1** (US-012 / 07-security-review) — health-indicator disclosure and the anonymous amplification TTL | **FR-6 preserved; the TTL is now more load-bearing and unmentioned** (T-D16) |
| **T-I8** (US-015) — ~30-min permission staleness | **Direction reversed.** For permission-side escalation it was a detection window; FR-3's caller gate is a live read, so the new capability is effective immediately. Feeds T-E27 |

---

## 7. Threats requiring design changes

**These must go back to the Architect before Gate 2 can close.** Each becomes one `/breakdown` task unless noted. **RC-15.3, RC-16.2 and RC-20 require decisions rather than edits — flag those first.**

### RC-15 — Record and mitigate FR-3's amplification of RES-1(b) *(T-E27, **High**)* — **the most important change in this list**

1. Record **T-E21 / RES-1(b)** in `03-design.md` §12.3 and in ADR-0018's "what this ADR does not close", as **amplified by this story**, carrying the inherited owner, the 2026-11-27 review and the Epic-3 hard expiry. Do not open a competing entry.
2. Correct §4.2's Javadoc replacement text so the method's own documentation states that the attach-after-assign path now confers **caller-side** administrative capability.
3. **Architect decision:** ship the threshold-crossing signal in US-017, or name a successor story with an id before US-017 merges. The signal: at `attachPermission`, on the dangerous path only, after the attach, one bounded M7 read; when `isFullyAdminEquivalent` becomes true emit `RBAC_ROLE_BECAME_FULLY_ADMIN_EQUIVALENT` `{tenantId, roleId, roleName, holderCount, grantedBy}` plus `nexus.rbac.role_became_fully_admin_equivalent{holders}`; ticket severity, **page** when `holderCount > 0`. One query on a rare admin-only path, no schema change, no new port method — the same shape and justification as US-016 RC-8.3, which was accepted and shipped.

### RC-16 — Correct RES-13's framing and give the promotion a signal *(T-E28 / T-R11, Medium)*

1. Re-word RES-13, ADR-0018's follow-on note, and §7.5's "Change 1" sentence: the mint side is narrower by construction but is reachable in one self-assignment, so it bounds nothing.
2. **Architect decision (small):** emit `RBAC_ADMIN_MINTED_BY_NON_NAMED_ADMIN` at the gate's pass point when `callerMatchedOn == ALL_DANGEROUS_PERMISSIONS` and the target role is the literal `TENANT_ADMIN`; ticket, **page** on self-target. Zero new queries.
3. Give `privileged_role_change_allowed` a log companion carrying `{tenantId, actorUserId, targetUserId, roleId, roleName, operation}` for the `ALL_DANGEROUS_PERMISSIONS` population only.

### RC-17 — Break the gate/canary shared input and bound M10 *(T-E29 / RES-18, Medium)*

1. Re-derive the canary from an **independent** SQL answer to "does this user hold an active assignment of a role carrying all three of these permissions, in this tenant?" (non-locking, driven off `fk_user_roles_user`, `HAVING COUNT(DISTINCT p.name) = 3`). Fallback if refused: a runtime M10-vs-M7 disagreement warning, recorded as strictly weaker.
2. Add **MC-H** — an integration test asserting that the role partition computed from one M10 call equals the partition computed by calling the shipped M7 per role, over a fixture matrix.
3. Re-rate RES-18 Low → Medium and restate it over all three consumers (gate, lockout, canary), not the canary alone.

### RC-18 — Pin both predicate implementations *(T-E30 part 3 / T-T15, Low-Medium)*

1. Specify `carriesAll` as a per-name case-insensitive `anyMatch` — **never** a count, **never** `containsAll`. Extend **MC-B** with the duplicate, mixed-case and null/empty assertions in §3 (T-E30).
2. Add **MC-I** — an equivalence test between the health indicator's SQL predicate and `RbacAdminEquivalence.isAdminEquivalent`, over a fixture matrix including a zero-permission role, a case-variant name, and the literal `TENANT_ADMIN`.

### RC-19 — Resolve D16's retention precondition *(T-R10, Medium)*

1. Mandate in writing, with the **figure named**, that `RBAC_LAST_ADMIN_REVOCATION_BLOCKED`, `RBAC_PRIVILEGED_ROLE_CHANGE_BLOCKED` and `RBAC_DANGEROUS_PERMISSION_DETACH_BLOCKED` are retained at least as long as `auth_events`. This is US-015 RES-10's own resolution, applied for the third time on this code path.
2. Add a ticket alert on `nexus.rbac.last_admin_lockout_blocked` firing repeatedly for the same tenant in a window.
3. Send §13 item 1 to Compliance with the corrected posture attached, not as drafted.

### RC-20 — Complete D7's proof, correct its reachability claim, and give harness C a benign thread *(T-D13 / T-D14 / T-D15, Medium)* — **Architect decision territory**

1. Correct D7's cost paragraph: M11 is acquired **before** the authorization decision on both verbs, so any `user:write` holder can force it; the bound is D14's denial throttle; cite US-016 RES-11(c)'s per-replica caveat and the `store-type=redis` runbook instruction as a **deployment prerequisite** for this design.
2. Make `privileged_revoke_lock_hold{operation="assign", outcome="denied"}` a first-class series with a runbook entry.
3. Record the composed amplification as **RES-19** (Medium) rather than leaving it inferable.
4. Give `admin_equivalent_lock_set_size` a soak-derived p99 threshold, a ticket alert and a runbook action; cross-reference RES-17 ↔ RES-1(b) in both directions; re-rate RES-17 Low → Medium.
5. Restate D7's rule **per index**: totally ordered with respect to `fk_user_roles_role`; serialised by the M11 conflict for privileged × privileged in `uq_user_role_active` / `fk_user_roles_user` / the clustered index; unchanged-in-kind for privileged × benign.
6. **Add a benign `assign`/`revoke` thread to harness C**, against the same users the privileged threads touch. Without it the harness proves only the case D7's mutual-exclusion argument already covers.
7. Define "ascending" in M11's port Javadoc as **unsigned byte-wise order of the 16-byte representation** (not `UUID.compareTo`); have MC-E assert that comparator; extend **MC-C** to assert the plan for IN-lists of size 1, 2 and ≥ 20.

### RC-21 — Make the pre-deploy sweep a forensic step, not just a detection step *(D20 step 3 / requirements Gap 2, Medium)*

The sweep as specified produces a list and stops. Four additions, all runbook-level:

1. **Attribution.** For each affected tenant, a point-in-time query against `auth_events` `ROLE_REVOKED` / `ROLE_ASSIGNED` history identifying **who** performed the revocations that took the tenant to zero and **when**. This matters because the population may not be innocent: before US-016 merged, `revoke()` had **no admin gate at all**, so a historical zeroing could have been performed by any `user:write` holder. US-016 RC-13 established exactly this discipline (a current-admin-set comparison produces false negatives on the escalation case); apply it here rather than re-deriving a weaker answer.
2. **Executable SQL, not a port method.** State the query as DBA SQL in the runbook, per US-015 RC-6 — an operator cannot invoke a Java port method. The design already says "raw SQL"; make it explicit that this is the reason.
3. **Scope and evidence.** Run the sweep in **every environment where either flag has ever been `true`** (dev, test, staging), not production alone — production's flags are `false`, so the population most likely to exist is in the lower environments. Retain the output as evidence with a date, since the widened indicator will immediately begin reporting the same population and the "before" list is the only way to distinguish pre-existing from new.
4. **A stated action on a non-empty result.** Today step 3's exit criterion is only "the affected list is known". Add: each affected tenant either has a remediation ticket with a DBA owner, or an explicit written acceptance, **before** step 5 — otherwise the first production DOWN is an unowned page for a condition the team already knew about, which is the fastest way to train operators to ignore this indicator.

### RC-22 — Health-indicator corrections *(T-D16 / T-T14, Low-Medium)*

1. Replace D10's "zero staleness" with the accurate claim (no application-maintained staleness; the shipped 30 s actuator cache is the only staleness and it is a security control).
2. Record `management.endpoint.health.cache.time-to-live` in §8.2 and `monitoring.md` as bounding an anonymous cost-amplification path (07-security-review M-2), and note that FR-2's two-query, four-table form makes it more load-bearing.
3. Record the liveness/readiness group exclusion as a **protected property**, ideally with a config assertion test.
4. Inject a narrow read-only interface into the indicator instead of `JpaUserRoleRepository` (preferred — removes RES-22 entirely), or state the write capability explicitly in D12 and the indicator's Javadoc.

### Editorial corrections (not tasks; fold into `03-design.md` at Gate 2)

- **§12.2 item 4 / release notes:** the break that matters on `detachPermission` is that a non-admin can no longer detach a dangerous permission **at all** (today: 204). The 404 → 403 ordering change is the footnote, not the headline.
- **§6.3:** add that the guard is now *stronger* than a lockout check — the caller must be a member of the set being protected, so no third party can drive a tenant to the boundary — so a future reader does not mistake it for dead code (T-E31; same reasoning as US-016 T-E24).
- **§7.5 "Change 1":** the population that can flip a role out of admin-equivalence is "an active literal `TENANT_ADMIN`, **or** anyone who can become one in a single request" (T-E28).
- **§4.3 (M5b Javadoc):** carry M5's shipped warning that the adapter must inspect only `.isEmpty()`/`.size()` and must never mutate the returned entities.
- **§0 / §12.1:** note that `npm audit` reports 27 pre-existing frontend toolchain findings unrelated to this story, so the Phase 7 audit inherits a known baseline rather than attributing them to US-017.

---

## 8. Gate 2 recommendation

**Conditional pass. No Blocker.**

US-017 closes RES-3 end to end and RES-9 for the assign/revoke caller test, closes RES-10 at the root rather than inheriting a widened version of it, and closes the only runtime path that could mutate the guard's own input. On every path I could construct, the target side and the detection side are strictly stronger than the status quo, and I found no way to turn the fix against itself: 403-before-409 and 404-before-403 hold by construction, the short-circuit cannot skip the read while clearing `privileged`, ALL ⊆ ANY makes D8's containment genuine rather than asserted, and the self-revocation proof survives independent re-derivation.

**The loosening is the risk, and it is well-designed.** D2 is the correct answer to the vacuity problem and I could not defeat it: no ALL-three role can exist that a literal `TENANT_ADMIN` did not deliberately create. What the design does not account for is the *population* that can end up holding such a role without anyone deciding to grant it — which is RES-1(b), which US-017 makes much more valuable and does not mention.

**Gate 2 may close once RC-15…RC-22 are folded into `03-design.md`.** Five of the eight are editorial, test-shaped or runbook-shaped and none reopens Gate 1 or requires an ADR beyond edits to ADR-0018's "does not close" section.

**Send back to the Architect before Gate 2 closes:**
- **RC-15.3** — ship the "role became fully admin-equivalent" signal, or file the named successor story with an id before merge. This is a scope decision. Silence is not an acceptable answer, because US-017 is the story that increases RES-1(b)'s payoff, and the register entry it belongs to expires at Epic 3 kickoff.
- **RC-16.2** — the promotion signal for a non-`TENANT_ADMIN` caller minting a literal `TENANT_ADMIN`. Small, but it is new code on the gate's pass path.
- **RC-20** — D7's reachability correction, the per-index restatement, harness C's benign thread, and the ordering/plan contract. This is the load-bearing section of the design and three of its claims need adjusting.

**Merge checklist items (non-code), following the US-015 §4.5 / US-016 §8 precedent:**
- RES-1(b)'s amplification is recorded with its inherited owner, review date and Epic-3 hard expiry **before merge**; RC-15.3's outcome (shipped, or successor story id) is recorded in §12.3 **before merge**.
- RES-10's closure evidence — reshaped harness C, `assign(TENANT_ADMIN)` thread restored, **plus RC-20.6's benign thread**, green over ≥5 runs — is attached to the PR. If it is not green, this entry reverts to an open, widened High and the story returns to Gate 2.
- RES-17, RES-18 and RES-13's re-ratings are reflected in `03-design.md` §12.3 before merge.
- RC-19's retention figure is **named**, with Ops sign-off, before merge.
- RC-21's sweep output is retained as dated evidence, and every affected tenant has a remediation ticket or a written acceptance, **before** the production deploy step.
- `./mvnw dependency:tree` runs at **Phase 7**, not skipped — no manifest delta exists today (verified §0.1 item 18), so there is nothing to scan at Gate 2. `npm audit`'s 27 pre-existing findings are recorded as an inherited baseline (§0.1 item 19) and are not attributable to this story.

### Cross-references

- `docs/features/US-017/03-design.md` — the artifact under review (§13 lists the three stakeholder flags this document answers in §4 rows 15–17)
- `docs/features/US-017/01-requirements.md` — Gate 1 Resolution (binding)
- `docs/features/US-017/02-impact.md` — Phase 2 and its Impact-Analysis Resolution; §5.5's five focus items are discharged by T-E29/T-E30 (item 2), §7.5 + T-I14 (item 1), T-D15 (item 3), T-I16 (item 4) and T-I15/T-D16 (item 5)
- `docs/adr/0018-admin-equivalent-lockout-and-caller-side-privilege-test.md` — D1–D8; RC-15.1, RC-16.1 and RC-20.5 amend its "does not close" and follow-on sections
- `docs/features/US-016/03b-threat-model.md` §3, §5, §7 — T-E21/RES-1(b), T-E23, T-D11, T-T13, RC-8, RC-12, RC-13, RES-6, RES-10, RES-11: the precedents this document applies
- `docs/features/US-015/03b-threat-model.md` §4.5 — RES-10's retention resolution, the precedent for RC-19
- `docs/features/US-012/03b-threat-model.md` — T-E7, T-D4, T-R4; `monitoring.md` §2/§3/§5 and `runbook.md` §2, all of which §9.5 must edit
- `docs/adr/0017-privilege-based-role-assignment-gate.md` D1–D5 and follow-on rules 2/6 — extended, body **not** edited

---

## 9. Delta review (2026-09-18) — verdict on `03-design.md` Revision 2 and ADR-0018's Gate 2 amendments

**Scope of this pass.** A *delta* review, not a re-derivation: I verified the architect's response to RC-15…RC-22 and the five editorial corrections against the cited sections, and ruled on the one disagreement addressed to me (RC-17.1). I did **not** re-run the STRIDE analysis, and nothing in revision 2 opens a new threat — every added mechanism (D22–D25, M12) is a read or a signal on an already-analysed path, adds no endpoint, no write, no secret, no PII field and no new external input. Dependency basis re-verified this session: `git diff --stat main...HEAD -- '*pom.xml' '*package.json' '*package-lock.json'` is still empty, so §0.1 items 18/19 stand unchanged — `dependency:tree` remains a Phase 7 obligation and `npm audit`'s 27 findings remain an inherited baseline.

### 9.1 Headline

**Every substantive ask landed, including all three items escalated as Architect decisions.** RC-15.3 ships rather than being deferred; RC-16's framing correction is honest and its signal covers the path I flagged; RC-20's three factual corrections are made in the load-bearing section and its per-index restatement is the one the analysis actually supports; RC-22.4 takes the *preferred* option and eliminates a residual instead of accepting it; RC-19 names the retention figure; RC-17 is resolved in a shape I accept (§9.3). The architect also correctly refused one thing I asked for badly (§9.3) and said so in writing rather than quietly re-shaping it — that is the right handling of a Gate 2 disagreement.

**What has not landed is a fold-in, not a decision.** Six sections of `03-design.md` still carry revision-1 text that now *contradicts* revision 2's own §0.1 change log and §0.2 decision table. Four of those contradictions matter enough to hold Gate 2 closure (§9.4); the rest are editorial (§9.5). None requires new analysis, a new decision, or a return to Step B: once the four are folded in, Gate 2 closes on this document without further security review.

### 9.2 Item-by-item verification

| Item | Verdict | Evidence |
|---|---|---|
| **RC-15.1** — RES-1(b) recorded **by citation**, owner/review/expiry carried forward | **Landed in the ADR; missing from the design's register.** | `docs/adr/0018-…md:170` is exactly right: *"This is recorded against the existing RES-1(b) entry — it does not open a competing one"*, with **owner (Md Nisar Ahmed), 2026-11-27 review and hard expiry at Epic 3 kickoff carried forward unchanged**, and the payoff delta stated correctly (likelihood unchanged, impact increased). §0.1 claims the same entry exists in `03-design.md` §12.3 — **it does not** (§9.4 item 1) |
| **RC-15.2** — §4.2 Javadoc replacement text | **Landed.** | `03-design.md:366` — the third paragraph states the amplification in the method's own documentation, in the terms T-E27 required |
| **RC-15.3** — the threshold-crossing signal is **real** and paged on existing holders | **Landed, and it ships in US-017** (the scope decision I asked for, taken rather than deferred). | `03-design.md:69` (D22), `:877` (WARN `RBAC_ROLE_BECAME_FULLY_ADMIN_EQUIVALENT` `{tenantId, roleId, roleName, holderCount, grantedBy}`, emitted on the dangerous path **after** the attach from one bounded M7 read), `:878` (counter, **ticket; page when `holders != "0"`**), `:961` (the `US-015/monitoring.md` edit that makes it operational). The "page on existing holders" property I asked for is present verbatim. **Anchor defect only:** D22 cites **§4.9**, which does not exist — §4 ends at §4.8 |
| **RC-16.1** — "narrower by construction, not a containment"; is the rewording honest? | **Landed, and it does not overclaim.** | `adr/0018-…md:169` and `03-design.md:65`, `:365`, `:729` all say the same thing: narrower **by construction**, *"it bounds nothing"*, *"recorded for definitional consistency, not as a control"*, *"a future reviewer … must not conclude there is a safety property to preserve"*. That is the accurate statement of T-E28, not a softened one. **But** `03-design.md:1065` (§12.3 RES-13) and `:1080` (§13 item 2 — the text going to **Security for sign-off**) both still read *"the mint side staying **narrower** is the safe direction"*, still rated Low-Med (§9.4 item 1) |
| **RC-16.2/3** — does D23's signal cover the self-assign-then-become-admin path? | **Yes — it fires on exactly that path.** | `03-design.md:70`, `:879`, `:880`. Trigger is `callerMatchedOn == ALL_DANGEROUS_PERMISSIONS` **and** target role is the literal `TENANT_ADMIN` — which is T-E28 step 1 precisely — with `{selfTarget}` bounded at 2 series and **page on self-target**. The PromQL-tier justification for adding a counter beside the WARN is correct for this repo. The RC-16.3 log companion (`:881`) gives the `ALL_DANGEROUS_PERMISSIONS` population a subject and also covers the *non-literal* variant (self-assigning another ALL-three role), which the WARN alone would miss. **One observation, Low, no action required:** the WARN is emitted at the gate's pass point, so it fires on attempts that subsequently 409 (`RBAC_004`) or roll back. Over-firing on a detection signal is the safe direction; recorded so a future reader does not "fix" it by moving it post-commit without re-reading this line |
| **RC-17.1** — the M12 substitution | **Accepted. See §9.3 — this is a ruling, not a pass-through** | |
| **RC-18.1/2** — `carriesAll` spec; Java↔SQL equivalence | **Spec landed; both mechanical controls did not.** | `03-design.md:316-322` specifies the per-name case-insensitive `anyMatch` and names both traps (never a count — fail-open; never `containsAll` — silently fails closed) exactly as required; `adr/0018-…md:41` mirrors it and D1's follow-on rule carries it. **But** §11.2's MC-B row (`:1022`) is unchanged and does not carry the three regression assertions, §11.3's unit matrix (`:1032`) covers case/empty/null but **not the duplicate-bearing list** — the one fail-open case — and **MC-I is referenced (`:59`, `:27`) but never defined in §11.2** (§9.4 item 2) |
| **RC-19** — retention precondition | **Landed in full, and better than I asked.** | `03-design.md:943` — figure **named** (≥ 1 year, sourced from `docs/observability-standards.md`), all three markers, **Ops sign-off as a merge-checklist item**; `adr/0018-…md:176` carries it. `:945`'s scope note — that the mandate reaches a shipped US-016 marker, and why splitting it would leave the weakest marker uncovered — is the honest handling. `:947`'s refusal of a `tenantId` tag on cardinality grounds, with the runbook pointing at the WARN's `tenantId` for attribution, is **correct**: it delivers RC-19.2's operator outcome without violating D15's bounded-series discipline. I withdraw the per-tenant phrasing |
| **RC-20.1** — reachability correction | **Landed.** | `03-design.md:700-704`: the clause is *withdrawn* in writing, the true ordering stated (M11 at check 4.5, gate at check 5), the ordering correctly defended as unchangeable, **D14 named as the real bound**, RES-11(c)'s per-replica caveat spelled out, and `store-type=redis` stated as *"a deployment prerequisite, not operational advice"*. `adr/0018-…md:122` and its new follow-on rule (`:184`) generalise it correctly |
| **RC-20.5** — per-index restatement | **Landed.** | `03-design.md:693-697` states it per index (total w.r.t. `fk_user_roles_role`; `uq_user_role_active` / `fk_user_roles_user` / clustered-index acquisitions serialised for privileged × privileged by the M11 conflict, unchanged-in-kind for privileged × benign) and, importantly, says plainly that *"not constructible by review" is not the standard §7 sets for itself*. `adr/0018-…md:124` matches |
| **RC-20.6** — benign thread in harness C | **Landed in the decision; not carried into the test sections.** | `03-design.md:708-710` mandates it and explains why it is not optional (the US-016 harness-A precedent). **But** §11.1's harness-C bullet (`:1013`) still mentions only the restored `assign(TENANT_ADMIN)` thread, and §10.3 step 1's exit criterion (`:991`) likewise (§9.5 item 5) |
| **RC-20.7** — "ascending" defined, and MC-E/MC-C | **Definition landed in prose; NOT reflected in the mechanical checks — the specific thing this delta was asked to confirm.** | The definition is correct and complete in M11's port Javadoc (`03-design.md:398-410`) and `adr/0018-…md:94`: unsigned byte-wise order of the 16-byte representation, **not** `UUID.compareTo`, plus plan stability as part of the claim. **But §11.2 — the section `/breakdown` turns into test tasks — is unchanged from revision 1:** MC-E (`:1025`) still reads *"sorted **ascending** (argument captor)"*, which is verbatim the wording T-D15 part 3 flagged as giving **false assurance**; MC-C (`:1023`) still asserts `key = fk_user_roles_role` with **no IN-list cardinality variation**. The document now contradicts itself in two places about what MC-E and MC-C assert (§9.4 item 2) |
| **RC-21** — forensic sweep | **Not landed.** §0.1 (`:30`) says *"§10.3 step 3 rewritten"*. It is not rewritten — `03-design.md:993` is revision-1 text (§9.4 item 3) |
| **RC-22.1/2/3** — TTL and protected properties | **Landed.** | `03-design.md:57` (D10 corrected to "no *application-maintained* staleness"), `:796-802` — Protected property 1 (the 30 s TTL named as a security control, with M-2's provenance and the "do not remove or lengthen" instruction) and Protected property 2 (liveness/readiness exclusion, with the `application.yml:99-106` / `Dockerfile:27` evidence). `adr/0018-…md:163` carries the same correction. **MC-J is referenced (`:802`) but never defined in §11.2** (§9.4 item 2) |
| **RC-22.4** — narrow the indicator's capability | **Decision landed (preferred option); the component section contradicts it.** | `03-design.md:72` (D25) and `:59` (D12 amended) adopt `ZeroAdminTenantReader` and state RES-22 is *eliminated*. **But §4.8 (`:544`) still reads "Constructor unchanged (still `JpaUserRoleRepository` directly — D12)"**, and the §2 architecture diagram (`:127`) still routes the indicator straight at `JpaUserRoleRepository`. An implementer working from §4.8 ships the capability D25 exists to remove (§9.4 item 4) |
| **Editorial 1–4** | **All four landed.** | `03-design.md:1058` (the detach break stated as 204 → 403 first), `:634` (the guard is stronger than a lockout check; no third party can drive a tenant to the boundary), `:729` (§7.5 Change 1's population), `:431` (M5b's `isEmpty()`/`size()`-only warning carried from M5) |
| **Editorial 5** | **Not landed.** §0.1 (`:36`) says §12.1 records the npm-audit baseline; §12.1 (`:1047-1051`) contains no such line (§9.5 item 4) |

### 9.3 Ruling on the RC-17.1 disagreement (`03-design.md:13`, `:71`; `adr/0018-…md:68`)

**The architect is right on the worked example, and I withdraw it.** RC-17.1 illustrated the required property with a query shape (`… p.name IN :dangerousNames … HAVING COUNT(DISTINCT p.name) = 3`) that would have put the dangerous-permission names behind a port method — while §4 row 5 of this same document **confirmed D3 as upheld**. That is an internal inconsistency in my own document, it was correctly identified as one, and refusing to reopen an ADR one day after acceptance on the strength of an illustration is the correct call. Flagging it back rather than silently reshaping it is also the correct process.

**Does M12 satisfy what RC-17.1 was protecting against? Yes, on the axis that matters.** T-E29's failure mode is a **defect in M10** — a mis-joined `rp.id.roleId`, a dropped `r.tenantId` predicate, a future `LEFT JOIN`, a duplicate row — producing an over-broad classification that fails open on the gate *and* on the lockout *and* silences the canary that exists to notice. M12 (`03-design.md:439-455`, `:894-914`) is a different statement, on a different driving index (`fk_user_roles_user` vs `r.tenantId`), with a different scoping (the caller's own active assignments vs the whole tenant) and a different join direction. **No M10 defect can propagate into it.** The canary therefore disagrees, and `nexus_rbac_gate_bypass_canary` fires, in exactly the scenario RES-18 conceded it would be silent. The canary's name half remains independent of both reads. M12 is correctly Javadoc'd as non-locking and **never** usable for an authorization decision, with MC-G asserting that negative on both verbs — the T-E7/T-S8 discipline survives the addition.

**What the substitution genuinely does not buy, and the design says so:** a second *combinator* implementation. Gate and canary both call `RbacAdminEquivalence.isFullyAdminEquivalent`, so a defect **in the predicate itself** corrupts both together and the canary stays silent. That residual is real, it is narrower than the one RC-17.1 attacked (a pure domain function under the 0.90 `rbac.domain` gate, versus a query where join/scoping/tenant-predicate defects actually originate), its one known fail-open shape is pinned by §4.1's spec, and it is named honestly in three places rather than glossed (`03-design.md:931`, D24's "the one axis not bought", `adr/0018-…md:175`'s RC-17.3 entry, which states the shared combinator plainly and extends the runbook's "inside, not around" caveat to name it). **That is the right disposition: not a gap, a correctly-scoped residual.**

**Ruling: the substitution is accepted. RC-17.1 is discharged by D24/M12.** Two conditions, both already in the design and neither new: (a) §4.1's `carriesAll` specification is the *only* thing standing between the shared combinator and a shared fail-open, so MC-B must actually carry the duplicate-list assertion (§9.4 item 2); (b) **MC-H** — the M10 ↔ M7 equivalence IT — remains required, because M12 fixes only the third row of §9.3's table and rows 1 and 2 (gate and lockout) still fail open on an over-broad M10 with nothing but tests between them. **RES-18 at Medium, restated over all three consumers, is the correct rating** and matches mine.

### 9.4 What blocks Gate 2 closure — four mechanical fold-ins, no decisions

Each is revision-1 text that now contradicts revision 2's own §0.1/§0.2. None needs analysis; all are edits the Architect can make directly.

**1. `03-design.md` §12.3 (`:1060-1071`) and §13 item 2 (`:1080`) — the residual register was not updated at all.** It still: frames RES-13 as *"the mint side staying narrower is the safe direction"* at Low-Med — the exact claim §0.1, D18, §4.2, §7.5 and the ADR all now correct, and the exact claim I **disputed**; rates RES-17 Low (D15/§0.1 say Medium); describes RES-18 as *"the canary and the gate now share one input (`fullyAdminEquivalentIds`, from M10)"* at Low — **a description of a design that D24 replaced**, directly contradicting `:929`; and contains **no RES-1(b) citation entry** (RC-15.1, which §0.1 claims is there), **no RES-19, RES-20, RES-21 or RES-23** (all four referenced as "recorded" elsewhere in the document), and no note that RES-22 is eliminated. **§13 item 2 is the text that goes to Security for sign-off**, and as written it asks Security to confirm a safety property the rest of the document says does not exist. ADR-0018's own new follow-on rule (`:187`) is the argument for fixing this: *"A risk register that silently accrues value on entries nobody re-read is worse than no register."* **Blocking.**

**2. `03-design.md` §11.2 (`:1017-1028`) — the mechanical-controls table was not updated, so three required controls are undefined and two are specified wrongly.** MC-E still says "sorted ascending", which RC-20.7 identified as false assurance, while the port Javadoc (`:402`) says MC-E asserts the byte-wise comparator — the document contradicts itself about what the test asserts. MC-C still asserts one plan, while `:409` says it covers IN-lists of size 1, 2 and ≥ 20. MC-B does not carry RC-18.1's three regression cases. **MC-H, MC-I and MC-J are each referenced as existing (`:26`, `:27`, `:31`, `:38`, `:59`, `:802`, `:929`) and none is defined**, and §10.3 step 1's exit criterion (`:991`) still says "MC-A…MC-G". `/breakdown` derives test tasks from §11.2; as it stands it would generate the revision-1 tests. **Blocking.**

**3. `03-design.md` §10.3 step 3 (`:993`) — RC-21 is not applied.** §0.1 (`:30`) says the step was rewritten with `auth_events` attribution, executable DBA SQL, every environment where either flag was ever `true`, dated evidence retention, and a remediation ticket or written acceptance per affected tenant before step 5. The row is unchanged revision-1 text: a sweep that produces a list and stops, with the exit criterion *"the affected list is known"*. The population it enumerates may have been zeroed before US-016's gate existed, when `revoke()` had no admin check at all — attribution is the point of the finding. **Blocking.**

**4. `03-design.md` §4.8 (`:544`) and the §2 diagram (`:127`) — D25 is not applied where the component is designed.** §4.8 still reads *"Constructor unchanged (still `JpaUserRoleRepository` directly — D12)"*. D12 (`:59`) and D25 (`:72`) say the opposite and claim RES-22 is *eliminated*. An implementer reading §4.8 injects the full `JpaRepository` and ships `save`/`delete`/`deleteAll` over `user_roles` into a health check — T-T14 unfixed while the register says it is gone. **Blocking** (it is a one-line fix, but the direction of the contradiction is the unsafe one).

### 9.5 Residuals to record, not blocking

1. **Dangling anchor:** D22 cites **§4.9** (`03-design.md:69`); §4 ends at §4.8. D22's substance is fully specified in §9.2 (`:877-878`) and §9.5 (`:961`), so nothing is missing — only the pointer. Either add the section or repoint it at §9.2.
2. **§4.3's heading** still says *"one method removed, **three** added"* while M12 makes it four (`:369`); the M12 Javadoc itself is present and correct in that section, and `:16`/`:38` say four.
3. **§11.3 coverage list** (`:1030-1041`) was not extended for revision 2: no adapter delegation test for **M12**, and no unit coverage for **D22**'s threshold-crossing emission or **D23**'s promotion WARN/counter. §9.2's rows define the signals; the test plan does not yet require them. Worth folding in with item 2 above so `/breakdown` prices them.
4. **Editorial 5** (npm-audit baseline) is claimed at `:36` but absent from §12.1. One sentence; it exists to stop the Phase 7 audit attributing 27 pre-existing frontend toolchain findings to this story.
5. **§11.1 (`:1013`) and §10.3 step 1 (`:991`)** name only the restored `assign(TENANT_ADMIN)` thread; §7.3's benign thread (RC-20.6) should appear in both, since step 1's exit criterion is what actually gates the merge.
6. **Typo:** `:710` refers to *"E20's per-index restatement"* — read RC-20.
7. **D23's WARN fires at the gate's pass point**, so it can precede a 409 `RBAC_004` or a rollback. Safe direction for a detection signal; recorded so it is not "corrected" later without re-reading T-E28.

### 9.6 Standing attestation for this delta (auth, crypto and PII are never approved silently)

- **Authentication / caller-identity — reviewed for the new surface. No findings.** M12 is non-locking and is explicitly barred from authorization decisions (`03-design.md:447-449`), with MC-G asserting the negative on both verbs; the gate's only determination remains M5b, the fresh locking `FOR SHARE` read. T-S8/T-E7 survive revision 2 unchanged. The canary now performs two non-locking reads (M4 + M12) post-commit on the self-assignment path only — no new authorization input.
- **Authorization — reviewed. No new threat.** D22–D25 add no gate, no gate condition and no new caller population. D24 narrows a detection dependency; D25 narrows a capability; D22/D23 are signals. The loosening's shape (FR-3) is unchanged from revision 1 and my §3/§4 verdicts stand.
- **Cryptography — reviewed. No findings.** Revision 2 introduces no key material, no randomness source and no id generation. The one crypto-adjacent item — the ordering contract — is now correctly specified as unsigned byte-wise `BINARY(16)` order (`:398-404`), which is the fix T-D15 part 3 asked for; only its mechanical assertion is outstanding (§9.4 item 2).
- **PII — reviewed against the organisation's no-PII rule. No new exposure.** Every field added by D22/D23 is a UUID, an integer, a bounded bucket tag, a role name or a permission name: `{tenantId, roleId, roleName, holderCount, grantedBy}`, `{tenantId, actorUserId, targetUserId, roleId}`, `{selfTarget}`, and the log companion's `{tenantId, actorUserId, targetUserId, roleId, roleName, operation}`. No email, no display name, no IP beyond the pre-existing `RequestContext` triple; ids stay in logs and out of metrics, which is the correct split. `roleName` inherits US-015 D6's CR/LF-excluding allow-list and the structured encoder — **log injection remains closed, inherited**, and revision 2 adds no new sink.
- **Secrets — reviewed. No findings.** No credential, token or connection string introduced. The two configuration values this review depends on (`management.endpoint.health.cache.time-to-live`, the D14 throttle's `store-type`) are non-secret and are now both named as controls rather than left implicit.

### 9.7 Closure confirmation (2026-09-18)

§9.4's four blocking fold-ins were applied to `03-design.md` by the Architect via `Edit` (no full rewrite; D1–D25 and §0.1 untouched) and independently checked line-by-line against §9.4's own citations, not taken on the Architect's report alone:

1. **§12.3/§13 item 2** — RES-13 reworded to the RC-16.1 disposition and re-rated Medium; RES-1(b) added as a citation-only row carrying its US-016 owner/review-date/expiry forward; RES-17 re-rated Medium; RES-18 rewritten to state independent inputs with only the ALL/ANY combinator shared; RES-19/20/21/23 added; RES-22 recorded as **eliminated**. Confirmed present at the cited lines.
2. **§11.2** — MC-E now asserts the unsigned byte-wise `BINARY(16)` comparator (not "sorted ascending"); MC-C now asserts plan stability for IN-list sizes 1, 2 and ≥ 20; MC-B carries RC-18.1's three regression cases; MC-H/MC-I/MC-J are defined; the exit-criterion line extended to MC-A…MC-J. Confirmed present.
3. **§10.3 step 3** — replaced with the RC-21 rewrite: DBA SQL in the runbook, all environments either flag was ever `true` in, per-tenant `auth_events` attribution, dated evidence retention, remediation ticket or written per-tenant acceptance before step 5. Confirmed present.
4. **§4.8 / §2 diagram** — §4.8 now states the constructor is changed (D25) to `ZeroAdminTenantReader`; the diagram shows the same. Confirmed present.

Per §9.1: none of the four required new analysis or a return to Step B. **Gate 2 is closed on this threat model.** §9.4 items 1–4 are left as written above as the audit record of what was found; this section records that they were subsequently closed, not that they were never open. §9.5's residuals (dangling §4.9 anchor, §4.3 heading count, §11.3 coverage gaps, editorial 5, benign-thread naming, the E20 typo, D23's pre-commit WARN timing) remain open as non-blocking — carry them into `/breakdown` rather than re-opening Gate 2 for them.

### 9.7 Disposition

**No Blocker. No decision outstanding. No return to Step B.** The four items in §9.4 are fold-ins of decisions already taken and recorded in the same document; once they land, **Gate 2 closes on this threat model without a further security pass** — I do not need to re-review the edits, but the merge checklist in §8 still applies, with two additions: RC-21's rewritten step 3 must exist before the production deploy step, and §11.2's MC-E/MC-C/MC-H/MC-I/MC-J must exist before `/breakdown` prices the test tasks.
