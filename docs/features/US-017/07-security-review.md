# US-017 — Phase 7 Security Review (Mode B, Code Audit)

_Extend last-admin lockout protection to admin-equivalent custom roles._

**Branch:** `feature/US-017` (zero commits; the diff was built by hand from the working tree against `origin/main`) · **Reviewer:** Application Security Engineer · **Date:** 2026-09-24 · **Threat model:** `docs/features/US-017/03b-threat-model.md` (Gate 2 closed 2026-09-18)

**Verdict: BLOCKED** *(as originally found — see §9 "Resolution" for current status: H-1, M-1 and L-3 are now fixed and verified; only L-1/L-2 remain open, deferred to follow-up tasks)*. One High finding (H-1) is a regression of a shipped control and conflicts with a binding requirement (`01-requirements.md:43`). It has to be triaged before merge: either re-implement it or accept it with a recorded mitigation. No Blocker.

| Severity | Count |
|---|---|
| Blocker | 0 |
| High | 1 |
| Medium | 1 |
| Low | 3 |

---

## 1. Scope and method

**Main code audited in full.**
- **New files, read in full:** `ActiveAssignmentHolder`, `RbacAdminEquivalence`, `RolePermissionName`, `ZeroAdminTenantReader`.
- **Modified files, diffed against `origin/main`:** `RoleAssignmentService` (read in full, all 1 078 lines), `RoleManagementService`, `UserRoleAssignmentPort`, `RbacDangerousPermissions`, `RbacZeroActiveAdminsHealthIndicator`, `JpaRoleRepository`, `JpaUserRoleAssignmentAdapter`, `JpaUserRoleRepository`.
- **Excluded:** unrelated working-tree changes under `.claude/*`, `.mcp.json` and `.github/workflows/ai-test-coverage.yml`.

**Tests spot-checked** for credentials, for test gaps that matter to security, and to confirm the mechanical controls MC-B, MC-C, MC-E, MC-H, MC-I and MC-J exist.

**Configuration read directly:**
- `application.yml:79-120`
- the `application-*.yml` profiles, which were grepped for any TTL override
- `SecurityConfig.java:78`
- `UuidV7Converter.java`
- `JpaRoleManagementAdapter.java:119-129`

**Not run:** the Docker/Testcontainers IT suite. It is deferred to Phase 8 per project convention, and this phase is audit-only.

---

## 2. Findings

### [HIGH] H-1 — The lockout and the zero-admin detector protect holders who cannot administer, so the last real administrator (including a literal `TENANT_ADMIN`) can now be removed

**OWASP:** A01 Broken Access Control / A04 Insecure Design

**File:**
- `nexus-backend/src/main/java/com/example/nexus/rbac/application/RoleAssignmentService.java:456-460, 487, 681-705`
- `nexus-backend/src/main/java/com/example/nexus/rbac/infrastructure/health/RbacZeroActiveAdminsHealthIndicator.java:67-75`
- `nexus-backend/src/main/java/com/example/nexus/rbac/infrastructure/persistence/JpaUserRoleRepository.java` (FR-2 (b), `findTenantsWithActiveAdminEquivalentHolders`)

**Issue.** Three controls use two different predicates:
- The **lockout** (`wouldLeaveTenantWithoutAdminEquivalentHolder`) counts distinct holders of every role in the lock set. That set is built from `adminEquivalentIds`, the **ANY**-dangerous-permission predicate.
- The **FR-2 health query** counts the same **ANY** population.
- The **caller gate** (`requireCallerHoldsAdminEquivalentRole`) admits only holders of the literal `TENANT_ADMIN` or of an **ALL-three** role.

ADR-0018 D2 proves that an ANY holder, for example a helpdesk role that carries only `user:write`, is *not* an administrator: they can never pass the gate. D5 still counts them as the tenant's remaining administrator. That is exactly the kind of population the story's own vacuity argument excludes.

**Concrete sequence**, reachable today in any tenant that has delegated `user:write` through a custom role:
1. A is the sole `TENANT_ADMIN`. B holds `HELPDESK`, which carries `{user:write}`.
2. A calls `DELETE /api/v1/users/{A}/roles/{TENANT_ADMIN}`.
   - `lockSet = {TENANT_ADMIN, HELPDESK}` and the locked holders are `{A, B}`.
   - After excluding `ref.id()`, `{B}` remains, so the call returns **204**.
   - On `origin/main` the same call returns **409 `RBAC_002`**, because the guard there was `nameMatch && lockedActiveAdminIds.size() <= 1 && contains(ref.id())`.
3. Nobody in the tenant can now pass either gate:
   - B's privileged assign/revoke returns 403, since B has no ALL-three role and no `TENANT_ADMIN`.
   - Attach/detach of dangerous permissions needs a literal `TENANT_ADMIN` (M5), and there is none.
4. `rbacZeroActiveAdmins` reports **UP**, because B counts as an active admin-equivalent holder. On `origin/main` this tenant would have reported DOWN (a seeded `TENANT_ADMIN` with zero active assignments).

The same thing happens when an ALL-three administrator revokes their own qualifying role while any ANY-only holder exists.

This contradicts `01-requirements.md:43`: *"the existing lockout/health behavior for the literally-named `TENANT_ADMIN` role must continue to fire exactly as it does today."* It also contradicts the threat model's claim (§0.2, §8) that the target and detection sides are "strictly stronger than the status quo". No test covers this case. `RoleAssignmentServiceTest:1425` (`EdgeCase2`) asserts that the revocation **succeeds** when the other holder's role carries only `user:write`, so it pins the regression as intended behaviour.

**Risk.**
- **Accidental:** an administrator can permanently lose the tenant's administrative capability with no 409 to stop them. An administrator tidying up their own assignment, believing the helpdesk holder is a co-admin, gets no warning.
- **Malicious:** a compromised sole-admin account can do the same thing deliberately, which is the exact T-R10 scenario. AC5 existed to prevent this.
- **Detection:** the only detection control stays green, so nothing pages. Recovery needs DBA-level intervention.

This takes insider or compromised-admin access, so it is not a Blocker. It is a regression of a shipped control, though, so it is rated High.

**Fix.** This needs an Architect decision, because it changes the meaning of D5 and FR-7.
- **Recommended:** keep the ANY-union **lock set** exactly as it is. The lock set is what D6/D8's ordering and containment proofs depend on. Evaluate the **lockout predicate** only over holders of the *caller-qualifying* set, `namedAdminRoleId ∪ fullyAdminEquivalentIds`.
  - Add `roleId` to `ActiveAssignmentHolder` (still ids only) so the service can filter the locked holders.
  - Use the same caller-qualifying predicate in FR-2 (b) (literal name OR `HAVING COUNT(DISTINCT p.name) = 3` over `:dangerousNames`). That keeps FR-7's "same set for lockout and detection" rule intact.
- **Minimum acceptable alternative:** restore the literal-`TENANT_ADMIN` guard as an *additional* check alongside the widened one, as FR-1/FR-2 "additive" requires. Record the ANY-versus-caller-capable gap as a residual with an owner.
- **Either way,** add a unit test and an `AdminEquivalentLockoutIT` case for the sequence above, asserting 409 and a DOWN health status.

---

### [MEDIUM] M-1 — The self-assignment bypass canary cannot fire when the target role is itself fully admin-equivalent, which is the most sensitive case

**OWASP:** A09 Security Logging & Monitoring Failures

**File:** `nexus-backend/src/main/java/com/example/nexus/rbac/application/RoleAssignmentService.java:333, 953-964`

**Issue.** `callerIsAdmin = privileged && callerHoldsActiveAdminEquivalentRole(actor)` runs inside `afterCommit()`, so it runs after the new assignment has been committed. Its inputs are:
- M4 (`findActiveAssignmentViews`)
- M12 (`findPermissionNamesForActiveAssignmentsOfUser`)

Both reads therefore include the assignment that was **just created**. When the target role is the literal `TENANT_ADMIN`, or any ALL-three role, `isFullyAdminEquivalent` is always true for that just-inserted row. The canary reports `callerIsAdmin="true"` whether or not the caller was an administrator *before* the request.

The page-severity `callerIsAdmin="false"` series (`nexus_rbac_gate_bypass_canary`) can therefore only fire when the target is ANY-but-not-ALL. It is structurally silent in exactly the scenario it exists for: a gate defect that lets a non-admin self-assign `TENANT_ADMIN`.

This shape already existed on `origin/main` for the `TENANT_ADMIN` target (US-016's `callerHoldsActiveTenantAdmin`, also post-commit). US-017 widens it to every ALL-three target. RC-17 was also closed on the claim that the canary now "fires in exactly the scenario RES-18 conceded it would be silent". That holds for M10 defects only on partially dangerous targets.

The tests don't catch this:
- `RoleAssignmentServiceTest.java:912` proves reachability by stubbing M4 to return `List.of()` after a successful self-assignment. That state cannot occur against a real database.
- `RoleAssignmentSecurityIT` (`should_notTripCanaryAsFalse_when_fullyAdminEquivalentNonNamedCallerSelfAssignsTenantAdmin`) asserts the blind outcome as correct.

**Risk.** A future gate-bypass defect of the T-E22 class (M5b answering the wrong question, or a caller-set construction bug) that lets a `user:write` holder mint themselves `TENANT_ADMIN` produces no page. D23's `RBAC_ADMIN_MINTED_BY_NON_NAMED_ADMIN` fires only when the gate *correctly* admitted an ALL-three caller, so it does not cover a bypass either.

**Fix.** Evaluate the canary against the caller's state **excluding the assignment this request created**. Filter out `a.roleId().equals(roleId)` in `callerHoldsActiveAdminEquivalentRole`, and ignore that role's M12 rows. An alternative is to take the two non-locking reads before the INSERT and carry the boolean into the post-commit runnable; MC-G still holds because neither read authorizes anything.

Replace the test at `:912` with one that stubs the *realistic* post-commit M4 (containing the new `TENANT_ADMIN` row) and still expects `callerIsAdmin="false"` when the caller held nothing before. Add an IT variant with a `TENANT_ADMIN` target.

---

### [LOW] L-1 — The UNKNOWN health detail echoes the raw `DataAccessException` message (pre-existing; now covers four tables)

**OWASP:** A05 Security Misconfiguration

**File:** `nexus-backend/src/main/java/com/example/nexus/rbac/infrastructure/health/RbacZeroActiveAdminsHealthIndicator.java:104-106`

**Issue.** `withDetail("issue", "… could not run: " + e.getMessage())` publishes driver or Hibernate text, which can include SQL fragments and table or column names, on `/actuator/health`. That endpoint is `permitAll`, and `show-details: when-authorized` means any authenticated principal can see the detail. In production, `show-details: never` masks it.

The code is unchanged by US-017, but FR-2 widened the statement to four tables and two queries, so more schema is exposed.

**Risk.** Schema reconnaissance for any authenticated tenant member in non-prod environments.

**Fix.** Use a fixed string in the detail (for example `"self-check query failed; see logs"`). Keep `e.getMessage()` in the WARN only.

---

### [LOW] L-2 — The D22 threshold-crossing signal can be evaded by concurrent attaches

**OWASP:** A09

**File:** `nexus-backend/src/main/java/com/example/nexus/rbac/application/RoleManagementService.java:208-210, 412-418`

**Issue.** `becameFullyAdminEquivalent` reads M7 inside the attach transaction. Under `REPEATABLE READ`, suppose two concurrent attaches add the 2nd and 3rd dangerous permissions to a role that already has the 1st:
- Transaction 1 sees `{p1, p2}`.
- Transaction 2 sees `{p1, p3}`.

Neither sees all three, so `RBAC_ROLE_BECAME_FULLY_ADMIN_EQUIVALENT` never fires, even though the role ends up ALL-three. The per-attach holder-count WARNs still fire.

**Risk.** An insider with `TENANT_ADMIN`, or a legitimate but unlucky race, can silently convert every existing holder into a caller-qualifying administrator. That weakens RC-15.3's T-E27 detection, and T-E27 is the story's highest-rated threat.

**Fix.** Do the M7 read inside the `afterCommit` runnable. It then sees committed state, and the later of any two racing commits is guaranteed to see all three. If both fire, the signal over-fires, which is the safe direction for a detection signal. Otherwise, record the race in RES-1(b)'s entry.

---

### [LOW] L-3 — The new D13 detach gate has only unit-test coverage

**OWASP:** A01 (test gap on an authorization control)

**File:** `nexus-backend/src/test/java/com/example/nexus/rbac/security/RolePermissionSecurityIT.java` (no D13 case); gate at `RoleManagementService.java:295-305`

**Issue.** This story adds a new authorization gate. The only proof it works is `RoleManagementServiceTest`, which uses mocks. No HTTP-level IT shows that a `role:write`-only non-admin gets **403** on `DELETE /api/v1/roles/{roleId}/permissions/{dangerousPermId}` with the `role_permissions` row still present. There is also no IT for the "not attached" case returning 403 rather than 404 (T-I14), or for an ordinary permission returning 204.

**Risk.** A regression in controller wiring, `@RequiresPermission` or exception mapping would not be caught. This is the gate that protects the lockout guard's own input.

**Fix.** Add those three cases to `RolePermissionSecurityIT`.

---

## 3. Threat-model cross-reference (RC-15 … RC-22)

| RC | Required mitigation | In code? | Evidence / note |
|---|---|---|---|
| **RC-15.3** | D22 WARN `RBAC_ROLE_BECAME_FULLY_ADMIN_EQUIVALENT` `{tenantId, roleId, roleName, holderCount, grantedBy}` + `nexus.rbac.role_became_fully_admin_equivalent{holders}`, dangerous path only, after the attach | **Yes** (see L-2) | `RoleManagementService.java:208-210` computes it only when `dangerous`, after `attachPermission` (`saveAndFlush`, `JpaRoleManagementAdapter.java:121`), so M7 sees the new row. Emitted post-commit at `:259-272`; the `holders` tag is bucketed (bounded). All five fields are present. Unit-tested only. |
| **RC-15.2** | Javadoc states the amplification | **Yes** | `RoleAssignmentService.java:194-204`, `:402-412` |
| **RC-16** | ALL-three-OR-literal caller gate, live locking read, fail-closed on empty | **Yes** | `requireCallerHoldsAdminEquivalentRole` (`:794-827`). Both branches go through M5b, a native `FOR SHARE` read with `FORCE INDEX` (`JpaUserRoleRepository.java:117-131`), and never read a JWT claim. The named branch short-circuits on `isPresent()` and the ALL-three branch on `isEmpty()`, so an empty caller-qualifying set gives a 403 without M5b being called. The ALL-three set comes from `carriesAll`, a per-name case-insensitive `anyMatch` (`RbacDangerousPermissions.java:52-58`) that is duplicate-safe (MC-B at `RbacDangerousPermissionsTest.java:59`). Stale-JWT IT extended to the ALL-three branch (`RoleAssignmentSecurityIT`). D23 WARN/counter at `:873-888`; RC-16.3 log companion at `:863-871`. |
| **RC-17** | Canary re-derived independently via M12, not from gate control flow | **Yes, with a defect** | `callerIsAdmin` comes from `callerHoldsActiveAdminEquivalentRole` (M4 + M12), not from `privileged`/M10. M12 is non-locking JPQL keyed by user (`JpaUserRoleRepository.java:146-157`), and it is not called on revoke (MC-G). **But it is evaluated post-commit and so includes the new assignment. See M-1.** MC-H exists (`AdminEquivalenceEquivalenceIT.java:60`). |
| **RC-18** | `carriesAll` spec; Java↔SQL equivalence | **Yes** | Spec at `RbacDangerousPermissions.java:38-58`; MC-I at `AdminEquivalenceSqlJavaEquivalenceIT.java:75, 213` |
| **RC-19** | The three WARN markers carry enough to reconstruct the incident from logs alone | **Yes (fields)**; retention is policy | `RBAC_LAST_ADMIN_REVOCATION_BLOCKED` (`:491-500`): `tenantId, targetUserId, actorUserId, roleId, matchedOn, adminEquivalentRoleCount, lockedRowCount`. There is no `roleName`, which is acceptable because `roles.name` is immutable and `roleId` resolves it. `RBAC_PRIVILEGED_ROLE_CHANGE_BLOCKED` (`:905-914`): all actor/target/role/operation fields. `RBAC_DANGEROUS_PERMISSION_DETACH_BLOCKED` (`RoleManagementService` `verifyCallerIsActiveTenantAdmin`): `tenantId, roleId, roleName, permissionId, permissionName, actorUserId`. The ≥ 1-year retention figure and Ops sign-off are not something code can show. **Merge-checklist item.** |
| **RC-20** | No lock leaks; union lock sorted to match `BINARY(16)` unsigned order | **Yes** | The only locking clauses in main code are M11 `FOR UPDATE` (`JpaUserRoleRepository.java:105`), M5b `FOR SHARE` (`:127`) and M5 `FOR SHARE` (`:251`); there is no `@Lock`/`LockModeType` anywhere. M1's `@Lock` was removed. The comparator (`RoleAssignmentService.java:118-124`) compares the most-significant 64 bits unsigned, then the least-significant 64 bits unsigned. Both `toBytes` (`JpaUserRoleAssignmentAdapter.java:72-77`) and `UuidV7Converter` (`:20-22`) serialize most-significant bits first, big-endian, so the comparator matches MySQL's unsigned byte-wise order exactly. The `TreeSet` built with that comparator is what gets sent. MC-E is at `RoleAssignmentServiceTest.java:2311` and MC-C (IN-list cardinalities) at `LastAdminLockoutIT.java:902`. `lockSet` always contains the target role, so M11 never gets an empty `IN ()`. M11 remains reachable before the gate on `assign()` and is bounded only by the D14 throttle (RES-19, accepted). The `store-type=redis` deployment prerequisite still applies. |
| **RC-21** | Forensic pre-deploy sweep | **N/A to code** | Runbook item. Not verified here. It remains a pre-production-deploy checklist item. |
| **RC-22** | Count-only actuator detail; narrow read-only dependency; TTL protected | **Yes** | The DOWN detail is `affectedTenantCount` plus a static `issue` string (`RbacZeroActiveAdminsHealthIndicator.java:88-98`), and the tenant ids appear only in the WARN log (`:78-80`). The indicator injects `ZeroAdminTenantReader` (`:58-61`), which has two read-only methods and no `save`/`delete` (RES-22 is eliminated). The TTL is `time-to-live: 30s` at `application.yml:95-96`, no profile overrides it (grep across `application-*.yml`), and `HealthProbeConfigurationTest.java:85` pins it. Liveness/readiness exclusion is pinned at `:67`. See L-1 for the UNKNOWN branch. |

**Threats the threat model marks mitigated that the code contradicts:**
- **H-1** — the "strictly stronger target and detection side" claim.
- **M-1** — RC-17's claim that the canary now fires.

---

## 4. OWASP Top 10 walk

- **A01 Broken Access Control.**
  - Every privileged mutation goes through a caller gate:
    - `assign()`/`revoke()` go through `requireCallerHoldsAdminEquivalentRole` whenever `privileged` is true.
    - `attachPermission` and `detachPermission` go through `verifyCallerIsActiveTenantAdmin` on the dangerous path.
  - Benign paths are unchanged, as designed.
  - I found no path that reaches a privileged INSERT, UPDATE or DELETE while skipping the gate. The throttle, the 404s and the cross-tenant 403s all run before it.
  - Tenant scoping on the new queries:
    - **M10:** `r.tenantId = :tenantId`.
    - **M11:** `tenant_id` residual predicate plus a tenant-derived role-id set; `AdminEquivalentLockoutIT.java:202` asserts no cross-tenant lock or count.
    - **M5b:** `tenant_id` predicate plus user plus role set.
    - **M12:** `ur.tenantId` predicate, with no `Role` join. Only the canary uses it, and cross-tenant rows can't be inserted in the first place (`verifySameTenant`).
    - **FR-2:** `ur.tenantId = r.tenantId`.
  - No cross-tenant row can be locked or read. **See H-1 for the design-level gap.**
- **A02 Cryptographic Failures.** No cryptographic code. See §5.
- **A03 Injection.**
  - M11 and M5b are native queries whose `IN (:roleIds)` is bound as a `Collection<byte[]>` named parameter. Hibernate expands it into bind placeholders; nothing is built by string concatenation.
  - `FORCE INDEX (fk_user_roles_role)` is a static literal.
  - M10, M12 and the FR-2 queries are parameterized JPQL, and `:dangerousNames` comes from the domain constant, not from user input.
  - **Clean.**
- **A04 Insecure Design.** H-1.
- **A05 Security Misconfiguration.** L-1. The TTL and probe-group protections are intact.
- **A06 Vulnerable Components.** No manifest delta (see §6).
- **A07 Identification & Authentication Failures.** No change. `RoleChangeActor` still comes only from the JWT. Admin status comes from a live locking read, never a claim.
- **A08 Software & Data Integrity Failures.** No new deserialization or update channel. The health indicator's write capability has been removed (D25).
- **A09 Security Logging & Monitoring Failures.**
  - M-1 and L-2.
  - **PII check.** Every new WARN/INFO field and counter tag is one of: a UUID, a role name, a permission name, an integer, or a bounded constant (`matchedOn`, `callerMatchedOn`, `operation`, `selfTarget`, `holders` bucket). No email, display name or free-text request field is logged.
  - **Log injection.** `roleName` is tenant-controlled but still constrained by US-015 D6's allow-list, which excludes CR/LF/U+2028/U+2029, and the logs use the structured key-value API. Log-injection protection is inherited and still closed.
  - **Cardinality.** No new counter carries a tenant or user id tag. The `tenantId` tags on `self_role_assignment` and `dangerous_permission_granted` were already there before this story.
- **A10 SSRF.** Not applicable. No outbound calls.
- **Denial of service.**
  - The health indicator is bounded by the 30s cache (verified).
  - M11 is taken before the gate on `assign()` and bounded by the D14 throttle. That is an accepted residual (RES-19), and it needs the Redis throttle store in multi-replica deployments.
  - M11's result size is still unbounded (RES-17, accepted Medium).

---

## 5. Required attestation (auth, crypto, PII)

- **Authentication — reviewed.** No authentication code changed. The actor still comes only from the RS256-validated JWT. Both caller-gate branches use M5b, a fresh `FOR SHARE` read, and the stale-JWT out-of-band-revocation IT was extended to the ALL-three branch. M12 is non-locking and never makes an authorization decision (MC-G).
- **Authorization — reviewed in depth.** The gates are wired correctly, fail closed, and follow 404-before-403-before-409. **H-1 is a design-level authorization and availability regression and must be triaged.**
- **Cryptography — reviewed. No findings.** No key material, randomness or id generation was added. The one crypto-adjacent item, the ordering contract, correctly implements unsigned byte-wise order and matches the storage serialization.
- **PII — reviewed against the organisation's no-PII rule. No findings.** See the A09 PII check above. The health detail discloses a count only.
- **Secrets — reviewed. No findings.** No credentials in main code. The new `HealthProbeConfigurationTest` uses explicit test-only placeholder values (for example `test-not-a-secret-hmac-key…`) and an empty datasource password. That is acceptable.

---

## 6. Dependency scans

- **Backend:** `./mvnw dependency:tree` exited 0 (198 lines). `git diff --stat origin/main -- '*pom.xml' '*package.json' '*package-lock.json'` is **empty**, so **US-017 changes no dependencies**. Security-relevant versions resolved:

  | Component | Version |
  |---|---|
  | Spring Boot | 4.1.0 |
  | spring-security-core | 7.1.0 |
  | tomcat-embed-core | 11.0.22 |
  | hibernate-core | 7.4.1.Final |
  | mysql-connector-j | 9.7.0 |
  | jjwt | 0.12.6 |
  | jackson-databind | 2.21.4 / 3.1.4 |
  | logback-classic | 1.5.34 |
  | netty-handler | 4.2.15.Final |
  | lettuce-core | 7.5.2 |
  | bcprov-jdk18on | 1.84 |

  No online CVE database was queried in this session, so nothing here is attributable to this story. The existing CI dependency-check gate stays authoritative.
- **Frontend:** `npm audit --audit-level=moderate` reports **27 vulnerabilities (1 critical, 7 high, 16 moderate, 3 low)**. This **matches the documented baseline exactly** (`03b-threat-model.md` §0.1 item 19; `03-design.md` §12.1 Editorial 5). US-017 touches zero files under `nexus-frontend/`, so these are pre-existing and not attributable to this story. The separate dependency-hygiene task still stands, and it must respect the npm-Windows lockfile prune trap.

---

## 7. Residuals carried (not new findings)

RES-17 (unbounded M11 set, Medium), RES-19 (pre-gate lock bounded by the throttle, Medium), RES-13 (name-based mint side, not a containment), RES-1(b) (amplified, owner and Epic-3 expiry carried) and RES-18 (shared ALL/ANY combinator) are unchanged and correctly recorded. D23's pass-point WARN can fire before a 409 or a rollback; that is accepted as the safe direction.

---

## 8. Verdict

**BLOCKED.** This is pending triage of **H-1**. The choices are to re-implement it (via `/implement`: evaluate the lockout and FR-2 (b) over caller-qualifying holders, or restore the additive literal-`TENANT_ADMIN` guard) or to accept it with a recorded mitigation and a named owner. **M-1** should be fixed in the same pass, since it is a small change on the same file. L-1, L-2 and L-3 can go to follow-up tasks.

Everything else the threat model required is present in code: RC-15, RC-16, RC-18, RC-20 and RC-22 are verified. RC-19 is verified for its log fields. RC-21 is a runbook item outside code scope.

---

## 9. Resolution (2026-09-24)

**H-1: FIXED, verified, re-scoped to the recommended fix.** Independently re-verified against the code before implementing (confirmed `ActiveAssignmentHolder` had no `roleId`, and `wouldLeaveTenantWithoutAdminEquivalentHolder` operated over the full ANY-population lock set) before presenting the finding and fix options to the story owner, who selected the reviewer's **recommended** fix (keep the ANY lock set for deadlock-freedom; restrict the distinct-holder check and FR-2's two queries to the caller-qualifying population).

Implemented exactly as recommended:
- `ActiveAssignmentHolder` gained a `roleId` field (ids only, contract preserved).
- `RoleAssignmentService#wouldLeaveTenantWithoutAdminEquivalentHolder` renamed to `wouldLeaveTenantWithoutCallerQualifyingHolder`, now filters locked holders to `roles.callerQualifyingIds()` (`fullyAdminEquivalentIds ∪ namedAdminRoleId`) before the distinct-`userId` count. The lock set itself (M11) is unchanged.
- `ZeroAdminTenantReader`'s two methods renamed (`findTenantsWithAFullyAdminEquivalentRole` / `findTenantsWithActiveFullyAdminEquivalentHolders`) and re-scoped from `OR EXISTS (... IN (...))` (ANY) to `OR (COUNT(DISTINCT p.name) = :dangerousNamesCount)` (ALL) — the same predicate `RbacDangerousPermissions.carriesAll` uses, avoiding the count-based fail-open trap by counting `DISTINCT` names.
- `RbacZeroActiveAdminsHealthIndicator`'s Javadoc, log message (`"...caller-qualifying holders..."`) and actuator `issue` text updated to match.

**New regression coverage, all green under a full Docker-backed run:**
- `AdminEquivalentLockoutIT#should_blockSelfRevoke_when_onlyRemainingHolderIsAnyQualifyingButNotCallerQualifying_H1` — reproduces the reviewer's exact sequence (sole `TENANT_ADMIN` self-revokes while an ANY-only `user:write` holder remains) against a real database; asserts `LastAdminRoleException` (409) where the pre-fix code would have returned 204.
- `RbacZeroActiveAdminsHealthIndicatorIT#should_report_down_when_theOnlyCallerQualifyingRoleIsAnAnyOnlyHolderAndTheNamedAdminIsZeroed_H1` — same scenario at the health-indicator layer; asserts DOWN where the pre-fix indicator would have reported UP.
- `AdminEquivalenceSqlJavaEquivalenceIT` (MC-I) fixture matrix rewritten: ANY-only fixtures (one or two of three dangerous permissions) now assert INVISIBLE (not UP/DOWN), and the DOWN fixture now requires all three permissions revoked — proving the shipped SQL and `RbacAdminEquivalence.isFullyAdminEquivalent` still agree exactly, post-re-scope.
- `RoleAssignmentServiceTest`'s `EdgeCase2` and every other lockout-adjacent unit test updated so "remaining holder" fixtures are caller-qualifying where the test asserts success, and the previously-cited `:1425` regression assertion no longer exists in that form.

**Full gate:** `./mvnw verify` (Docker up) — **1389 tests, 0 failures, 0 errors, 1 pre-existing skip, EXIT=0.**

Design docs updated to record the correction: `docs/features/US-017/03-design.md` (D5, §6.3's self-revocation proof, §7.2's pseudocode), `03b-threat-model.md` (new **RES-24**, closed same-day), `docs/features/US-012/monitoring.md` §3/§5, `docs/features/US-012/runbook.md` §2 and the RC-21 forensic-sweep SQL (both re-scoped from `OR EXISTS` (ANY) to `COUNT(DISTINCT) = 3` (ALL), so an operator's manual confirmation query agrees with what the shipped code now actually protects).

**M-1: FIXED, verified.** Independently re-verified against the code (confirmed `callerHoldsActiveAdminEquivalentRole` was called inside the `afterCommit` runnable, reading M4/M12 after the INSERT) before implementing the reviewer's own suggested fix (option 2: take the reads before the INSERT and carry the result into the post-commit runnable).

Implemented exactly as suggested:
- `RoleAssignmentService#assign()` now computes `callerWasAdminBeforeThisAssignment` immediately after the caller gate passes and before the duplicate-assignment check / INSERT, calling `callerHoldsActiveAdminEquivalentRole(actor)` at that point instead of inside the post-commit runnable.
- The post-commit runnable's `callerIsAdmin` now reuses that pre-computed value rather than re-reading M4/M12 after commit.
- MC-G is unaffected: the pre-insert read is still never used to authorize anything — the gate (M5b) has already made its decision by the time this runs; it only feeds the canary's metric/log signal.

**New regression coverage:** `RoleAssignmentServiceTest#should_readCanaryStateBeforeTheInsert_notAfter_when_selfAssigningATenantAdminRole_M1` — an `InOrder` proof that `findActiveAssignmentViews` is invoked before `assign()`'s INSERT, with a realistic "caller held nothing before this request" stub correctly producing `callerIsAdmin=false` even though a post-commit read of the same mock state would see the just-created `TENANT_ADMIN` row and (incorrectly) report `true`. The existing reachability test at `:912` (`should_tagCallerIsAdminFalse_when_gateAndCanaryDisagree`) required no change — its stubbed "caller holds nothing" state, previously synthetic/unreachable against a real post-commit read, is now the realistic pre-insert state the fix actually reads.

**Full gate:** unit suite green (107/107 in `RoleAssignmentServiceTest`, 0 failures); full Docker-backed `./mvnw verify` re-run after both H-1 and M-1 landed together.

Design docs updated: `docs/features/US-017/03-design.md` §9.3 (a fourth, timing-based failure mode amendment), `03b-threat-model.md` (new **RES-25**, closed same-day).

**L-3: FIXED, verified (2026-09-24, Phase 8 `/test-validate`).** The qa-engineer agent closed this during the test-coverage audit — added three HTTP-level cases to `RolePermissionSecurityIT.java`: a non-admin `role:write` holder gets 403 detaching a dangerous permission (row left intact), gets 403 (not 404) detaching a dangerous permission that was never attached (T-I14), and gets 204 detaching an ordinary (non-dangerous) permission. Full suite green afterward (see `docs/features/US-017/08-test-audit.md`).

**L-1 and L-2 remain open** — both are code-level findings with no test-only fix (a fixed error-message string, and moving an M7 read from mid-transaction to post-commit), correctly left to follow-up tasks per the reviewer's own instruction.
