# US-018 — STRIDE Threat Model: Harden RBAC for production readiness

_Output of Phase 3 Step B (`/security-review` in threat-model mode). **Gate 2 deliverable.** Adversarial STRIDE analysis of `03-design.md` (Status: Proposed, 2026-09-26) and ADRs 0021–0025 (all Proposed), organised per milestone so each milestone's PR can trace its own threats. Feeds `/breakdown` (Phase 4)._

**Epic:** EPIC-002 (RBAC Foundation) · **Story:** US-018 · **Reviewer:** Application Security Engineer · **Status:** **Conditional pass, not yet closed.** Two High findings and sixteen Medium findings require design changes (§7) before Gate 2 can close. No Blocker. Five of the changes are Architect decisions rather than edits.

No PII: people are referred to by role only.

---

## 0. Scope, verification basis, headline

### 0.1 Scope

Every milestone in `03-design.md`: M1 (A8), M2 (A1–A4), M3 (A5, D3), M4 (A6), M5 (A7), M6 (A11), M7/M7b (A9, A10), M8 (B1–B8), M9 (C1, C2, C3, C5, C6), M11 (D1, D2, D4, D5). ADRs 0021–0025. The binding Gate 1 decisions (`01-requirements.md` §14) are not reopened. Where a finding touches one of them (for example the time-boxed fail-open), the finding is about its *implementation*, not the decision.

### 0.2 Verification basis

**Rule applied:** trust a prior story's code citation unless `git log -- <path>` shows the file changed since. `git log` on `rbac/`, `identity/` and `src/main/resources` shows the last functional change is US-017 (`867c513`), and the design verifies at `3d8ec5f`, the same commit as HEAD. So US-016/017's verified facts stand. The items below are **new facts this story depends on**, each re-read this session.

| # | Claim under test | Verified at | Result |
|---|---|---|---|
| 1 | Anyone can self-register, and lands in a configured default tenant | `RegistrationController.java:54` (`@Value("${nexus.identity.default-tenant-id}")`), `:82`, `:130`; `RegisterUserUseCase.java:90-96` | **Confirmed.** Registration is anonymous (`permitAll`, `SecurityConfig.java:79-80`). **One attacker can hold two accounts in the default tenant.** This defeats R-2's "needs two principals" (T-E32) |
| 2 | The SPA sends the bearer header on `POST /auth/refresh` and `/auth/logout` | `auth.interceptor.ts:22` (`AUTH_PATHS`), `:104` (only the *proactive* block excludes auth paths), `:125-129` (standard attach: any same-origin API call, no auth-path exclusion) | **Confirmed.** The refresh and logout calls carry the current, possibly stale, access token |
| 3 | The JWT filter processes a bearer on every path, including `permitAll` ones | `JwtAuthenticationFilter.java:66-92` (no `shouldNotFilter`); `SecurityConfig.java:74` | **Confirmed.** Any `AuthenticationException` from the bearer calls the entry point and returns 401, even on `/auth/refresh`. Items 2 and 3 together give **T-D17** |
| 4 | Clock skew used in the epoch-key TTL formula | `AuthConstants.java:13` — `AUTH_CLOCK_SKEW_SECONDS = 0` | **Confirmed: 0.** "Token TTL + 2 × skew" = 900 s, which equals the permission-cache TTL (`application.yml:143`, 900). The margin is zero (T-E37) |
| 5 | The refresh family id is known before the use case runs | `LoginRateLimitFilter.java:200-209` (IP bucket only); `RefreshTokenUseCase.java:107` (family comes from `findByTokenHash`) | **Refuted.** The cookie is opaque; the family is DB-derived after lookup. An invalid token has no family (T-D19) |
| 6 | Each failed refresh writes an audit row | `RefreshTokenUseCase.java:99-110` (`TOKEN_REFRESH_FAILURE` via `recordEvent`, `REQUIRES_NEW`, `SecureEventService.java:52-55`) | **Confirmed.** It writes to the append-only `auth_events` on every invalid attempt. The per-IP bucket bounds unauthenticated audit-write amplification (T-D19) |
| 7 | The per-IP key source | `LoginRateLimitFilter.java:44-50`, `:111-112` (DF-1: `getRemoteAddr()` only; behind a proxy every user shares one bucket) | **Confirmed.** The design's NAT analysis (§9.7) assumes per-client IPs; in the proxied topology the bucket is platform-wide |
| 8 | `audit:read` gates an existing endpoint | `grep 'audit:read' src/main` → only the V5 seed (`V5__rbac_schema.sql:114`) | **Refuted.** No endpoint uses it. C3's premise, "`audit:read` already reads actor ids in `auth_events`", is false (T-I17) |
| 9 | Caller authority on the set-lock path is a live **locking** read today (T-E7) | `UserRoleAssignmentPort.java:94-108` (M5b: `FOR SHARE`, `FORCE INDEX (fk_user_roles_role)`, contained in M11's X region) | **Confirmed.** M3 replaces this with M13, a non-locking snapshot (T-E33) |
| 10 | Cross-tenant denials feed the denial throttle | `RoleAssignmentService.java:213-225` (the denial is recorded and thrown **before** `requireNotThrottled`); `:956` (only the privileged-denial funnel calls `recordThrottleDenialAndMaybeWarn`) | **Refuted: they do not.** B1 therefore changes no throttle accounting. It leaves cross-tenant probing bounded only by the endpoint (T-R13) |
| 11 | An async audit path already exists | `AuthEventRetryBuffer.java:36-41` (non-blocking `offer()`, `@Scheduled` drain); `JpaAuthEventAdapter.java:59` | **Confirmed.** B1's rejected alternative ("needs a new executor") is not accurate (T-R13) |
| 12 | `auth_events.tenant_id` accepts null (CLI refusal for an unknown user) | `V2__identity_schema.sql:79` | **Confirmed nullable** |
| 13 | Redis authentication and transport | `application.yml:48` (`REDIS_PASSWORD` defaults to blank); ADR-0016 D1 (AOF everysec, Sentinel; **no** auth, ACL or TLS decision) | **Confirmed gap.** Redis write access already equals permission injection at mint (permset cache). A9 adds revocation suppression (T-T16) |
| 14 | Redis version (`TIME` inside a writing Lua script) | `docker-compose.yml:44`, `TestcontainersConfiguration.java:95` — `redis:7.4-alpine` | **Safe.** Redis 7 always uses effects replication |
| 15 | `sub` is validated as a UUID | `JwtRs256Service.java:124-150` | **Refuted.** It is null-checked only. A11 fixes `tenant_id` but not `sub` (T-S10) |
| 16 | Locking-read privilege on MySQL 8.4 | `docs/features/US-016/02-impact.md:137`, `US-015/02-impact.md:252` (`SELECT` plus one of `DELETE`, `LOCK TABLES` or `UPDATE`) | **Project record.** `roles` is `SELECT, INSERT` for `nexus_app` today. C1's "code first, then grants" order puts `FOR SHARE` on `roles` into production before any `UPDATE` grant exists (T-T18) |
| 17 | `RoleResolutionService` fingerprints on role names only | `RoleResolutionService.java:57-67` | **Confirmed** (the impact analysis re-trace holds) |
| 18 | Dependency manifests | `git status -- '*pom.xml' '*package.json' '*package-lock.json'` → empty; `./mvnw -o dependency:tree` ran (Spring Boot 4.1.1, Tomcat 11.0.26, BC 1.86, jjwt 0.12.6, Lettuce 7.5.2, mysql-connector-j 9.7.0) | **No delta; no new dependency** in the design. The Phase 7 code audit re-runs the CVE check on the final tree |
| 19 | `npm audit` (frontend) | Run this session | **27 pre-existing findings (1 critical, 7 high, 16 moderate, 3 low)**, identical to the US-017 baseline and all in the build and toolchain graph. **Not attributable to US-018.** M8/M9 add no frontend dependency |

### 0.3 Headline

**This is the best-structured design in the epic, and most of its core calls are right.** Grant-subset by permission id; the "throttle before new reads" ordering; `requiredPermission` never naming the missing permission; mint reading the epoch before the permissions; the epoch-keyed cache as the fix for the evict-then-repopulate race; the 503-not-401 end state; accepting token version N+1 one release ahead; and A7 never calling `assign()`. I attacked each of these directly and each survived (§3, Low items marked ✅).

**What does not survive, in order of consequence:**

1. **R-2 is not a two-principal threat** (**T-E32, High**). Self-registration is anonymous and lands in the default tenant. One attacker registers a second account, uses `user:role:assign` to give it a benign role, and waits for an administrator to escalate the role. **RES-1(b)'s primitive survives A4 with one extra step.** The design must not report RES-1(b) as closed in the EPIC-002 tracking.
2. **The M7 epoch check and the degraded 503 fire on `/auth/refresh` itself** (**T-D17, High**). The SPA attaches the stale bearer to the refresh call, and the filter rejects any bearer on any path. So every revoke or detach logs affected holders out instead of refreshing them. Degraded-closed blocks refresh for everyone. A logout carrying a stale bearer skips the server-side revocation of the refresh-token family. The design's storm analysis, the NAT merge gate and "login and refresh unaffected" all rest on the opposite assumption.
3. **"One definition of administrator" is two definitions** (**T-E34**). Revoke-subset, role-subset and A2 test the **union** of a caller's roles. A4, the lockout, the health indicator and A7 test **per role**. The sentence that justifies retiring T-E17 is false by §2.1's own words. Retiring D13 opens a **non-self** path to a tenant with zero administrators, which ledger row 19 calls "stays detective".
4. **M3 regresses T-E7** (**T-E33**). On the set-lock path the caller's authority comes from a snapshot that can predate the lock wait. A compromised administrator can race their own revocation, which the shipped M5b containment prevents.
5. **Four A9 correctness gaps**, each Medium:
   - **Zero TTL margin (T-E37).** The epoch-key TTL has no margin because skew is 0, and it ignores the cache TTL.
   - **Lost bumps are never replayed (T-E38).** This also makes the degraded-closed 503 buy almost no protection.
   - **The degraded-state machine is too sensitive (T-D20).** One blip trips it, and flapping or restarts reset the window.
   - **The refresh-limit split does not work as specified (T-D19).** The per-family bucket cannot be built where the design puts it, and the per-IP loosening multiplies unauthenticated audit writes tenfold.
6. **The catalogue coupling cascades further than §2.1 states** (**T-E35**). Under A3, "an administrator attaches the new permission" is impossible when no administrator holds it. Tenants with custom-only administrators and no seeded `TENANT_ADMIN` become permanently unrecoverable and invisible to the indicator.
7. **Retiring the canary re-creates T-E29 one layer up** (**T-E36**). A2, A3, A4, revoke-subset and role-subset now share one read (M13). Nothing independent notices an over-broad M13.

**Verdict:** conditional pass. Gate 2 can close once RC-23 to RC-38 are folded in (§7). RC-39 and RC-40 can land as tasks. **No Blocker.** None of the findings overturns a Gate 1 decision.

### 0.4 Attestation (auth, crypto and PII are never approved silently)

- **Authentication — reviewed in depth; findings T-D17, T-S10, T-E37, T-E38, T-D19, T-D20.**
  - Sound: A11's version-set check, the `tenant_id` validation, and v2-as-epoch-0.
  - Not approved as written:
    - freshness checks on public paths (T-D17);
    - the key-TTL formula (T-E37);
    - lost-bump handling (T-E38);
    - the refresh-limit split (T-D19).
- **Authorization — reviewed in depth; the story's core.** Covered by T-E32 to T-E36, T-T17, T-T18 and T-I17. The ledger is verified row by row in §5.
  - Confirmed sound:
    - id-based grant-subset;
    - A3 on every permission, which closes RES-13;
    - the precedence order and single audit row;
    - the non-oracle `requiredPermission`;
    - EC2 resolved structurally;
    - a union-holder cannot convert into an escalation (T-E41).
  - Not approved:
    - the two-definition inconsistency (T-E34);
    - the T-E7 regression (T-E33);
    - the RES-1(b) closure claim (T-E32).
- **Cryptography — reviewed. No findings.** No key material, algorithm or randomness source changes. The epoch value is Redis server time (a monotonic counter, not a secret). The `REFRESH_FAMILY` bucket hashes a non-secret UUID only to keep it out of logs. The design must name the key, or use a plain SHA-256; this is noted in RC-32 as a detail, not a crypto finding. RS256 and the explicit algorithm assertion are unchanged (`JwtRs256Service.java:117-120`).
- **PII — reviewed against the organisation's no-PII rule. No new exposure.** Every new log field, audit metadata field, metric tag and response field is a UUID, a count, a bounded enum or a role/permission name. That covers `RBAC_ATTACH_EXCEEDS_CALLER`, `RBAC_BREAK_GLASS_USED`, `ROLE_BREAK_GLASS_GRANT`, `ROLE_UPDATED`, the C3 responses and `REFRESH_FAMILY`. `ROLE_UPDATED` correctly omits the description text. `changeRef` is pattern-validated; RC-37 asks the pattern to exclude free text so an operator cannot paste a name into it. C3 returns ids only. **Log injection: closed, inherited** (role names keep US-015 D6's CR/LF-excluding allow-list and the structured encoder).
- **Secrets — reviewed; one finding.** Redis credentials default to blank (T-T16). The CLI uses `nexus_app` credentials already present in the runtime secret, and no new secret is introduced.

### 0.5 Numbering

The epic sequence continues. US-017 ended at T-S8, T-T15, T-R12, T-I16, T-D16, T-E31, RC-22 and RES-25. **US-018 starts at T-S9, T-T16, T-R13, T-I17, T-D17, T-E32, RC-23 and RES-26.** The design's own R-1, R-2 and R-3 are cross-referenced to the RES ids here.

---

## 1. Trust boundaries and data flow (what US-018 adds or changes)

```
[ Internet: anonymous client (can self-register into the DEFAULT tenant — §0.2 #1) ]
[ Authenticated tenant member: valid RS256 token, permissions[] up to 900 s stale      ]
      |  POST/DELETE /users/{id}/roles   (M2: user:role:assign)
      |  POST/DELETE /roles/{id}/permissions (M2: A3; M3: role-subset)
      |  PATCH/DELETE /roles/{id} (M9 C1)   GET access-review x3 (M9 C3, audit:read)
      |  POST /auth/refresh, /auth/logout  ** SPA ATTACHES THE BEARER HERE (§0.2 #2) **
      v
=== TB1 network -> app ============================================================
  LoginRateLimitFilter: REFRESH_IP (M7: 30 -> 300/60 s; key = getRemoteAddr, DF-1)
  JwtAuthenticationFilter: verify (M6: version set, tenant_id) -> M7: EPOCH CHECK
     ** runs for ANY bearer on ANY path, incl. /auth/refresh (T-D17) **
     -> Redis GET epoch (50 ms, per-instance degraded state machine; T-D20)
=== TB2 Redis (authorization-relevant from M7) ====================================
  nexus:rbac:epoch:{t}:{u}      <- a DEL suppresses revocation (T-T16)
  nexus:rbac:permset:{t}:{u}:{e} <- a write injects permissions at mint (pre-existing; T-T16)
  REDIS_PASSWORD defaults to blank; no ACL or TLS decision (§0.2 #13)
=== TB3 method security ============================================================
  @RequiresPermission (flat JWT claim)  | M1: @PublicEndpoint / @AuthenticatedEndpoint markers
=== TB4 application ================================================================
  RoleAssignmentService.assign/revoke
     tenant 404s -> throttle (M8: classification M14+M15 moves BEFORE it) ->
     [admin-defining target: M10' -> M11 set lock (X)]  <- the lock wait can outlast the snapshot
     M13 SNAPSHOT (caller holdings; feeds A2, A4, revoke-subset)  <- T-E33, T-E36
     A4 (per-role "administrator") / A2, revoke-subset (UNION)    <- T-E34
     INSERT/UPDATE -> M4: audit in-transaction (MANDATORY + flush)
     after commit: evict; M7: epoch bump (revoke); lost bump = never replayed (T-E38)
  RoleManagementService.attach (A3, M13) / detach (M3 role-subset, UNION; no lock) ->
     after commit: holders read -> Lua fan-out (bump + DEL permset:{old})
  RoleManagementService.update/delete (M9) ** no role-subset (T-T17) **
  AccessReviewController (M9) ** first live use of audit:read (T-I17) **
=== TB5 MySQL as nexus_app =========================================================
  roles: SELECT, INSERT (+ M9 column UPDATE)  <- FOR SHARE before the grant (T-T18)
  auth_events: INSERT, SELECT (append-only)   <- refresh-failure rows x10 per IP (T-D19),
                                                  B8 unthrottled denials (T-D18)
=== TB6 non-HTTP privileged entry (M5) =============================================
  kubectl/Job -> jar --spring.profiles.active=break-glass (nexus_app, Flyway off)
     trust = infra access; operator attribution = --change-ref (T-S9, T-R14)
     alert = ERROR log from a seconds-lived pod (T-R15)
=== TB7 migrations =================================================================
  V6 (seed + B7 footer): the catalogue grows -> custom admin roles demoted (T-E35)
  V7 (composite FK, COPY): half-applied on a data mismatch (T-D21)
  V8/V9 (soft delete)
```

---

## 2. STRIDE tables, per milestone

Legend: ✅ addressed as designed · ⚠️ partially addressed, gap · ❌ change required · n/a.

### M1 — A8 deny-by-default (markers, ArchUnit, anonymous-401 test)

| | Threat | Verdict |
|---|---|---|
| **S** | An anonymous caller reaches a non-public handler through `permitAll` drift | ✅ The runtime `EndpointClassificationWebTest` catches drift in both directions. This is better than comparing two string lists |
| **T** | A handler ships unclassified | ✅ ArchUnit rule "exactly one marker". Note the self-invocation rule covers only same-class calls |
| **R** | — | n/a |
| **I** | An `@AuthenticatedEndpoint` handler returns another user's data (IDOR, OWASP A01) | ⚠️ **T-E39 (Low).** "Own data only" is a review convention with no mechanical check. A cheap ArchUnit rule is available |
| **D** | — | n/a |
| **E** | The drift test silently skips the RBAC controllers | ⚠️ **T-E39 (Low).** They are `@ConditionalOnProperty` (flag-gated), so the test context must enable every flag. A public handler legitimately returns 401 (`/auth/refresh` without a cookie gives AUTH_004), so asserting on status alone will produce false failures. That invites an exclusion list, which is the drift the test exists to prevent |

### M2 — A1–A4 grant-subset core

| | Threat | Verdict |
|---|---|---|
| **S** | Caller holdings taken from the JWT | ✅ M13 is a live DB read, named for authorization. MC-2 keeps M12 off decision paths |
| **T** | Holdings change between read and write (R-1) | ⚠️ On M2 paths without a lock, the window is milliseconds: accepted (RES-27). **On the set-lock path the window includes the lock wait** (T-E33, which bites from M3, when the legacy M5b goes) |
| **R** | A4 and A2 denials leave no record | ✅ One `ROLE_ASSIGNMENT_DENIED` row per request, first reason, `REQUIRES_NEW`. A3 gets WARN plus metric with ≥ 1-year retention (consistent with US-015 AC11) |
| **I** | 403 reveals role contents | ✅ `requiredPermission` is always the endpoint permission. The audit carries a **count** of missing ids, not the ids. The throttle runs before the new reads (EC8, until M8; see T-I18) |
| **I** | A3 existence oracle (409 `RBAC_005` before 403) | ✅ A3 runs before the duplicate check |
| **D** | Two added reads on every assign | ✅ Indexed, admin-only, budget < 10 ms p95 |
| **E** | **Self pre-positioning (RES-1(b)) via a second account** | ❌ **T-E32 (High)** |
| **E** | A union-holder uses a colluder to become an "administrator" | ✅ **T-E41 (Low), attacked and survived.** A union-holder already holds everything; the A4 exemption adds nothing |
| **E** | The A1 rollout lets `user:write`-only holders assign through old instances | ✅ **T-E42 (Low).** Minutes-long overlap, parent flag off in production |
| **E** | RES-13: the attach gate is name-based | ✅ **Closed by A3** (every permission, id-based). The name-based detach gate survives until M3 (role-subset). See §4 |

### M3 — A5 retirement (ledger verified row by row in §5)

| | Threat | Verdict |
|---|---|---|
| **S** | Caller authority on the set-lock path comes from a stale snapshot (T-E7 regression) | ❌ **T-E33 (Medium)** |
| **T** | A non-administrator demotes an admin-defining role, leaving zero administrators | ❌ **T-E34 (Medium).** A union-holder passes role-subset. Row 19's case is newly reachable, not "stays" |
| **R** | Canary retired; the counter cannot tell a bypass from legitimate use | ❌ **T-E36 (Medium)** |
| **I** | `listActive` redaction redefined as "administrator" | ✅ A stated, small widening. **But** C3 bypasses it (T-I17) |
| **D** | Lock set re-scoped | ✅ ADR-0018 D5–D7 upheld. Harness C (with its benign thread) is the exit gate |
| **E** | Revoke-subset replaces T-E17 | ⚠️ **T-E34.** Sound against callers who do not hold the whole catalogue. The written justification is false for union-holders |
| **E** | Catalogue growth demotes custom admin roles | ❌ **T-E35 (Medium)** |

### M4 — A6 atomic audit

| | Threat | Verdict |
|---|---|---|
| **S** | — | n/a |
| **T** | A mutation commits without its audit row | ✅ `MANDATORY`, `saveAndFlush`, retry buffer bypassed, propagate, rollback, 500. TS-5 proves it with a DB trigger |
| **R** | Denial events lose their survive-rollback property | ✅ **Confirmed:** Group B `recordRoleAssignmentDenied` keeps `REQUIRES_NEW`, never throws, may buffer. That is ADR-0009 and FR-A6.c, unchanged (`SecureEventService.java:52-55`) |
| **I** | 500 body leaks detail | ✅ Generic `INTERNAL_ERROR`; ids in the ERROR log only |
| **D** | An audit outage blocks RBAC writes, including break-glass | ✅ **T-D22 (Low), accepted.** Same database. Add an ordering rule (no Group B write after a Group A write in one transaction) |
| **E** | — | n/a |

### M5 — A7 break-glass CLI

| | Threat | Verdict |
|---|---|---|
| **S** | A requester impersonates a tenant's owner to get admin granted to an attacker-registered account | ❌ **T-S9 (Medium)** |
| **S** | An old `--change-ref` is replayed after the tenant falls to zero again | ❌ **T-S9** |
| **T** | The CLI mutates a schema, or runs against a mismatched schema | ✅ Flyway off, `ddl-auto=validate`. Same image as the service |
| **R** | Operator attribution depends on an infra audit log the design does not require | ❌ **T-R14 (Medium)** |
| **R** | The page never fires (short-lived pod, log not shipped) | ❌ **T-R15 (Medium)** |
| **I** | The operator's identity is linked into tenant data | ✅ Correctly avoided (`assigned_by = target`) |
| **D** | The `break-glass` profile is activated in a serving pod | ⚠️ Folded into RC-37: the runner must refuse unless the web application type is `none` |
| **E** | Break-glass becomes a general backdoor | ✅ Zero-admin precondition under the set lock; a re-run refuses. **But** after T-E35's demotion, tenants with live custom administrators satisfy "zero administrators" |
| **E** | REST reaches `BootstrapAdminService` | ✅ ArchUnit containment plus profile gating |

### M6 — A11 claim validation

| | Threat | Verdict |
|---|---|---|
| **S** | A token with a missing `tenant_id` produces a 500 (NPE) | ✅ `verify()` rejects it with 401 (closes `JwtAuthenticationFilter.java:80-84`) |
| **S** | A non-UUID `sub` produces a 500 on the RBAC and M7 paths | ⚠️ **T-S10 (Low)** |
| **T** | v3 accepted before its shape is frozen | ⚠️ **T-S10.** Safe today (only our key mints tokens). Freeze v3 = v2 ∪ {`perm_epoch`} at M6 merge |
| **R/I** | Rejection logging floods | ✅ DEBUG plus a bounded `reason` tag |
| **D** | A mixed-version rollout ping-pongs sessions | ✅ The {2,3} set is the right expand/contract shape |
| **E** | — | n/a |

### M7/M7b — A9 epoch, A10 fan-out, refresh limit

| | Threat | Verdict |
|---|---|---|
| **S** | Stale permissions accepted under a fresh epoch | ✅ Mint reads the epoch before the permissions (MC-7a); bumps happen after commit (MC-7b); the cache is keyed by epoch |
| **T** | The epoch-key TTL lets a stale cache entry outlive the key | ❌ **T-E37 (Medium)** |
| **T** | Redis write access suppresses revocation or injects permissions | ❌ **T-T16 (Medium)** |
| **R** | A lost bump is silent to the admin who revoked | ❌ **T-E38 (Medium)** |
| **I** | — | n/a |
| **D** | **The epoch check and the degraded 503 hit `/auth/refresh` and `/auth/logout`** | ❌ **T-D17 (High)** |
| **D** | The degraded-state machine trips on one blip; flapping or restarts reset the box; a Redis outage becomes a platform-wide 503 | ❌ **T-D20 (Medium)** |
| **D** | The refresh-limit loosening | ❌ **T-D19 (Medium)** |
| **D** | Fan-out is unbounded and synchronous | ✅ **T-D23 (Low).** Admin-only; a cap would be fail-open |
| **E** | Attach does not bump; v2 treated as epoch 0; M6 accepts v3 | ✅ **T-E40 (Low), attacked and survived** |
| **E** | Lost bumps are never replayed after Redis recovers | ❌ **T-E38** |

### M8 — Group B

| | Threat | Verdict |
|---|---|---|
| **S** | B2: a cross-tenant `user_roles` row | ✅ The composite FK makes it impossible at the DB. It does **not** cover T-I16's user-tenant axis (optional, RC-40) |
| **T** | B7 footer omitted from a permission migration | ⚠️ **T-T19 (Low).** The scanner must be case- and variant-insensitive |
| **R** | B1 drops the durable cross-tenant row | ⚠️ **T-R13 (Low).** Conditionally acceptable; a better alternative exists |
| **I** | B1 timing oracle | ✅ Removed |
| **I** | B8 throttle reveals the admin-defining bit (EC8); classification now precedes the throttle | ✅ **T-I18 (Low).** Accepted, but §4.4 must be updated |
| **I** | B3 `tenantId` metric tags | ✅ Removed; MC-8 guards it. Tenant ids no longer reach whoever can read Prometheus |
| **D** | B8 unthrottled denial audit writes | ❌ **T-D18 (Medium)** |
| **D** | B2 V7 half-applied on a data mismatch; COPY blocks writes | ⚠️ **T-D21 (Low)** |
| **E** | B5 frontend guard stays fail-open | ✅ The route-table spec compensates. The backend is the authority (RES-39) |
| **E** | B8 per-JVM throttle state (RES-11) | ✅ Closed by the Redis-native adapter and `require-shared-store`, **conditional on** the production runbook setting it |

### M9 — Group C

| | Threat | Verdict |
|---|---|---|
| **S** | — | n/a |
| **T** | PATCH/DELETE on roles beyond the caller's authority (rename an admin role to look benign) | ❌ **T-T17 (Medium)** |
| **T** | A soft-deleted role keeps or gains an active holder; `FOR SHARE` fails under the grants in force | ❌ **T-T18 (Medium)** |
| **R** | Access-review reads are not audited durably | ✅ INFO plus metric is proportionate. SOC 2 evidence is the review itself |
| **I** | C3 enumerates the administrator roster to every `audit:read` holder; unredacted `assignedBy` bypasses row 16 | ❌ **T-I17 (Medium)** |
| **D** | C2 unbounded page size | ✅ `size > 100` gives 400 |
| **E** | C5 default role | ✅ None, pinned by `RegistrationIT` |
| **E** | C6 frontend redirect | ✅ **T-I19 (Low).** Fixed route; UX only; not an authorization control |

### M11 — Group D

| | Threat | Verdict |
|---|---|---|
| **R** | Stale ADR claims (the `jti` denylist "implemented") mislead operators | ✅ Corrected by dated amendment notes. This is itself a security fix: the false claim would lead an incident responder to believe logout revokes access tokens |

---

## 3. Identified threats

Format per entry: attack · existing mitigation · required mitigation (RC) · residual.

### T-E32 — R-2 is a one-attacker path: the RES-1(b) primitive survives A4 via a second account · **High** · ❌

**Attack (verified end to end against the design and §0.2 #1):**
1. The attacker holds `user:role:assign` (and some benign permissions). From an anonymous browser they self-register a second account in the default tenant. That needs only `permitAll` register plus email verification with a second mailbox.
2. `POST /users/{sockPuppet}/roles {B}`, where B is any role whose permissions ⊆ the attacker's. A4 does not fire (not self). A2 passes. 201.
3. Weeks later an administrator attaches permissions to B for a legitimate reason. A3 passes, because the administrator holds them. The sock puppet's holdings grow on its next request (from M7 its epoch is untouched by an attach, so its next mint picks them up) or on its next refresh.
4. If B became admin-defining, the sock puppet is an administrator. It now assigns anything to the attacker's main account (A2 passes, not self).

**What changes versus the design's R-2:** "needs two principals" and "a *different* threat from RES-1(b)" are both false where self-registration is open. A4 adds one registration step to RES-1(b); it does not remove the primitive. The success metric in `01-requirements.md` §13 ("fully closed — not mitigated") cannot be met by A4 alone.

**Existing mitigation:** the M3 `role_became_admin_defining{holders}` page covers only the admin-defining payoff. Partial escalations (B gaining `role:write` or `user:role:assign`) are not signalled.

**Required: RC-23.** Restate the closure, record R-2 as RES-26 inheriting RES-1(b)'s ownership and expiry, add an attach-time provenance signal, and put the preventive provenance rule to the Architect.

**Residual:** High if only the restatement lands. Medium with RC-23.2. Low with RC-23.3.

### T-D17 — The epoch check and the degraded 503 fire on `/auth/refresh` and `/auth/logout` · **High** · ❌

**Mechanism.** The SPA attaches `Authorization: Bearer <current token>` to every same-origin API call, including the refresh and logout POSTs (`auth.interceptor.ts:125-129`; only the proactive block, `:104`, excludes auth paths). The filter verifies any bearer on any path and calls the entry point on failure (`JwtAuthenticationFilter.java:66-92`). M7 adds two rejection causes to that filter.

**Consequences:**
- **Every revoke and detach logs the affected holders out.** Holder request → 401 stale → reactive refresh → the refresh POST carries the **same stale bearer** → 401 at the filter → the refresh `catchError` clears the session (`auth.interceptor.ts:150-154`). TS-8/TS-9 will pass in a backend IT that calls refresh without a bearer, and fail in production.
- **Degraded-closed blocks refresh for everyone.** The refresh POST with a (still valid) bearer gets 503, the refresh `catchError` fires, and the session is cleared. §9.5's "keeps sessions intact" is false.
- **Logout with a stale bearer never reaches the controller.** The server-side revocation of the refresh-token family is skipped, and the cookie survives server-side after a user believes they logged out.
- **Pre-existing, same root cause:** a reactive refresh after *expiry* carries an expired bearer and is rejected. Fixing the root cause fixes both.

**Required: RC-24.** **Residual:** none once fixed and pinned by an IT.

### T-E33 — M3 regresses T-E7: caller authority on the set-lock path comes from a pre-lock snapshot · **Medium** · ❌

InnoDB `REPEATABLE READ` creates the read view at the transaction's **first consistent read**. That is the tenant 404 checks, well before M11. If `assign`/`revoke` then waits on M11 (up to `innodb_lock_wait_timeout`), M13 reads **as of before the wait**.

**Race.** Security revokes compromised administrator X, which is an admin-defining target, so it takes the set lock. X concurrently assigns `TENANT_ADMIN` to a sock puppet, or revokes another administrator. X's transaction waits on M11, acquires it after Security commits, and M13's snapshot still shows X as an administrator: A4 and A2 pass. **The revocation is raced.** US-017's M5b is a `FOR SHARE` read contained in M11's X region with `FORCE INDEX (fk_user_roles_role)` (`UserRoleAssignmentPort.java:94-108`), and it prevents exactly this. ADR-0021's objection ("a locking read on the caller's rows would be a new acquisition outside the set-lock region") holds for a read driven by `fk_user_roles_user`. It does not hold for the contained form, and on the set-lock path M11's own result already contains the caller's current, locked admin-defining rows.

**Required: RC-25.** **Residual:** R-1 on unlocked paths, milliseconds (RES-27, Low).

### T-E34 — "One definition of administrator" is two; a non-administrator can zero a tenant's administrators · **Medium** · ❌

- §2.1: "A user holding everything through two partial roles is *not* an administrator."
- §5.1 row 2 / ADR-0021 D5: "A non-administrator cannot hold all of an admin-defining role's permissions, so T-E17 stays closed." **That sentence contradicts §2.1.**

A union-holder U is a non-administrator who passes revoke-subset on `TENANT_ADMIN`, and role-subset on any custom admin-defining role.

- **Revoke:** U can strip administrators down to the last one (the lockout blocks the last). Within U's permissions, but not what the ledger claims.
- **Detach (the new path).** In a tenant whose administrators hold only custom admin-defining roles (or whose `TENANT_ADMIN` has no holders), U detaches one permission from each admin-defining role → **zero administrators**.
  - The lockout guards revoke only.
  - Row 19 files this as "an admin detaching from the only admin-defining custom role they hold... stays detective (ADR-0018 D8)".
  - Under US-017, D13 required a **literal `TENANT_ADMIN`**, who by construction remained an administrator, so the case was unreachable. **Retiring D13 opens it, for self and non-self callers alike.** "Stays" is wrong.

**Required: RC-26.** **Residual:** a race-only path (RES-28, Low).

### T-E35 — Catalogue coupling cascades through A4, the lockout, A7 and the indicator, and can be unrecoverable · **Medium** · ❌

A permission-adding migration demotes every custom admin-defining role. Consequences the design does not state:

| Effect | Consequence |
|---|---|
| Recovery path in §4.8 | "An administrator attaching `user:role:assign`": **A3 requires the attacher to hold it.** In a tenant whose administrators were custom-only, nobody holds the new permission. The only recovery is break-glass |
| A7 | Tenants with **live, working** custom administrators now satisfy "zero administrators", so the CLI becomes eligible there after every permission migration. Social-engineering exposure (T-S9) rises with each one |
| Tenants without a seeded `TENANT_ADMIN` (today every tenant except the bootstrap one, impact §5.1 #2) | The CLI refuses (Decision 11), and nobody holds the new permission. **Permanently unrecoverable until Epic 3.** The indicator is blind (no admin-defining role at all: RES-14) |
| Lockout | The protected population silently shrinks to `TENANT_ADMIN` holders |

**Required: RC-27.** **Residual:** RES-29.

### T-E36 — Retiring the canary re-creates T-E29: one read (M13) now feeds five decisions, and nothing independent watches it · **Medium** · ❌

M13 feeds A2, A3, A4, revoke-subset and role-subset, deliberately from **one** read (§4.4). An over-broad M13 fails open on all five together. Examples: a dropped `r.tenantId = ur.tenantId`, a join fan-out, or a future `LEFT JOIN`.

- US-016's M-2 and US-017's T-E29/RC-17 established that unit tests are not a substitute for an independent runtime derivation.
- Row 7's replacements are A4 itself (the thing being checked), a `ROLE_ASSIGNED` row where actor = target (a record, not a detector), and an untagged counter with a ticket on increase.
- **After A4, every successful self-assignment is by an administrator, so that ticket fires only on legitimate activity: pure noise.**

**Required: RC-28.** **Residual:** a shared combinator in `RbacAdministrators` under the 0.90 domain gate (RES-42, Low).

### T-E37 — The epoch-key TTL margin is zero and ignores the cache TTL; the §9.4 race fix fails open at key expiry · **Medium** · ❌

Key TTL = 900 + 2 × 0 = 900 s = permission-cache TTL. Consider a **first-ever bump** for user H (old epoch = 0):
1. A racing mint writes the stale set under `permset:…:0` at time t_b + δ, where δ is the mint's epoch-read-to-cache-write latency.
2. That entry expires at t_b + δ + 900. The epoch key expires at t_b + 900.
3. In the gap of δ seconds, mints read epoch 0, **hit the stale `:0` entry** and issue a token with the revoked permission, epoch 0, current 0 → FRESH, valid 900 s.

δ is milliseconds normally, but seconds under DB load. If an operator raises `NEXUS_RBAC_PERMISSION_CACHE_TTL_SECONDS` above the token TTL, the gap becomes (cache TTL − 900) seconds for **every** first-bump user.

**Required: RC-29.** **Residual:** none once fixed.

### T-E38 — Lost bumps are never replayed; this also empties the degraded-closed 503 of most of its value · **Medium** · ❌

A post-commit bump that fails is lost for good. After Redis recovers, the revoked holder's token (up to 900 s) is accepted and its cache entry (up to 900 s, not evicted) re-mints the revoked permission on refresh: **about 30 minutes of exposure while Redis is healthy.** The admin who revoked got 204 and has no way to know. In incident response that is the worst case: "access cut" is reported while it is not.

The same fact undercuts §9.5. A revoke during an outage is lost. Degraded-closed then 503s everyone, but the moment Redis returns, the lost bump is still not applied and the stale token is accepted again. **Without replay, the 503 end state buys almost no revocation guarantee; it buys availability loss.**

**Required: RC-30.** **Residual:** replay lost on instance restart; bumps lost to async replication at Sentinel failover are silent (RES-31, Low).

### T-D20 — The degraded-state machine: one blip trips it, flapping and restarts reset it, and a Redis outage becomes a platform-wide 503 · **Medium** · ❌

1. **"Epoch read fails or exceeds 50 ms" moves the whole instance to degraded-open.** A single JVM pause during the call counts. The page therefore fires on benign blips; §9.5 says "page on entry" while §9.9 says "page if open > 0 for 1 min". Page noise trains operators to ignore the one page that matters.
2. **t0 clears on one successful probe,** so a flapping Redis restarts the 15-minute box indefinitely. **Pod restarts** (crash, autoscale, and the runbook's own "raise window + rolling restart") also reset it: new pods start Healthy.
3. **Can an attacker force an outage to extend fail-open?** Redis is internal. Externally the realistic lever is saturating Redis through the unauthenticated rate-limited endpoints when `store-type=redis`, which is hard at the scale needed. More important: **extending fail-open does not extend per-revocation exposure beyond T-E38's bound** (token TTL plus cache TTL). The larger risk runs the other way: an induced or organic Redis outage longer than 15 minutes becomes a **platform-wide authenticated 503**. That is an availability amplification the design should own explicitly.

**Required: RC-31.** **Residual:** RES-30.

### T-D19 — The refresh-limit split cannot be built as specified, and the per-IP loosening multiplies unauthenticated audit writes by 10 · **Medium** · ❌

- **The per-family bucket.** "Resolved from the refresh cookie, which the refresh use case already parses" is inaccurate: the cookie is opaque, and the family comes from `findByTokenHash` (`RefreshTokenUseCase.java:107`). `LoginRateLimitFilter` cannot compute it without a DB lookup. **Invalid or unknown tokens have no family**, so for the brute-force and theft-probing population the only bound is the per-IP bucket, now 300.
- **The cost of that population.** Each failed refresh writes `TOKEN_REFRESH_FAILURE` into the append-only `auth_events` via `REQUIRES_NEW`, a second connection (`:99-110`). Loosening 30 → 300 per IP raises unauthenticated, undeletable audit writes and pool pressure tenfold per source.
- **Brute force and reuse detection:** not weakened. The token is 256-bit, and reuse detection (`:114-121`) is independent of the limit. Correct as the design says, but the DoS bound matters, and it is not "still a bound" at the same order.
- **DF-1** (`LoginRateLimitFilter.java:44-50`): behind a proxy, `getRemoteAddr()` is the proxy, so the per-IP bucket is **platform-wide**. The §9.7 NAT analysis and its k6 gate model the wrong topology for that deployment shape.

**Required: RC-32.** **Residual:** RES-40 (Low).

### T-D18 — B8: unthrottled denial writes on non-admin-defining targets re-open US-016 T-D10 · **Medium** · ❌

A throttled actor's requests against non-admin-defining targets proceed to evaluation. Each denial writes a `REQUIRES_NEW` row on a second pooled connection, in an append-only table. The only bounds are possession of `user:role:assign` and request rate; the RBAC endpoints have no endpoint rate limit. This is the US-016 T-D10 shape that D14's throttle was built to close, re-opened for the benign population. It is also audit flooding: an attacker can bury their few meaningful denials in noise.

FR-B8.a asks only that **authorized** benign changes are not blocked. It does not require unthrottled denial *audit*.

**Required: RC-33.** **Residual:** the first N denials per window are recorded in full. Accepted.

### T-T16 — Redis is now authorization state, and its access control is undecided · **Medium** · ❌

Write access to Redis already equals **permission injection at mint**: write `permset:{t}:{u}:{e}`, refresh, receive those permissions. This is pre-existing (ADR-0016). A9 adds **revocation suppression** (DEL the epoch key) and a targeted DoS (set an epoch to `Long.MAX` and that user can never hold a fresh token). `REDIS_PASSWORD` defaults to blank (`application.yml:48`). ADR-0016 decides topology and persistence but not authentication, ACL or TLS.

**Required: RC-34.** **Residual:** RES-32 (Low after RC-34).

### T-T17 — C1 PATCH/DELETE are not bounded by the caller's authority · **Medium** · ❌

Any `role:write` holder can rename or delete **any** custom role, including admin-defining roles they could not detach from under role-subset.
- **Rename as tampering:** an attacker renames "Tenant Super Admin" to "Read Only". An administrator later assigns "Read Only" to someone, believing it benign. A2 passes because the administrator holds everything, and the assignee becomes an administrator. The role *name* is the label administrators decide on, and the Epic 3 UI will display it.
- **Delete:** removes an admin-defining custom role with no holders. That is configuration destruction by a caller outside the role's authority.

This is inconsistent with the grant-subset model the story adopts ("a caller may only modify within their own authority").

**Required: RC-35.** **Residual:** none.

### T-T18 — C1 soft delete: the lock order is sound, the lock privilege and rollout order are not · **Medium** · ❌

- **Lock order:** delete takes the role row X, then `user_roles` FOR UPDATE. Assign takes the role row S, then M11 and the INSERT. Revoke takes no role-row lock. **Both role-first; no cycle. Confirmed sound.** The FK child check on INSERT takes S on the parent, which is already held.
- **`FOR SHARE` on `roles` under the grants.** `roles` is `SELECT, INSERT` today. The project's recorded rule (§0.2 #16) is that a locking read needs `SELECT` plus one of `DELETE`, `LOCK TABLES` or `UPDATE`. The design's rollout (§11.1: "code first, then grants") puts the `FOR SHARE` assign into production **before** the column `UPDATE` grant exists, so assign fails as `nexus_app`. ITs connecting as a superuser would not notice (the US-016 D5 trap).
- **The `INSERT … SELECT … FROM roles WHERE … AND deleted_at IS NULL` fallback** needs no lock privilege. Under RR it takes the shared lock on the source row as part of the INSERT, and it inserts zero rows if the role was deleted, so it is *atomically* conditional. It should be the primary, not the fallback.
- **`@SQLRestriction` does not cover native queries** (M11, M5/M5b, the indicator SQL) and should not be relied on for to-one association loads. The primary control is the invariant "a deleted role has no active holders". `@SQLRestriction` is defense in depth, and the invariant needs a detector.

**Required: RC-36.** **Residual:** none once the invariant has a detector.

### T-S9 — A7: requester spoofing, and replay of an old approval · **Medium** · ❌

- The target user must only be ACTIVE in the tenant. Self-registration makes it trivial for an attacker to be one (§0.2 #1). The most realistic abuse is social: "our only admin left; please make my account admin." The tool trusts the operator; the design does not say what the operator must verify.
- `--change-ref` is pattern-validated only. A re-run after the tenant returns to zero administrators succeeds with the same, old reference.

**Required: RC-37.1, RC-37.2.** **Residual:** RES-35 (Low after RC-37).

### T-R14 — A7 attribution rests on an infra audit log the design does not require to exist · **Medium** · ❌

"The operator's identity lives in the infra access log (kubectl or SSH audit)." Kubernetes API audit logging is off by default in many clusters, and its retention is not stated. Without it, `--change-ref` joins to nothing. Also, `assigned_by = target` makes a break-glass grant indistinguishable from a self-assignment in `user_roles`, `listActive` and C3's holders unless the reader joins to `ROLE_BREAK_GLASS_GRANT`. An access reviewer (C3's SOC 2 purpose) will see a self-granted administrator.

**Required: RC-37.3, RC-37.5.**

### T-R15 — A7's page depends on log capture from a seconds-lived pod · **Medium** · ❌

A log-based alert is the right choice over a metric (the scrape argument is correct). But `kubectl run --rm` or a Job with a short TTL can remove the pod before a node-level shipper reads the container log. The durable row exists; the *page* may not.

**Required: RC-37.4.**

### T-I17 — C3 makes `audit:read` live for the first time and discloses the administrator roster; unredacted `assignedBy` bypasses row 16 · **Medium** · ❌

- **The premise is false** (§0.2 #8). No endpoint exposes `auth_events`, so "`audit:read` already reads actor ids" is not true today.
- **What C3 discloses.** Holders of admin-defining roles, meaning a ready targeting list for phishing and account takeover, and who granted what to whom. This is the same field row 16 redacts in `listActive` unless the caller is an administrator. Two rules for one field.
- **Who can get `audit:read`.** It is a non-admin permission. Under A2/A3, any holder of it with `user:role:assign` or `role:write` can propagate it.
- The ids-only responses are correct and necessary.

**Required: RC-38.** **Residual:** RES-37 (Low).

### Low findings

| ID | Finding | Required |
|---|---|---|
| **T-S10** | `sub` is not UUID-validated (`JwtRs256Service.java:124-150`), and M7's filter will parse it for the epoch lookup. Separately, v3's shape is not frozen when M6 starts accepting it; an M6 instance would accept a future v3 variant without validating it | RC-40.1 |
| **T-T19** | The B7 scanner looks for the literal `INSERT INTO permissions`. `insert into`, `INSERT IGNORE INTO`, backticked names or `REPLACE INTO` would bypass it | RC-40.3 |
| **T-R13** | B1 moves the cross-tenant evidence from an append-only DB row to a WARN log. The oracle it removes is low-value (UUIDv7 ids carry 74 random bits), and the evidence it drops is an IDOR-probing record (OWASP A01, A09). The existing `AuthEventRetryBuffer` (non-blocking `offer()`, scheduled drain, §0.2 #11) could keep the row off the request thread without a new executor | RC-39 |
| **T-I18** | From M8, M14 and M15 run **before** the throttle, contradicting §4.4's EC8 statement. The one-bit disclosure (target is admin-defining) is accepted; the document must say it | RC-33.2 |
| **T-I19** | C6: fixed route, no server data in the URL, UX only. ✅ Keep it free of query parameters (no `returnUrl`: open-redirect class) | RC-40.7 |
| **T-D21** | V7: MySQL DDL is not transactional. On a data mismatch the UNIQUE statement applies and the FK statement fails, leaving Flyway in a failed state that blocks every new instance until a manual repair. The COPY algorithm also blocks writes to `user_roles` (assign, revoke, break-glass) | RC-40.4 |
| **T-D22** | A6's coupling is accepted. Pin the ordering rule "no Group B write after a Group A write in one transaction", so a `REQUIRES_NEW` insert never waits on its own outer transaction's audit-row locks | RC-40.5 |
| **T-D23** | A10's fan-out runs on the request thread with no cap. It is admin-only, and a cap would be a silent fail-open. ✅ Accepted as designed |  — |
| **T-E39** | A8's runtime test: flag-gated controllers must be enabled; assert the entry-point 401 (AUTH_003 from `jwtAuthenticationEntryPoint`), not the status alone; the `@AuthenticatedEndpoint` own-data rule needs a mechanical check | RC-40.2 |
| **T-E40** | ✅ **Attacked and survived:** epoch before permissions (a reversed order is fail-open; this order is fail-safe); attach and assign not bumping (they only add, so a missing permission is fail-safe; the AC deviation is accepted by Security); v2 as epoch 0 (a v2 token *is* rejected for a recently revoked user); M6 accepting v3 (only our key mints; see T-S10 for the shape freeze); rollback to M6 is always safe but silently disables epoch checks, so the runbook must page Security on rollback (RC-40.6) | RC-40.6 |
| **T-E41** | ✅ A union-holder plus a colluder can make the union-holder an "administrator" (assign an admin-defining role to the colluder; the colluder assigns it back). The gain is only the A4 exemption, which is harmless to a holder of everything | — |
| **T-E42** | ✅ A1: the rolling overlap lets `user:write`-only holders assign through old instances for minutes, with the parent flag off in production. V6: `TENANT_ADMIN` holders lack `user:role:assign` for up to about 30 min without the cache flush (availability only) | — |

---

## 4. Verdicts on the Architect's hotspots and the extra items

| # | Hotspot | Verdict | Basis |
|---|---|---|---|
| 1 | Single "administrator" definition; catalogue coupling; effect on the lockout, A4, A7 and the indicator | **DISPUTED as "one definition"; CONFIRMED-WITH-CONDITIONS as a predicate** | The predicate (`!catalogue.isEmpty() && containsAll`, over ids, per role, empty fails closed) is sound (MC-1). But revoke-subset, role-subset and A2 test the union (T-E34), and the catalogue cascade reaches further than stated: A4 fails closed (fine); the lockout population shrinks; A7 becomes eligible in tenants with live custom administrators; tenants with no seeded `TENANT_ADMIN` become unrecoverable and invisible (T-E35) |
| 2a | R-1: M13 snapshot TOCTOU | **DISPUTED: "milliseconds" holds only off the set-lock path** | The read view predates any M11 wait; this regresses T-E7 (T-E33) |
| 2b | R-2 collusion, a "new residual" | **DISPUTED: it is RES-1(b) plus one registration** | T-E32, High |
| 2c | RES-13 closed by A3 | **CONFIRMED**, conditional on role-subset landing in M3 and T-E34's fix | A3 is id-based and covers every permission, so the name-based attach gate no longer bounds anything. The detach name gate survives until M3; its replacement must not admit union-holders on admin-defining roles |
| 3 | Ledger rows 2, 7, 12, 19 | **Row 2 CONFIRMED-WITH-CONDITIONS; row 7 DISPUTED; row 12 CONFIRMED-WITH-CONDITIONS; row 19 DISPUTED** | See §5 |
| 4 | A9 correctness | **Mint order CONFIRMED · epoch-keyed cache CONFIRMED with a TTL defect (T-E37) · lost bumps not retried DISPUTED (T-E38) · attach not bumping CONFIRMED (T-E40) · v2 = epoch 0 CONFIRMED · per-instance window DISPUTED as specified (T-D20) · attacker-forced outage: see T-D20 part 3** | The dominant gap is not in A9's logic but in where the filter runs (T-D17) |
| 5 | M6 accepting v3; the refresh-limit loosening | **v3 CONFIRMED** with a shape freeze (T-S10) · **the loosening DISPUTED as specified** (T-D19) | Brute force and reuse detection are not weakened. Unauthenticated audit-write amplification rises tenfold; the per-family bucket cannot sit in the filter; DF-1 makes the per-IP bucket global behind a proxy |
| 6 | A7 break-glass | **CONFIRMED as a decision** (CLI over token; `assigned_by` self-reference over a synthetic principal; the refusal set; containment) · **CONDITIONAL** on RC-37 | T-S9, T-R14, T-R15. Running as `nexus_app` with Flyway off is correct: no new principal, no schema risk, and `validate` catches version skew. Idempotency holds via the TENANT_HAS_ADMIN refusal under the lock; replay of an old approval does not (RC-37.2) |
| 7 | B1 drops the synchronous cross-tenant audit row | **CONDITIONALLY ACCEPTABLE** | The oracle is low-value, and losing a durable IDOR record is a real A09 cost. Acceptable with the ≥ 1-year WARN retention (Ops sign-off) **and** a rate alert. Preferred: the existing async buffer (T-R13, RC-39) |
| 8 | B8 unthrottled denial writes | **DISPUTED: an audit-flooding and pool-pressure vector** | T-D18. The fix preserves FR-B8.a |
| 9 | C1 lock order, `FOR SHARE` grant, `@SQLRestriction`, deleted-role resolvability | **Lock order CONFIRMED · `FOR SHARE` DISPUTED under the stated rollout order · `@SQLRestriction` gap CONFIRMED and needs a detector** | T-T18 |
| 10 | A6 availability coupling; denials on `REQUIRES_NEW` | **CONFIRMED** | Denial events keep `REQUIRES_NEW`, never throw and may buffer (ADR-0009, FR-A6.c). The coupling is accepted (same DB). The ordering rule is RC-40.5 |
| — | A8 three markers; runtime anonymous-401 test | **CONFIRMED** with T-E39's corrections | The third marker is the right call; the runtime test is better than a static list comparison |
| — | A11 null `tenant_id` | **CONFIRMED** (removes the NPE and 500 at source); extend to `sub` (T-S10) | — |
| — | B2/V7 data-mismatch failure at startup | **CONFIRMED** pre-flight · **half-applied migration risk** (T-D21) | Split V7 |
| — | B3 no `tenantId` tags | **CONFIRMED** | MC-8 is the right guard. It reduces tenant-id exposure to metric readers |
| — | C3 access review | **DISPUTED premise** (T-I17) | — |
| — | C6 frontend 403 routing | **CONFIRMED** (T-I19) | UX only; the backend remains the authority |

---

## 5. A5 retirement ledger: row-by-row verdict (input to M3's own re-pass)

| # | Machinery | Verdict | Condition or finding |
|---|---|---|---|
| 1 | Assign privileged gates → A2 + A4 | **Confirmed** | Intended loosening accepted. T-E32 concerns the population, not the gate |
| 2 | Revoke gates (T-E17) → revoke-subset | **Confirmed with conditions** | Replace the false justification. Require administrator status on admin-defining targets, evaluated from M11's locked rows (RC-25, RC-26) |
| 3 | Last-admin lockout | **Confirmed** | Its population shrinks on catalogue growth (T-E35) |
| 4 | Union set lock | **Confirmed** | Harness C with the benign thread stays the exit gate. Add RC-25.3's race case |
| 5 | H-1 filter | **Confirmed** | — |
| 6 | M10 → M10' | **Confirmed** | MC-A. Soft-delete filter explicit (native or JPQL), per RC-36.3 |
| 7 | Canaries and the page alert | **DISPUTED** | Retire the M12 mechanism, but keep an independent runtime disagreement check and the page (RC-28). The untagged-counter ticket is noise after A4 |
| 8 | M12 deleted | **Confirmed** | Once RC-28's replacement lands |
| 9 | D23 counters → `admin_role_assigned{selfTarget}` | **Confirmed** | Ticket, never page, correct |
| 10 | Lock timers | **Confirmed** | Re-baseline after M4 |
| 11 | Attach name gate → A3 | **Confirmed** | RES-13 closed |
| 12 | Detach name gate → role-subset | **Confirmed with conditions** | Union-holders must not pass on admin-defining roles, and the caller must remain an administrator (RC-26.2) |
| 13 | Holder-count signal on every attach | **Confirmed** | Extend with provenance (RC-23.2) |
| 14 | `role_became_admin_defining`, paged when `holders > 0` | **Confirmed** | Necessary but not sufficient for R-2 (RC-23.2) |
| 15 | Zero-admin indicator re-scoped | **Confirmed with conditions** | Blind to tenants with no admin-defining role after demotion (RC-27.2d); must filter soft-deleted roles (RC-36.3); the 30 s TTL and the probe exclusion remain protected properties |
| 16 | `listActive` redaction = administrator | **Confirmed** | C3 must follow the same rule or record the widening (RC-38.2) |
| 17 | Delete `RbacDangerousPermissions` / `RbacAdminEquivalence` | **Confirmed** | After rows 1, 2, 11, 12 and 15 migrate |
| 18 | ArchUnit M12 rule | **Confirmed** | — |
| 19 | Detach to zero administrators stays detective | **DISPUTED** | It is **newly reachable**, and by non-self callers (T-E34). RC-26.2 makes it race-only |

**Retirement rule (FR-A5.d):** "a test is obsolete only if ADR-0021 names the covering control and an equivalent test lands in the same PR". **Endorsed.** Add: `RoleAssignmentSecurityIT`'s stale-JWT, out-of-band-revocation proof (T-E7) is **not** obsolete under M3. It moves to the set-lock path per RC-25.3.

---

## 6. Summary of threats by severity

| Severity | Count | IDs |
|---|---|---|
| **Blocker** | 0 | — |
| **High** | 2 | T-E32 (R-2 sock-puppet pre-positioning), T-D17 (epoch check and 503 on refresh/logout) |
| **Medium** | 16 | T-E33 (T-E7 regression), T-E34 (two definitions; non-self zero-admin detach), T-E35 (catalogue cascade), T-E36 (canary retirement; shared M13 input), T-E37 (epoch TTL margin), T-E38 (lost bumps never replayed), T-D18 (B8 audit flood), T-D19 (refresh-limit split), T-D20 (degraded-state machine), T-T16 (Redis trust boundary), T-T17 (C1 authority), T-T18 (C1 lock privilege, rollout, soft-delete invariant), T-S9 (A7 requester spoofing, replay), T-R14 (A7 attribution), T-R15 (A7 page capture), T-I17 (C3 disclosure) |
| **Low** | 12 | T-S10, T-T19, T-R13, T-I18, T-I19, T-D21, T-D22, T-D23, T-E39, T-E40 ✅, T-E41 ✅, T-E42 ✅ |
| **Total** | **30** | |

Per milestone, so each PR traces its own threats:

| Milestone | Threats |
|---|---|
| M1 | T-E39 |
| M2 | T-E32, T-E41, T-E42 (and T-E36's M13 input) |
| M3 | T-E33, T-E34, T-E35, T-E36 |
| M4 | T-D22 |
| M5 | T-S9, T-R14, T-R15 |
| M6 | T-S10 |
| M7/M7b | T-D17, T-E37, T-E38, T-D20, T-D19, T-T16, T-D23, T-E40 |
| M8 | T-D18, T-R13, T-I18, T-T19, T-D21 |
| M9 | T-T17, T-T18, T-I17, T-I19 |
| M11 | none (corrections only) |

---

## 7. Required design changes (back to architect)

Each item is a concrete change to `03-design.md` or an ADR, required **before Gate 2**. Each becomes at least one `/breakdown` task. **Architect decisions** (not edits) are marked ◆: RC-23.3, RC-26.2, RC-27.1, RC-38.2 and RC-39.

**RC-23 — R-2 / RES-1(b) (T-E32, High; M2 and M3)**
1. In §4.9 R-2, §16 item 2, and ADR-0021 "What this ADR does not close":
   - Replace "needs two principals" and "a *different* threat from RES-1(b)" with: *"needs two accounts. Where self-registration is open (today the default tenant: `RegistrationController.java:54`) one attacker can hold both. A4 closes the literal self-target step of RES-1(b); the primitive survives through a second account."*
   - Record it as **RES-26**, citing RES-1(b) and carrying its accountable owner role, its 2026-11-27 review date and its Epic-3 hard expiry.
   - State that RES-1(b) is reported in EPIC-002 as "self path closed; transformed into RES-26", **not** "fully closed".
2. §5.1 row 13 (M3), on every attach, reuses the post-commit holder read extended to return `assigned_by`, plus M10' (the tenant's administrator user set). Emit:
   - WARN `RBAC_ATTACH_ESCALATES_NON_ADMIN_ASSIGNED_HOLDERS {tenantId, roleId, permissionId, holderCount, nonAdminAssignedCount}`;
   - counter `nexus.rbac.attach_escalates_non_admin_assigned{holders}` (bucketed, no tenant tag);
   - **ticket** when `nonAdminAssignedCount > 0`; **page** when additionally the attached permission is `user:role:assign` or `role:write`, or the attach makes the role admin-defining.
3. ◆ Decide whether to add the preventive **assignment-provenance rule**: *attach of P to R returns 409 (new code) while R has an active holder whose assignment was made by a user who does not currently hold P; the administrator must revoke or re-assign first.*
   - If rejected, record the rejection in ADR-0021. RES-26 then stays **Medium** with RC-23.2, and **High** without it.

**RC-24 — Freshness checks must not run on public auth paths (T-D17, High; M7)**
1. §9.1/§9.5 and ADR-0022 D5: `JwtAuthenticationFilter` skips the epoch check and the degraded-closed 503 for requests to `@PublicEndpoint` handlers. Preferably it skips all bearer processing there. The minimum is `/api/v1/auth/{login,refresh,logout}`. Derive the skip set from the same source A8's test enumerates, not from a third literal list.
2. Correct §9.5 ("login and refresh unaffected", "keeps sessions intact") and impact §7.2, citing `auth.interceptor.ts:125-129` and `JwtAuthenticationFilter.java:66-92`.
3. Add to `TokenFreshnessIT`:
   - refresh with a stale-epoch bearer attached returns 200;
   - refresh while the instance is degraded-closed, with a bearer attached, returns 200;
   - logout with a stale-epoch bearer revokes the refresh-token family server-side;
   - refresh with an **expired** bearer attached returns 200 (pre-existing defect, same fix).

**RC-25 — Restore T-E7 on the set-lock path (T-E33, Medium; M3)**
1. §5.3, §4.3 and ADR-0021 D2: on any request that takes the set lock (admin-defining target, M3 onward: assign, revoke, CLI), compute the caller's administrator status **from the rows M11 returns** (current and X-locked: the caller is a holder in M11's result). Never compute it from M13. This needs zero extra reads, and it is the US-017 D8 containment property expressed without M5b. M13 remains the source only for the non-admin-defining part of A2 and revoke-subset.
2. Restate R-1 (RES-27): the window runs from the transaction's first consistent read to M13. It includes any M11 wait, bounded by `innodb_lock_wait_timeout`. After RC-25.1 it applies only to paths that take no lock.
3. Keep `RoleAssignmentSecurityIT`'s stale-JWT and out-of-band-revocation proof. Add a harness-C case: a revoke of the caller's admin-defining role races the caller's admin-defining assign, and the assign must return 403.

**RC-26 — One definition, used consistently (T-E34, Medium; M3)**
1. Delete from §5.1 row 2 and ADR-0021 D5 the sentence "A non-administrator cannot hold all of an admin-defining role's permissions". §2.1 contradicts it.
2. ◆ On an **admin-defining** target:
   - **Revoke-subset** additionally requires the caller to be an administrator (§2.1, evaluated per RC-25.1).
   - **Role-subset (detach)** additionally requires the caller to be an administrator through **a role other than R** (from M13's per-role sets), so no single detach can remove the last administrator the caller relies on.
   - Security recommends adopting both.
3. Rewrite §5.1 row 19 and ADR-0021's "does not close" bullet. The case is **newly reachable in M3** (US-017 D13 required a literal `TENANT_ADMIN`). After RC-26.2 it is reachable only through a concurrent-revoke race, which is **RES-28**.

**RC-27 — Catalogue coupling (T-E35, Medium; M2 and M8)**
1. ◆ Security recommends extending the B7 footer (V6 included) to **preserve admin-defining status**: *for every role, system or custom, that carried every permission of the pre-migration catalogue, attach the permissions this migration inserts.*
   - Record in ADR-0021 why this is not the `user:write` backfill Decision 3 rejects: it touches only roles that were already full stand-ins.
   - Extend the B7 scanner and the `RbacSchemaMigrationIT` footer test to cover it.
2. If RC-27.1 is rejected, all four of the following:
   - (a) correct §4.8's remedy sentence: under A3 no one can attach a permission nobody holds, so recovery is break-glass, and only where a system `TENANT_ADMIN` is seeded;
   - (b) make the custom-admin exposure check a **deploy-blocking** step of every permission-adding migration, with a per-tenant recorded outcome (a `TENANT_ADMIN` holder exists / break-glass pre-approved / deploy waits);
   - (c) state in ADR-0021 that tenants with custom-only administrators and no seeded `TENANT_ADMIN` become unrecoverable until Epic 3;
   - (d) add a count-only indicator detail "tenants with active assignments and no admin-defining role" at **ticket** severity, so RES-14's blind spot is visible after such a deploy.

**RC-28 — Replace the canary rather than retire it (T-E36, Medium; M3)**
1. §5.1 row 7: on a successful **self-target** assign, capture pre-INSERT (per US-017 RES-25) "the caller was an administrator" through a statement **independent of M13**: the row-15 SQL form (`COUNT(DISTINCT rp.permission_id) = catalogue count` over the caller's own active roles, driven by `fk_user_roles_user`).
   - When it disagrees with A4, emit a paging `RBAC_SELF_ASSIGN_ADMIN_DISAGREEMENT`.
   - Keep `nexus_rbac_gate_bypass_canary`, re-pointed at this signal.
2. Add **MC-H'**: an IT asserting that M13's per-role partition equals M14 called per role, over the US-017 MC-H fixture matrix. The matrix covers a foreign-tenant role, a zero-permission role, `TENANT_ADMIN`, and a role that is soft-deleted from M9.
3. Drop the ticket alert on `nexus.rbac.self_role_assignment_total`, or state what it detects. After A4 it fires only on legitimate administrator self-assignments.

**RC-29 — Epoch-key TTL (T-E37, Medium; M7)**
1. §9.2 and ADR-0022 D1: key TTL = `max(access-token TTL, permission-cache TTL) + margin`, with margin ≥ 60 s. Note that `AUTH_CLOCK_SKEW_SECONDS` is 0 (`AuthConstants.java:13`), so "2 × skew" contributes nothing today.
2. Startup assertion: fail if `key-ttl-seconds` ≤ the permission-cache TTL or ≤ the access-token TTL.
3. `TokenFreshnessIT`: reproduce the first-bump race at key expiry (the latch-paused mint with old epoch 0), and assert that no fresh token carries the revoked permission after expiry.

**RC-30 — Replay lost bumps (T-E38, Medium; M7)**
1. §9.3 and ADR-0022 D3: replace "no retry" with a **bounded per-instance replay queue**.
   - A failed bump enqueues `(tenantId, userIds, failedAt)`.
   - The degraded-state probe drains it on its first success, off the request thread.
   - Entries older than the key TTL are dropped (their tokens have expired).
   - Overflow increments `bump_failed{reason="overflow"}` and pages.
2. Restate §9.5's exposure argument: without replay, degraded-closed's 503 does not keep a lost revocation effective after recovery.
3. Incident-response runbook: before declaring access cut, check `RBAC_EPOCH_BUMP_FAILED` for the target user.

**RC-31 — Degraded-state machine (T-D20, Medium; M7)**
1. Enter degraded-open only after N consecutive failures (N ≥ 3). A single timeout fails open for that request only, and is counted.
2. Clear t0 only after sustained health (≥ 60 s of consecutive successful probes). Page when an instance enters degraded-open 3 or more times in 15 minutes.
3. Reconcile §9.5 "page on entry" with §9.9: keep "page if open > 0 for 1 min".
4. Record that pod restarts, including the runbook's "raise window + rolling restart", reset every instance's window.
5. Record, with the SRE owner, that a Redis outage longer than the window is a platform-wide authenticated outage. Add a Redis latency early-warning alert (p99 > 25 ms for 5 min) and put Redis capacity in the M7 runbook.

**RC-32 — Refresh limit (T-D19, Medium; M7)**
1. §9.7 and ADR-0022 D8: enforce `REFRESH_FAMILY` **in `RefreshTokenUseCase` after `findByTokenHash`**, before rotation, not in `LoginRateLimitFilter`. State that unknown and invalid tokens have no family. Name the hash (plain SHA-256 is sufficient; the family id is not a secret).
2. Add a per-IP **failure** bucket at 30/60 s, consumed only on refresh failure outcomes (each writes a `TOKEN_REFRESH_FAILURE` row, `RefreshTokenUseCase.java:99-110`), alongside the 300/60 s per-IP total and the 30/60 s per-family bucket.
3. Reconcile with DF-1 (`LoginRateLimitFilter.java:44-50`). Behind a proxy, the per-IP buckets are platform-wide. Run the k6 merge gate in the production ingress topology, and record the result for both deployment shapes.

**RC-33 — B8 denial audit while throttled (T-D18, Medium; M8)**
1. §10.8: while an actor is throttled, a request that is evaluated and **denied** on a non-admin-defining target returns its 403 **without** a new `ROLE_ASSIGNMENT_DENIED` row, as today's throttled path does. It increments `nexus.rbac.denial_throttled` and emits at most one WARN per throttle window. Authorized benign requests still succeed (FR-B8.a).
2. Update §4.4's EC8 sentence: from M8, M14 and M15 run before the throttle, and the admin-defining bit is disclosed to a throttled actor (accepted, RES-33).

**RC-34 — Redis trust boundary (T-T16, Medium; M7)**
1. ADR-0022 "Consequences", and an ADR-0016 amendment note under D2, both make these production prerequisites:
   - Redis authentication, with an ACL user limited to the `nexus:*` key patterns, or at least `requirepass`;
   - network isolation;
   - TLS wherever Redis is not on a private network.
   Add a startup assertion (production profile) that the Redis password is non-blank, mirroring `require-shared-store`.
2. State in ADR-0022 that Redis write access equals permission injection at mint and revocation suppression. Add "removes a Redis-write → privilege path" as a recorded consideration in B6's decision rule.

**RC-35 — C1 bounded by authority (T-T17, Medium; M9)**
1. §11.1: PATCH and DELETE on role R apply **role-subset** (the caller holds every permission of R) and return 403 `RBAC_001` before the 404/409 checks that follow resolution. Same WARN, metric and audit posture as the detach denial.
2. Add the rename-to-benign case and the delete-of-admin-defining-role case to the C1 ITs as 403 assertions.

**RC-36 — C1 soft-delete invariant (T-T18, Medium; M9)**
1. §11.1: make the `INSERT … SELECT … FROM roles WHERE id = ? AND tenant_id = ? AND deleted_at IS NULL` form the **primary** assign insert (it needs no lock privilege and is atomically conditional; 0 rows means 404). If `FOR SHARE` is kept instead, reverse the rollout order:
   - (a) release indicator tolerance;
   - (b) apply the grants;
   - (c) release the `FOR SHARE` code.
   `roles` is `SELECT, INSERT` today, and a locking read needs one of `DELETE`, `LOCK TABLES` or `UPDATE`.
2. `RolesPrivilegeIT` runs **as `nexus_app`**, under both the pre-grant and the post-grant set.
3. Extend MC-9 to M13, M14, M10', `RoleResolutionService`'s two reads, the three C3 queries, `ZeroAdminTenantReader` and the CLI's `findRoleIdByName`.
4. Add a count-only detector (health detail or scheduled check): "active `user_roles` rows referencing a soft-deleted role" > 0 → page.

**RC-37 — A7 (T-S9, T-R14, T-R15, Medium; M5)**
1. ADR-0025 D2 and the runbook:
   - The requester's authority is verified against the tenant's contractual contact of record, not against the target account.
   - A second person from Platform Security approves, recorded under the change reference.
   - The `--change-ref` pattern admits ticket-id shapes only (no free text, so no PII).
2. `BootstrapAdminService` refuses (new exit code) a `--change-ref` that already appears on a SUCCESS `ROLE_BREAK_GLASS_GRANT` row. That is one non-locking `auth_events` read, and the refusal is audited.
3. Deployment prerequisite with Ops sign-off on the M5 merge checklist: Kubernetes API audit logging (pod create and exec, with user identity), retained ≥ 1 year.
4. The M5 staging drill's exit criterion includes **"page received from a Job run exactly as the runbook specifies"**. If log shipping cannot guarantee capture, the runbook forbids `--rm` and the runner waits for a flush interval before exiting. Add a backstop: a daily reconciliation alert on new `ROLE_BREAK_GLASS_GRANT` rows.
5. Record in ADR-0025 and the access-review runbook (C3) that a break-glass grant appears as `assigned_by = target`, and that reviewers must join to `ROLE_BREAK_GLASS_GRANT`.
6. The runner refuses to start unless `spring.main.web-application-type=none`, as a guard against the profile being activated in a serving pod.

**RC-38 — C3 disclosure (T-I17, Medium; M9)**
1. Correct §11.3: no endpoint exposes `auth_events` today (`audit:read` gates nothing in `src/main`). C3 is the first live use of `audit:read`.
2. ◆ `RoleHolder.assignedBy` either follows §5.1 row 16's rule (redact unless the caller is an administrator), or ADR-0021 records the widening with Security acceptance. One rule per field.
3. State in the C3 docs and ADR-0021 that `audit:read` now discloses the tenant's administrator roster, and is propagatable under A2/A3. Add `audit:read` to the M9 pre-deploy detection query (which custom roles carry it, ids only).

**RC-39 — B1 evidence (T-R13, Low; M8)**
1. ◆ Enqueue the cross-tenant denial row through the existing `AuthEventRetryBuffer.enqueue` (non-blocking `offer`; the scheduled drain already exists) instead of dropping it, so neither path does DB I/O on the request thread. Alternatively, record in ADR-0022 or ADR-0024 why the existing buffer does not qualify.
2. Either way, add a ticket alert on the rate of `permission_denied{reason="CROSS_TENANT_TARGET"}`, and keep the ≥ 1-year WARN retention with Ops sign-off on M8.

**RC-40 — Low items as tasks**
1. A11 also rejects a `sub` that is not a UUID. For `schema_version = 3`, M6 validates `perm_epoch` as present and a non-negative long even though it ignores the value. ADR-0022 D7 freezes v3 = v2 ∪ {`perm_epoch`} at M6 merge; any other claim change is v4 (T-S10).
2. `EndpointClassificationWebTest` runs with every feature flag enabled. It asserts the **entry-point** 401 (AUTH_003 body from `jwtAuthenticationEntryPoint`), not the status alone. Add an ArchUnit rule: `@AuthenticatedEndpoint` handlers declare no `@PathVariable` or `@RequestParam` of type `UUID` (T-E39).
3. The B7 scanner matches case-insensitively, including `INSERT IGNORE INTO`, backticked `permissions`, and `REPLACE INTO` (T-T19).
4. Split V7 into one `ALTER` per migration file, so a data mismatch fails a single-statement migration with nothing half-applied (T-D21). Optional: a composite FK `user_roles(user_id, tenant_id)` → `users(id, tenant_id)` closes US-017 T-I16 at the DB.
5. Extend MC-4: no Group B audit call after a Group A audit call in one transaction (T-D22).
6. The M7 rollback runbook pages Platform Security, because rolling back to M6 silently disables the epoch check (T-E40).
7. C6: the interceptor navigates to `/access-denied` with no query parameters derived from server data (T-I19).

---

## 8. Residual risk register

RES-26 onward is new. Owners are roles. "Accept" means the residual can be accepted at Gate 2 once its RC lands; "Escalate" means it needs a named role's explicit decision.

| # | Residual | Severity (after RC) | Owner | Disposition |
|---|---|---|---|---|
| **RES-1(b)** *(inherited)* | Self-target pre-positioning | **Closed for the literal self path by A4 (M2); transformed into RES-26** | RES-1(b) accountable owner (the story's designated owner) | Update the EPIC-002 record per RC-23.1 |
| **RES-13** *(inherited)* | Mint-side, name-based gate | **Closed** by A3 (M2) and role-subset (M3, with RC-26.2) | Architect | Close at M3 merge |
| **RES-26** | R-2: pre-positioning through a second account (sock puppet or colluder) | High → **Medium** with RC-23.2 · **Low** with RC-23.3 | Platform Security Owner (inherits RES-1(b)'s accountability, 2026-11-27 review, Epic-3 hard expiry) | **Escalate** if RC-23.2 is not adopted |
| **RES-27** | R-1: snapshot TOCTOU on lock-free paths (ms) | Low | Architect | Accept |
| **RES-28** | Detach to zero administrators via a concurrent-revoke race only (after RC-26.2); detected by the indicator | Low | Architect + SRE | Accept |
| **RES-29** | Catalogue coupling for tenants with custom-only administrators | **Low** with RC-27.1 · **Medium** without (unrecoverable tenants until Epic 3) | Architect + PM (Epic 3 seeding) | **Escalate** if RC-27.1 is rejected |
| **RES-30** | Time-boxed fail-open: per-revocation exposure ≤ token TTL + cache TTL; a Redis outage longer than the window is a platform-wide authenticated 503 | Medium | SRE (Redis capacity) + Platform Security | **Escalate to SRE and PM for SLO acceptance.** The Gate 1 decision stands; the availability consequence needs an owner |
| **RES-31** | Replay queue lost on instance restart; bumps lost silently to async replication at Sentinel failover; key loss without AOF degrades silently to the pre-A9 bound | Low | SRE | Accept. Optional: `WAIT 1 <ms>` after the bump script |
| **RES-32** | Redis write access equals authorization (pre-existing for the permset cache) | Low after RC-34 | SRE / Platform | Accept once the prerequisite is enforced |
| **RES-33** | B8/EC8: a throttled actor learns whether a target is admin-defining | Low | Architect | Accept |
| **RES-34** | B1: cross-tenant evidence is best-effort (buffered) or log-only | Low | Security + Ops (retention) | Accept with RC-39 |
| **RES-35** | A7 trust is anchored in infra access; residual social engineering | Low after RC-37 | Platform Security on-call | Accept |
| **RES-36** | A6: an audit outage blocks RBAC writes, including break-glass | Low | Architect | Accept (same DB) |
| **RES-37** | C3: roster visible to `audit:read` holders | Low after RC-38 | Security + Compliance | Accept |
| **RES-38** | Object-level authorization deferred (ADR-0023) | Medium | PM + Security | Accept (Gate 1 OQ7) |
| **RES-39** | Frontend guard fail-open retained; the route spec compensates | Low | Frontend Tech Lead | Accept |
| **RES-40** | Per-IP refresh ceiling raised for successful refreshes | Low after RC-32 | Security | Accept |
| **RES-41** | Break-glass cannot recover tenants without a seeded `TENANT_ADMIN` until Epic 3 | Medium | PM (Epic 3) | Accept (ADR-0025 trade-off), cross-referenced to RES-29 |
| **RES-42** | Shared combinator (`RbacAdministrators`) across gate and canary after RC-28 | Low | Architect | Accept (0.90 domain gate, MC-1) |
| **RES-6** *(inherited)* | Log retention now covers `RBAC_CROSS_TENANT_TARGET`, `RBAC_ATTACH_EXCEEDS_CALLER` and `RBAC_BREAK_GLASS_USED` | Medium until Ops signs | Architect + Ops | Merge-checklist sign-off on M2, M5 and M8 (as design §2.3) |
| **RES-11** *(inherited)* | Per-replica throttle state | **Closed by B8**, conditional on the production runbook setting `require-shared-store=true` | Ops | Close at M8 deploy |
| **RES-14** *(inherited)* | Tenants with no admin-defining role are invisible to the indicator | Low with RC-27.1 or RC-27.2d | Architect | Accept |

---

## 9. Cross-references to prior threat models

| Prior item | Status after US-018 |
|---|---|
| **RES-1(b) / T-E21 / T-E27** (US-016, US-017) | Literal self path closed by A4. The primitive survives as RES-26 (T-E32) |
| **RES-13 / T-E28** (US-017) | Closed by A3 and role-subset. T-E28's point ("the mint side bounds nothing") becomes moot, because no name gate remains |
| **T-E7** (US-012): caller authority is a live locking read | **Regressed by M3** unless RC-25 lands (T-E33) |
| **T-E17** (US-015): revoke-side stripping | Closed against callers who lack the catalogue. Union-holders need RC-26 |
| **T-E29 / RES-18** (US-017): one input, several fail-open consumers, silent canary | **Recurs** with M13 as the single input (T-E36). RC-28 is the RC-17 pattern applied again |
| **RES-25** (US-017): canary read after the INSERT | Its lesson (capture before the INSERT) is carried into RC-28.1 |
| **T-D10 / RES-19** (US-016, US-017): unthrottled denial amplification | **Partially re-opened by B8** (T-D18) |
| **RES-11** (US-016): per-JVM throttle | Closed by B8 (conditional) |
| **T-D16 / RES-21** (US-017): 30 s actuator TTL as a security control | Unchanged and still protected. The re-scoped indicator SQL keeps depending on it |
| **T-I16** (US-017): no user-tenant check in M11 | Not closed by V7 (role axis only). Optional FK in RC-40.4 |
| **T-I5 / RES-15** (US-012, US-017): `assignedBy` redaction | Redefined (row 16); bypassed by C3 unless RC-38.2 |
| **RES-6** (US-016): log retention | Extended to three more markers |
| **US-016 D5 / US-015 R-6 trap**: locking read passes the ITs, fails in production | Recurs for C1 `FOR SHARE` on `roles` (T-T18) |
| **ADR-0008 / ADR-0016 "jti denylist implemented"** | Correctly identified as false (design §2.4). A9 is the first per-request Redis dependency |

---

## 10. Gate 2 recommendation

**Conditional pass. No Blocker.**

The grant-subset core is the right model, and it removes an entire family of name- and list-based predicates that the epic has patched story after story. I could not defeat A2/A3 as gates: they are id-based, precedence and audit are right, and the oracle discipline holds. The two High findings are about the population around the gate (R-2) and about where the M7 filter runs (T-D17). Neither needs a Gate 1 decision reopened.

**Send back to the Architect before Gate 2 closes:** RC-23 to RC-38, with the five ◆ decisions (RC-23.3, RC-26.2, RC-27.1, RC-38.2, RC-39) flagged first. RC-39 and RC-40 may land as tasks.

**Merge-checklist items (non-code), carried per milestone:**
- **M2:**
  - RES-26 recorded per RC-23.1 **before merge**.
  - RES-6 retention sign-off for `RBAC_ATTACH_EXCEEDS_CALLER`.
- **M3:**
  - Its own Step B re-pass, verifying §5 row by row against the code.
  - Harness C green with the RC-25.3 race case.
  - The zero-admin sweep under the new definition, done forensically (US-017 RC-21 pattern).
- **M5:**
  - RC-37.3 Ops sign-off (Kubernetes audit logging, ≥ 1 year).
  - A staging drill in which the page is actually received.
  - RES-6 sign-off for `RBAC_BREAK_GLASS_USED`.
- **M7:**
  - RC-24's four IT cases green.
  - k6 latency ≤ 2 ms p95.
  - The NAT/refresh gate run in the production ingress topology (RC-32.3).
  - RC-34's Redis prerequisites enforced in production config.
- **M8:**
  - V7 pre-flight = 0 in every environment.
  - `require-shared-store=true` in the production runbook.
  - RES-6 sign-off for `RBAC_CROSS_TENANT_TARGET`.
- **M9:**
  - `RolesPrivilegeIT` green as `nexus_app` under both grant sets.
  - The RC-36.4 detector in place.
- **All milestones:** `./mvnw dependency:tree` and `npm audit` re-run at each Phase 7. Today's baseline: no manifest delta; 27 pre-existing npm findings, not attributable to this story.

### Cross-references

- `docs/features/US-018/03-design.md`: the artifact under review (§16 lists the ten points this document answers in §4)
- `docs/features/US-018/01-requirements.md` §14: Gate 1 decisions (binding); §13, success metric "fully closed, not mitigated" (T-E32)
- `docs/features/US-018/02-impact.md` §2.3 (the R-2 caveat), §8.2–§8.4 (A9 inputs)
- `docs/adr/0021` to `0025`: RC-23, RC-25, RC-26, RC-27, RC-28, RC-38 amend 0021; RC-24, RC-29 to RC-32, RC-34 and RC-40.1 amend 0022; RC-37 amends 0025; RC-39 may amend 0022 or 0024
- `docs/features/US-017/03b-threat-model.md` T-E27, T-E28, T-E29, RC-17, RES-25: the precedents applied
- `docs/features/US-016/03b-threat-model.md` T-E21, T-D10, RES-1(b), RES-6, RES-11

---

## 11. Delta review — Revision 1 (2026-09-26)

_Phase 3 Step C. **Scope: only what Revision 1 changed.** That is the `03-design.md` changelog and "Revision 1 decisions for Gate 2" (§0), ADRs 0021, 0022, 0024 and 0025, and impact §7.2 and §12.1. §0–§10 above are not reopened; their items are closed or carried forward as stated here. No PII: people are referred to by role only._

### 11.1 Verification basis (facts new to this revision only)

| # | Claim under test | Verified at | Result |
|---|---|---|---|
| D1 | Logout uses a verified bearer's principal to revoke every refresh family, with the cookie as fallback | `LoginController.java:133-137`; `LogoutUseCase.execute` (the bearer's user id first, otherwise `findByTokenHash` on the cookie) | **Confirmed** |
| D2 | No other `@PublicEndpoint` handler reads the principal | grep `SecurityContextHolder` / `Authentication` over `src/main`: among public handlers only `LoginController.java:133` reads it. The other readers are `UserProfileController.me` (authenticated) and `RbacControllerSupport` (RBAC) | **Confirmed.** The 9 public handlers are the POSTs under `/api/v1/auth/*` plus GET `/.well-known/jwks.json`. No non-public handler shares their method and pattern |
| D3 | The principal the filter sets carries the token's `permissions[]` | `JwtAuthenticationFilter.java:74-85` | **Confirmed.** A principal set on a public request carries the token's permission set, which may be stale |
| D4 | Retry buffer: two lanes, drop-newest, fixed-delay drain; `LOGIN_FAILURE`, `TOKEN_REFRESH_FAILURE` and `ROLE_ASSIGNMENT_DENIED` go to STANDARD | `AuthEventRetryBuffer.java:112-136`, `:143`, `:204-221`; `AuthEventType.java:88-97` | **Confirmed.** The 800 / 10 s / 250 values are the design's citation of `application.yml:175-189`. That file was not re-read in this session (read not permitted in this environment) |
| D5 | `RateLimitStore` exposes only `tryConsume`, and the Redis adapter fails open | `RateLimitStore.java`; `RedisRateLimitStore.java` (`catch → permit()`, "ADR 0016 §7") | **Confirmed.** `isExhausted` would be new on both adapters and would inherit fail-open |
| D6 | `RefreshTokenUseCase` receives the client IP | `LoginController.java:113` | **Confirmed.** A per-IP bucket can be consumed and enforced inside the use case |
| D7 | `auth_events` supports the change-ref lookup | `V2__identity_schema.sql:76-90` (`metadata JSON`; `idx_auth_events_event_type_created_at`) | **Confirmed.** The lookup is bounded by `event_type`; the ref comparison runs inside the JSON |
| D8 | A production profile exists | `src/main/resources/application-prod.yml` (listed; contents not read) | **Exists.** RC-34.1 asked for the assertion on the production profile |
| D9 | Migration numbering is free | `db/migration/`: V1–V5 only | **Confirmed.** V6–V10 are unused |

### 11.2 Per-RC verdicts

| RC | Verdict | Where it landed | Note |
|---|---|---|---|
| RC-23 | **Landed** | §4 header, §4.9, §5.1 rows 13–14, §5.6, §5.7, §16 item 2, §2.3 retention; ADR-0021 D7, D8, "does not close" | .23.3 ruled in §11.3; formula precision in RC-50(a) |
| RC-24 | **Landed** (deviation accepted with conditions, §11.4) | §3.1, §9.1, §9.5, §9.8, §9.11; ADR-0022 D5 and follow-on rule; impact §7.2 | New T-E45 → RC-44 |
| RC-25 | **Landed** | §4.3, §4.9 (RES-27), §5.3, §5.5, §5.7; ADR-0021 D2 and follow-on rule | — |
| RC-26 | **Landed** | §0 #5, #8; §2.1; §5.1 rows 2, 12, 19; §5.3; §5.7; ADR-0021 D3, D5 | — |
| RC-27 | **Landed** | §0 #3, §2.1, §4.7, §4.8 (27.2(a) applied), §4.11, §10.7; ADR-0021 D1 | 27.2(b)–(d) correctly dropped. New T-T21 → RC-48 |
| RC-28 | **Landed** | §5.1 rows 7–8, §5.7 (MC-H'), §15 (MC-A); ADR-0021 D7 | Precision in RC-50(b) |
| RC-29 | **Landed** | §0 #14, §9.2, §9.10, §9.11; ADR-0022 D1 and follow-on rule | — |
| RC-30 | **Landed** | §9.1, §9.3, §9.5, §9.9–§9.11; ADR-0022 D3 | New T-E44 → RC-42 |
| RC-31 | **Landed** | §0 #16, §9.5, §9.9, §9.10; ADR-0022 D5 | New T-E43 → RC-41 |
| RC-32 | **Landed as specified** | §0 #19, §9.7, §9.11; ADR-0022 D8 | New T-D24 → RC-43 |
| RC-33 | **Landed** | §4.1, §4.4, §10.8, §2.3 | — |
| RC-34 | **Partial** | §9.10, §9.12, §10.6, §14; ADR-0022 Consequences, D9 | `require-auth` defaults to `false` and is set only by the runbook, while RC-34.1 asked for the production profile. The dedicated epoch factory's credentials are unspecified. → RC-45. The ADR-0016 note deferral is accepted (§11.4) |
| RC-35 | **Landed** | §2.2, §11.1 | — |
| RC-36 | **Landed** | §0 #26, §11.1, §14 | Invariant sound. New T-T20 (lock order) → RC-46 |
| RC-37 | **Landed** | §0 #11, #12; §7.1–§7.3; §11.3; §14; ADR-0025 | New T-S11 → RC-47; guard wording in RC-50(d) |
| RC-38 | **Landed** | §0 #28, §5.1 row 16, §11.3; ADR-0021 Consequences | — |
| RC-39 | **Not adopted (◆), reason recorded; RC-39.2 landed** | §0 #20, §10.1; ADR-0024 item 6 | Ruled in §11.3; alert floor in RC-50(c) |
| RC-40 | **Landed** | .1: §8, ADR-0022 D7 · .2: §3.1 · .3: §10.7 · .4: §0 #21, §10.2 (optional FK declined, §11.4), impact §12.1 · .5: §6.4, ADR-0024 item 5 · .6: §9.10, ADR-0022 · .7: §11.5 | New T-D25 → RC-49 |

**Tally:** 16 Landed, 1 Partial (RC-34), 0 Wrong, and 1 not adopted by decision (RC-39, accepted below).

### 11.3 Rulings on the Architect's ◆ decisions

**R1-1 / RC-23.3: narrow provenance rule. Accepted; RES-26 is confirmed at Medium.**
- **The rejection of the general rule holds.** `user_roles` is append-only, so "re-assign" means a revoke plus an assign per holder. The general rule would also fire on the delegation pattern A1 exists to enable. A preventive control that routinely blocks legitimate work tends to get removed.
- **The narrow rule guards the only way in.** I checked every path by which a role becomes admin-defining, and attach is the only one:
  - catalogue permissions are never deleted;
  - detach and C1 only shrink or rename a role;
  - RC-27.1's footer extends only roles that are already admin-defining.
- **The attacker cannot bypass it through assign.** The attacker cannot assign an admin-defining role to the sock puppet (A2). A union-holder doing so is T-E41: they already hold everything.
- **What remains is Medium, not Low:** the "catalogue minus one" partial escalation, which is detective only. Row 13 pages when the attached permission is `user:role:assign` or `role:write`, the two that let the sock puppet propagate further. The race after the check's snapshot is paged by row 14.
- **Escalation:** the Platform Security Owner records acceptance at Gate 2. RES-26 inherits RES-1(b)'s 2026-11-27 review date and Epic-3 hard expiry, and is re-confirmed at the M3 re-pass.

**R1-2 / RC-26.2: both parts. Accepted.**
- Revoke-subset's administrator test comes from M11's locked rows (current). Role-subset's "through a role other than R" comes from M13 on a lock-free path, so only the concurrent race remains (RES-28, Low).
- C1 PATCH and DELETE reuse the same rule, which is consistent.
- The newly denied populations are acceptable:
  - union-holders;
  - an administrator whose only admin-defining role is R. They can first self-assign `TENANT_ADMIN`: A4 exempts administrators, and A2 passes because R carries the whole catalogue.

**R1-3 / RC-27.1: adopted; 27.2(b)–(d) dropped, (a) applied. Accepted.**
- (b)–(d) applied only if 27.1 was rejected, so dropping them is correct.
- RES-29 and RES-14 go to Low.
- Condition: RC-48. Without it, the preservation statement is one copy-paste away from silently doing nothing.

**R1-4 / RC-38.2: redact `assignedBy` for non-administrators. Accepted.** One rule per field, and no widening to accept. Consequence: the RC-37.5 reviewer hint ("`assignedBy` equals its own `userId`") is visible only to administrator reviewers. The access-review runbook should say that reviewers are administrators, or that they use the `ROLE_BREAK_GLASS_GRANT` join.

**R1-5 / RC-39: not adopted. Accepted. RES-34 is acceptable at Low.**
- **The argument is verified (D4).** STANDARD is shared with `LOGIN_FAILURE`, `TOKEN_REFRESH_FAILURE` and `ROLE_ASSIGNMENT_DENIED`, and it is drop-newest with a fixed-delay drain. As a primary path for a prober-triggerable event, it would let attacker traffic crowd out genuine failure-path evidence. That is T-D1's shape turned on the buffer itself, so the cure would be worse than the gap.
- **Conditions for Low:**
  1. The RES-6 retention sign-off for `RBAC_CROSS_TENANT_TARGET` on M8 (already on the checklist).
  2. The rate alert has an absolute floor. With a near-zero 7-day baseline, "5× baseline" either fires on any single event or never (RC-50(c)).

### 11.4 Rulings on the deviations

**RC-24: the filter never rejects on public paths, and a verified bearer still sets the principal. Accepted, conditional on RC-44.**
- **Keeping the principal is correct.** My preferred "skip all bearer processing" would have dropped the cookie-less revoke-all logout path (D1).
- **A stale-epoch bearer on logout adds no new risk.**
  - An epoch bump records a *permission* change, not an identity revocation. The token's signature, expiry and claims are still verified, so its user id is as trustworthy as on any authenticated request.
  - The only effect is revoking that same user's refresh families, which is a reduction.
  - Pre-existing and unchanged: a stolen, unexpired token can force-logout its owner.
  - An expired or invalid bearer is ignored, and logout falls back to the cookie (the existing T-7.1 path).
- **No other public endpoint reads the principal today (D2).** Login, refresh, register, verify-email, resend-verification, password forgot and reset, and JWKS take no `Authentication` and never call `SecurityContextHolder`.
- **New risk: the exemption turns the matcher into a fail-open switch for A9.** The principal that passes through it carries unchecked permissions (D3). This is T-E45 → RC-44.

**RC-34.1: the ADR-0016 amendment is deferred to M11. Accepted.** ADR-0001 forbids editing accepted ADR bodies. The content is already in ADR-0022, which supersedes ADR-0016 in part, and enforcement lands with M7 (§9.10, §14). The deferral is documentation only. It does not cover the assertion gap (RC-45).

**RC-40.4: the optional `user_roles` → `users` composite FK is declined. Accepted.** It was offered as optional.
- US-017 T-I16 stays as US-017 recorded it: every write derives the user's tenant from a tenant-checked read.
- The reasons given are proportionate: a new unique key on the identity-owned `users` table, and a second COPY rebuild of `user_roles`.
- It is not a residual of this story.

**The two "900 s + skew" cells: not misleading about the key TTL; wording nit only.**
- Locations in `03-design.md`:
  - §9.10, line 850: "**M7b** after at least 900 s + skew."
  - §14 rollout table, M7b row, line 1107: "≥ 900 s + skew after M7".
- Both describe the M7b wait. That wait is governed by the **access-token TTL** (every v2 token must have expired before M7b stops accepting v2), not by the epoch-key TTL.
- So 900 s is the correct figure. Skew is 0 (`AuthConstants.java:13`), which makes "+ skew" vacuous but harmless, and the 960 s key TTL does not bear on M7b.
- Optional: align both cells with §9.6, line 773 ("at least 900 s (the access-token TTL; skew is 0)") so no reader conflates the two TTLs. Not a required change.

### 11.5 New threats (regressions introduced by Revision 1 only)

Numbering continues from §0.5 and §3.

#### T-E43 — "3 consecutive failures" lets an intermittently failing Redis fail open with no time box · **Medium** · ❌

RC-31.1 landed as "N = 3 **consecutive**", and a single failure fails open for that request only.

- **Healthy state.** Take a failure pattern of F F S F F S …, from an overloaded Redis, a lossy network path, pauses on the Redis host, or the saturation lever in T-D20 part 3. Up to two of every three checks skip the epoch, yet:
  - the instance never enters degraded-open, so `t0` is never set;
  - the 15-minute window never runs, so degraded-closed never arrives;
  - nothing pages.
- **Weak signals.** `epoch.check{outcome=skipped_error}` has no alert (§9.9). The p99 > 25 ms ticket does not fire for fast failures (connection reset or refused).
- **Recovering state has the same shape.** Leaving it needs 60 s of consecutive successes, and relapsing needs 3 consecutive failures. So an intermittent Redis keeps the instance in Recovering indefinitely, with per-request fail-open and no alert on `degraded{state=recovering}`.

This is the Gate 1 "time-boxed" fail-open without its time box. Per-revocation exposure stays bounded by token TTL plus cache TTL (T-D20 part 3), hence Medium. **Required: RC-41.**

#### T-E44 — The replay queue drains only on a degraded-state probe; a bump lost while Healthy may never be replayed · **Medium** · ❌

- **The drain is tied to recovery.** §9.3 says "the prober drains the queue on its first successful probe". §9.5 and the state diagram run the probe in the degraded states.
- **A single failure is the common case, and it stalls.** A post-commit bump that fails once counts towards N but does not trip it. The instance stays Healthy, nothing drains the entry, and it waits for the next degraded episode, which then drops it by age. That is T-E38 again, for the most common failure.
  - Such failures are likely: §9.1 puts the bump on the "dedicated 50 ms template", while §9.5 says that template is "used only for epoch reads". On the 50 ms template, a 500-user fan-out batch can exceed the timeout under load.
- **Also unspecified:**
  - which entry overflow drops;
  - what happens to the rest of a batch when a drain fails partway;
  - deduplication (the same user queued repeatedly consumes capacity).
- **Memory and DoS are acceptable.** At capacity the queue is a few MB per instance. Filling it needs admin-only revoke or detach calls during a Redis failure, so it is not an external DoS lever.

**Required: RC-42.**

#### T-D24 — The per-IP failure bucket, checked in the filter, blocks successful refreshes: 30 junk requests per minute log out everyone behind an IP · **Medium** · ❌

- **The attack.** §9.7 has the filter check `REFRESH_IP_FAIL:{ip}` without consuming it and return 429 once it is exhausted. That applies to **every** refresh from the IP, valid ones included, and the SPA clears the session on a refresh 429 (`auth.interceptor.ts:150-154`).
  - An unauthenticated attacker behind a shared NAT sends 30 invalid refreshes a minute, and every user behind that NAT is logged out at their next refresh.
  - Behind the proxy (DF-1) the bucket is platform-wide, so this becomes a platform-wide logout lever.
  - The RC-32.3 k6 gate models only benign storms and will not see it.
- **Relative to today.** It is no worse than today's single 30/60 s bucket, where the same attack works. But it defeats the split's stated purpose ("cannot log out users behind a shared NAT"), and the fix is cheap.
- **Secondary race.** The check (filter) and the consume (use case) are separate, non-atomic operations. Concurrent failing requests all pass the check before any of them consumes, so under concurrency the failure bound falls back toward the 300/60 s total. That makes T-D19's tenfold amplification reachable with parallelism.
- **Redis failure mode.** `isExhausted` inherits the Redis adapter's fail-open (D5), consistent with every other bucket (ADR-0016 §7). Accepted.

**Required: RC-43** (it closes both the attack and the race).

#### T-E45 — `PublicEndpointRequestMatcher` is a fail-open switch for A9, and the principal it lets through carries unchecked permissions · **Medium** · ❌

**Effect of a false positive.** A non-public request matched as public skips the epoch check and the degraded-closed 503. The filter still sets a verified principal carrying the token's `permissions[]` (D3), so `@RequiresPermission` authorizes on a possibly stale set. That is an A9 bypass, and a silent one: no metric distinguishes it.

**Ways to get a false positive:**
- matching on path without method (a future non-public GET or DELETE that shares a public POST's pattern under `/api/v1/auth`);
- calling `RequestMappingInfo.getMatchingCondition` from a servlet filter before the request path has been parsed and cached, with an implementation that catches the resulting exception as "public";
- a handler pattern broader than intended.

**The opposite direction fails closed.** An empty matcher brings T-D17 back (availability), and the existing unit assertion (login, refresh and logout are in the set) catches it.

**Severity.** Not exploitable today (D2), and a false positive is bounded by the pre-A9 baseline. That makes it Medium: a defense-in-depth gap on a Gate 1 control.

**Required: RC-44.**

#### T-T20 — The C1 "role row first" lock-order claim is false on admin-defining assigns; DELETE can deadlock with them · **Low** · ❌

- **The claim.** §11.1 says "Both take the role row first (DELETE X, assign S through the INSERT … SELECT)".
- **What actually happens on an admin-defining target.** With the conditional insert, assign's S lock on the role row is taken at INSERT time. Assign has already taken M11 before that: a locking read on `user_roles` over the admin-defining role ids via `fk_user_roles_role` (§5.3).
- **The cycle.** DELETE takes `roles` X, then `user_roles FOR UPDATE` via `fk_user_roles_role`. So assign locks `user_roles` → `roles`, while DELETE locks `roles` → `user_roles`. The trigger is a holder-less admin-defining custom role being deleted while someone assigns it; M11's next-key locks can overlap DELETE's range scan.
- **Integrity holds.** InnoDB rolls back a victim, and both the conditional insert and the holder check are current reads. The consequence is an unmapped 1213, which surfaces as a 500 on a rare, admin-only path.
- **The soft-delete invariant itself is sound.** The INSERT … SELECT's source read is a locking current read under RR:
  - a committed delete gives 0 rows, which maps to 404;
  - an uncommitted delete makes the insert wait;
  - a committed assign makes DELETE's `FOR UPDATE` see the holder, which gives 409 `RBAC_009`.

**Required: RC-46.**

#### T-S11 — The `--change-ref` reuse refusal can be bypassed with leading zeros · **Low** · ❌

- **The bypass.** `^[A-Z][A-Z0-9]{1,9}-[0-9]{1,8}$` accepts `ABC-1`, `ABC-01` and `ABC-0001` as distinct strings for one ticket. The exit-6 lookup compares strings, so re-padding the number replays an old approval.
- **Also unspecified:** the lookup must be global rather than tenant-scoped, and it must compare the unquoted JSON value against a bound parameter.
- **Accepted as is:** two concurrent runs with one reference can both pass the non-locking lookup. With the per-tenant set lock, both can succeed only in two different zero-admin tenants. The runbook should say one invocation at a time per reference.
- **Otherwise sound:** the port follows the established direction (rbac port, identity implementation, `SELECT` only); the lookup is bounded by the `event_type` index (D7); refusals are audited, and a null `tenant_id` is allowed (§0.2 #12).

**Required: RC-47.**

#### T-T21 — The B7 preservation statement depends on a per-migration id list the scanner cannot check · **Low** · ❌

- **Why the scanner can't check it.** Statement (a) defines the pre-migration catalogue as "every permission except the ids this migration inserts" (§4.7). That list differs per migration, so (a) cannot be fixed footer text, and §10.7's "normalized whitespace comparison" cannot validate it.
- **How it fails silently.** A future migration that copies V6's footer verbatim excludes only `user:role:assign`. Its own new permission then counts as "pre-migration", no role carries it, and (a) attaches nothing. The result is silent demotion (T-E35 recurs), which only the post-deploy runbook check would catch.
- **Two legitimate forms.** From V9 on, (a) must filter `deleted_at IS NULL`, which V6 cannot.
- **Otherwise sound.** The footer touches only roles that were already admin-defining. It is order-independent because of the explicit exclusion list, and it is idempotent.

**Required: RC-48.**

#### T-D25 — Split migrations still need `flyway repair` after a failure, and V9 rebuilds `roles` · **Low** · ❌

- **"Clean re-run" is not accurate on MySQL.** §10.2 says a V8 failure "leaves nothing half-applied and the fix is a clean re-run". The first half is correct, since each file is one atomic DDL statement. But Flyway records the failed V8 in `flyway_schema_history`, and every booting instance refuses to start until `flyway repair` removes that row. T-D21's startup-blocking consequence is unchanged; only the half-applied part is fixed.
- **V9 rebuilds `roles`.** A STORED generated column cannot be added in place, so `roles` is rebuilt (COPY) and writes to it (create, PATCH, DELETE) block for the duration. §14's M9 row has no maintenance window.
- **Otherwise sound.** The order V7 → V8 → V9 → V10 matches the delivery order M8 → M9. If the milestones are ever reordered, versions must be reassigned at merge, as the design already says.

**Required: RC-49.**

### 11.6 Updated residual risk rows

Only the rows that changed, or that are new. All other rows in §8 stand as written: RES-27, RES-28, RES-33, RES-35 to RES-39, RES-41, RES-42, RES-6 and RES-11.

| # | Residual | Severity | Owner | Disposition |
|---|---|---|---|---|
| **RES-26** | R-2: pre-positioning through a second account; partial ("catalogue minus one") escalation stays detective | **Medium** (confirmed: RC-23.2 plus the narrow `RBAC_010`, ADR-0021 D8) | Platform Security Owner | **Escalate.** Acceptance recorded at Gate 2; re-confirmed at the M3 re-pass; review 2026-11-27; Epic-3 hard expiry |
| **RES-29** | Catalogue coupling for custom administrators | **Low** (RC-27.1 adopted), conditional on RC-48 | Architect | Accept |
| **RES-14** | Tenants with no admin-defining role are invisible to the indicator | Low (RC-27.1) | Architect | Accept |
| **RES-30** | A Redis outage longer than the window is a platform-wide authenticated 503 | Medium | SRE + PM | **Escalate; still open.** The design records the intent, not the sign-off, so acceptance must be recorded at Gate 2. Once RC-41 lands, the window also bounds intermittent failure |
| **RES-31** | Replay queue (users, and since M7 part 2 review M-2 the role queue of failed detach holder reads) lost on restart; **pre-PR review L-1/L-2:** the global bounds are shared (read pool 100,000 = ten tenants at the 10% share; own-bump pool 200,000 = five tenants at their 40,000 ceiling), so a few large tenants can fill them, and a tenant over its replay share (10% of each queue) overflows itself and pages, never another tenant. A refused read-derived entry is paged (`last_seen_dropped{reason=capacity}`) but deliberately does not fail the tenant closed: the read pool is full on any busy instance, and that would turn the fail-open grace into constant 401 loops; bumps lost to async replication at Sentinel failover; overflow drops (`overflow`, `role_overflow`) | Low after RC-42 | SRE | Accept |
| **RES-32** | Redis write access equals authorization | Low after RC-34 **and RC-45** | SRE / Platform | Accept once enforced in the production profile |
| **RES-34** | Cross-tenant evidence is log-only | Low | Security + Ops | Accept, with the RC-50(c) floor and the RES-6 M8 sign-off |
| **RES-40** | Per-IP refresh ceiling raised for successful refreshes; **amended (M7 part 2 review M-1): `REFRESH_IP` also counts invalid refreshes, so 300 junk requests a minute from one IP make valid refreshes from it answer 429 for the window (platform-wide behind the proxy, DF-1). Accepted because the SPA keeps the session on a refresh 429 and retries after `Retry-After`; k6 `refresh-junk-flood.js` is the gate** | **Low after RC-43** (Medium until then, per T-D24) | Security | Accept after RC-43 |
| **RES-43** *(new)* | A verified bearer on a `@PublicEndpoint` request sets a principal without an epoch check; only logout reads it, to revoke its own families | Low after RC-44 | Architect | Accept |
| **RES-44** *(new)* | A failed V7–V10 migration blocks instance start until `flyway repair` | Low | Ops | Accept, with the RC-49 runbook step |
| **RES-45** *(new)* | C1 DELETE versus admin-defining assign can deadlock (only if RC-46 option (b) is chosen) | Low | Architect | Accept |

### 11.7 Delta required changes

RC-41 to RC-45 are required **before Gate 2 closes**. RC-46 to RC-50 land as `/breakdown` tasks.

**RC-41 — Degraded entry counts failures in a sliding window, not consecutively (T-E43, Medium; M7)**
1. In §0 #16, §9.5 (text and state diagram) and ADR-0022 D5: enter degraded-open when **3 or more failures occur within a 10 s sliding window**, not "3 consecutive". Set `t0` at the first failure in that window.
   - Use the same rule for the Recovering → degraded relapse.
   - Keep "a single failure fails open for that request only".
2. §9.9 gains two alerts:
   - **page** when `epoch.check{outcome=skipped_error}` exceeds 1% of checks for 5 minutes on an instance;
   - **ticket** when `degraded{state=recovering}` > 0 for 10 minutes.
3. `PermissionFreshnessServiceTest`: an F F S F F S … pattern sustained past the window trips degraded-open, then degraded-closed.

**RC-42 — Replay whenever the queue is non-empty (T-E44, Medium; M7)**
1. §9.1, §9.3 and ADR-0022 D3: the 1 s scheduled task drains a non-empty replay queue **in every state, Healthy included**, not only on a degraded-state probe. A failed drain re-enqueues the unreplayed remainder with its original `failedAt`.
2. §9.1 and §9.5: state the bump script's timeout. It must not be the 50 ms epoch-read template. The bump and its replay get their own bound, sized for a 500-user batch.
3. §9.3 queue semantics:
   - it coalesces by `(tenantId, userId)`, keeping the oldest `failedAt`, so capacity counts distinct users;
   - overflow rejects the arriving ids (drop-newest) and increments `bump_failed{reason="overflow"}` by the dropped count, which pages (already stated).
4. `TokenFreshnessIT`: a single bump failure, with the instance still Healthy, is replayed within 2 s, and the holder's old token is then rejected.

**RC-43 — Enforce the per-IP failure bucket only on failing refreshes, inside the use case (T-D24, Medium; M7)**
1. §0 #19, §9.7 and ADR-0022 D8: remove the filter-side check. In `RefreshTokenUseCase`, after `findByTokenHash`:
   - a **valid** token proceeds, subject to the family bucket, whatever `REFRESH_IP_FAIL` says;
   - on a failure outcome, call `tryConsume("REFRESH_IP_FAIL:{ip}", 60, 30)` **before** writing `TOKEN_REFRESH_FAILURE`;
   - if that call rejects, return 429 with `Retry-After` and write **no** audit row. Instead, increment a counter and emit at most one WARN per window, as RC-33 does for B8.
2. `RateLimitStore.isExhausted` is no longer needed. Drop it (no port change).
3. Tests:
   - 30 invalid refreshes from an IP, then a valid refresh from the same IP, returns 200;
   - the 31st invalid refresh returns 429 and writes no `auth_events` row;
   - N concurrent invalid refreshes write at most 30 rows.
   - Add an "attacker behind the NAT" case to the RC-32.3 k6 scenario.

**RC-44 — Make the public-endpoint exemption fail closed and permission-free (T-E45, Medium; M7, M1)**
1. §3.1: `PublicEndpointRequestMatcher` matches on **HTTP method and pattern**, using the same path parsing as MVC dispatch (parse and cache the request path before matching). Any exception or ambiguity counts as **non-public**.
2. §9.5 and ADR-0022 D5: on a `@PublicEndpoint` request, a verified bearer sets a principal with an **empty** `PERMISSIONS` detail and no authorities. An epoch-unchecked token then can never satisfy `@RequiresPermission`. Logout needs only the principal's user id.
3. `EndpointClassificationWebTest` asserts, for every `(method, pattern)` in `RequestMappingHandlerMapping`, that `matcher.matches(request)` is true exactly when the handler carries `@PublicEndpoint`. It includes a negative fixture with the same path and a different method.
4. `TokenFreshnessIT` adds three cases:
   - logout with a stale-epoch bearer and **no cookie** revokes every refresh family of that user (the path the deviation keeps);
   - a stale-epoch bearer on a non-public handler gets 401 while the instance is healthy;
   - the same request gets 503 while the instance is degraded-closed.

**RC-45 — Complete RC-34.1 (RC-34 Partial; M7)**
1. §9.10 and §9.12: set `nexus.rbac.redis.require-auth=true` in `application-prod.yml`, not only in the runbook, and set `nexus.rbac.throttle.require-shared-store=true` there too (same pattern). A production start without a Redis password then fails without depending on an operator step. The runbook keeps both as checks.
2. §9.5: the dedicated 50 ms `LettuceConnectionFactory` is built from the same `spring.data.redis.*` properties as the main one: password, ACL username and SSL. The startup assertion covers it, and an IT runs the epoch path against an auth-enabled Redis container.

**RC-46 — C1 lock order on admin-defining roles (T-T20, Low; M9)**
1. §11.1: correct "Both take the role row first", then choose one:
   - (a) DELETE of an admin-defining role takes the set lock (M10' → M11) before its `UPDATE roles`, as assign does;
   - (b) map InnoDB deadlock 1213 on DELETE and assign to 409 with a retry hint, and record RES-45.
2. `RoleDeleteConcurrencyIT` includes a holder-less admin-defining custom role and asserts that no 500 occurs.

**RC-47 — Change-ref canonical form (T-S11, Low; M5)**
1. §7.2 and ADR-0025 D1: the pattern becomes `^[A-Z][A-Z0-9]{1,9}-[1-9][0-9]{0,7}$` (no leading zeros).
2. §7.2: the exit-6 lookup:
   - is global across tenants;
   - filters on `event_type = 'ROLE_BREAK_GLASS_GRANT' AND outcome = 'SUCCESS'`;
   - compares the unquoted `metadata.changeRef` against a bound parameter.
3. `BreakGlassAdminIT` adds a zero-padded replay, which must exit 6.

**RC-48 — Make the B7 preservation statement checkable (T-T21, Low; M2, M8)**
1. §4.7 and §10.7: publish the footer as a template with one placeholder, the list of ids the file inserts. The scanner asserts:
   - that statement (a)'s exclusion list equals exactly the ids inserted by the same file;
   - that from V9 on, (a) filters `deleted_at IS NULL`.
2. The permission-migration template's IT step seeds a full-catalogue custom role and asserts it gains the new permission. This applies to every such migration, not only V6.

**RC-49 — Migration failure recovery and V9 cost (T-D25, Low; M8, M9)**
1. §10.2: replace "the fix is a clean re-run" with "the fix is `flyway repair`, then a re-run; nothing is half-applied". The runbook carries the repair step, which needs the Flyway DDL user.
2. §11.1 and §14 (M9 row): V9 rebuilds `roles`, because a STORED generated column cannot be added in place. Schedule it in a maintenance window, as V8 is.

**RC-50 — Precision items (Low; tasks)**
- **(a)** §5.6 and ADR-0021 D8: the `RBAC_010` condition becomes "R is **not** admin-defining now **and** M14(R) ∪ {P} ⊇ M15". A duplicate attach to an already admin-defining role then still gets `RBAC_005`.
- **(b)** §5.1 row 7: state that the independent statement groups by role (`GROUP BY ur.role_id HAVING COUNT(DISTINCT rp.permission_id) = …`), as ADR-0021 D7 says. It also carries its own `r.tenant_id = ur.tenant_id` and active and soft-delete predicates. A union-level count would page on every union-holder.
- **(c)** §10.1 and ADR-0024 item 6: the cross-tenant rate alert fires at `max(5 × 7-day baseline, 20 per 15 min)`. Without a floor, a near-zero baseline makes it fire on any single event, or never.
- **(d)** §7.2 (RC-37.6 guard): implement it as a bean-initialization check in the `break-glass` profile, so it fails the context refresh before the embedded server starts. Drop "before any DB access": `ddl-auto=validate` already reads the schema during the refresh.

### 11.8 Final Gate 2 verdict

**Pass, conditional. No Blocker and no High.**

- **Revision 1 outcome:** 16 of 18 required changes landed. RC-34 is Partial, and RC-39 was not adopted, by an accepted decision.
- **Rulings:** all five ◆ decisions are accepted. All three deviations are accepted, RC-24's on condition of RC-44. The "900 s + skew" cells are not misleading.
- **New regressions:**
  - four Medium, all in M7's new machinery: T-E43, T-E44, T-D24 and T-E45;
  - four Low: T-T20, T-S11, T-T21 and T-D25.
  - None of them reopens a Gate 1 decision.
- **Before Gate 2 closes:**
  - Fold RC-41 to RC-45 into `03-design.md` and ADR-0022. They are text-level changes to M7, plus one M1 test assertion. Security spot-checks the edits; no further STRIDE pass is needed.
  - Record the RES-26 acceptance (Platform Security Owner) and the RES-30 acceptance (SRE and PM).
- **As `/breakdown` tasks:** RC-46 to RC-50.
- **Merge-checklist additions to §10:**
  - **M5:** RC-47's padded-replay case.
  - **M7:** the RC-41 to RC-45 tests are green, and the RC-43 NAT-attacker k6 case passes.
  - **M9:** V9 runs in a maintenance window.

## 12. Spot-check — Revision 2 (2026-10-01)

_Phase 3 Step C spot-check, not a STRIDE pass. **Scope:** the Revision 2 changelog and §0 decisions #11, #12, #16, #19, #20, #21, #24 and #26 in `03-design.md`, the sections they cite, and ADRs 0021, 0022, 0024 and 0025. §0 to §11 are not reopened. No PII: people are referred to by role only._

### 12.1 Verification basis (new facts only)

| # | Claim under test | Verified at | Result |
|---|---|---|---|
| E1 | The reuse branch revokes the family and writes its own event | `RefreshTokenUseCase.java:114-122` (`revokeFamily`, then `TOKEN_REFRESH_REUSE`) | **Confirmed.** The branch is a theft response, not only an audit write (bears on T-E46) |
| E2 | How `@Scheduled` tasks are executed | `application.yml:17-19` (`spring.threads.virtual.enabled: true`); `SchedulingConfig.java:21-27` | Virtual threads are on, so Boot uses a per-execution scheduler. A slow drain therefore cannot starve `AuthEventRetryBuffer.drain()`. **But the only `@EnableScheduling` is conditional on `nexus.identity.audit.retry-buffer.enabled`** (bears on RC-52) |
| E3 | Deadlocks are not mapped to a client error | grep `PessimisticLockingFailure`, `DeadlockLoser`, `CannotAcquireLock` over `src/main`: no handler | **Confirmed.** An InnoDB 1213 still surfaces as a 500 (bears on ruling (d)) |

### 12.2 Per-RC verdicts

| RC | Verdict | Where it landed | Note |
|---|---|---|---|
| RC-41 | **Landed** | §0 #16; §9.5 text and state diagram (both relapse edges); §9.9 (both alerts); §9.10 config; §9.11 F F S test; §14 M7; ADR-0022 D5 | New interaction with RC-42: T-E47 → RC-53 |
| RC-42 | **Landed** | §9.1, §9.3 (coalescing, oldest `failedAt`, drop-newest counted per id, partial-drain re-enqueue, remaining batches enqueued), §9.5, §9.9, §9.11 single-failure IT; ADR-0022 D3, D5 | 500 ms is ruled in (c) |
| RC-43 | **Landed as specified** | §0 #19; §9.7; §9.9 counter; §9.11 (three tests, filter assertion); §9.7 k6 NAT-attacker case; ADR-0022 D8; `isExhausted` dropped | The specification itself (Security's RC-43 wording) did not exclude the reuse branch. That gap is T-E46 → RC-51 |
| RC-44 | **Landed** | §3.1 (method and pattern, `parseAndCache`, false on any exception or ambiguity; equivalence test with a same-path, different-method fixture); §9.5 and ADR-0022 D5 (empty `PERMISSIONS`, no authorities); §9.11 (three cases); §0 public-endpoint bullet | — |
| RC-45 | **Landed** (the split rollout is ruled in (b)) | §9.10, §9.12, §10.8, §14 M7 and M8; §9.5 (both dedicated factories built from `spring.data.redis.*`); §9.11 (auth-enabled Redis IT, prod-profile test); ADR-0022 Consequences | Precision in RC-54(b) |
| RC-46 | **Landed** (option (a)) | §0 #26; §11.1 (claim corrected, per-class lock order, rationale); §14 M9; `RoleDeleteConcurrencyIT` holder-less admin-defining case | The classification-flip edge is ruled in (d) |
| RC-47 | **Landed** (the test deviation is ruled in (a)) | §0 #11; §7.1; §7.2 (pattern, global lookup, `event_type` and `outcome`, bound parameter, the concurrency note); §7.3; ADR-0025 1, 4 | Precision in RC-54(a) |
| RC-48 | **Landed** | §0 #24; §4.7 (`{{INSERTED_PERMISSION_IDS}}`, pre-V9 and V9+ variants); §10.7 (exact-set check, `deleted_at IS NULL` from V9); every permission-migration IT seeds a full-catalogue custom role; ADR-0021 D1, follow-on rule | — |
| RC-49 | **Landed** | §0 #21; §10.2 (`flyway repair` as the Flyway DDL user, no widening of `nexus_app`); §11.1 V9 COPY; §14 M8 and M9 | — |
| RC-50 | **Landed** | (a) §5.6, ADR-0021 D8 · (b) §5.1 row 7, ADR-0021 D7 · (c) §0 #20, §10.1, ADR-0024 item 6 · (d) §0 #12, §7.1, §7.2, ADR-0025 1 | — |
| Optional | **Landed** | §9.10 and §14 M7b now say "900 s (the access-token TTL; skew is 0)" | — |

**Tally:** 10 of 10 landed. None is Partial or Wrong. RES-26 and RES-30 are correctly marked as "acceptance pending at Gate 2" and are not claimed as accepted.

### 12.3 Rulings on the Architect's judgement calls

**(a) RC-47.3: the padded replay asserts "never grants", not exit 6. Accepted, with the condition in RC-54(a).**
- **Why it is right.** Under the canonical pattern, `ABC-0001` cannot pass validation, so exit 6 is unreachable for it by construction. That is a stronger control than the lookup: a padded reference is refused before any tenant or DB state is consulted.
- **Exit 6 stays covered** by the exact-string replay and by the cross-tenant replay, which is the case that proves the lookup is global. `ABC-0` is also rejected.
- **Condition.** The IT asserts that an argument-validation refusal is "audited and paged", but §7.1 validates arguments in the runner, before any audit write, and names no exit code for that refusal. The audit row for an invalid argument must also **not** echo the rejected value, or free text reaches audit metadata through the refusal path, which is what the pattern exists to prevent (RC-54(a)).

**(b) RC-45: `require-shared-store=true` goes in with M8, `require-auth=true` with M7. Accepted.**
- A production profile that requires a shared store before the Redis throttle adapter exists would fail to start. Setting the property before its reader exists would only be a dead key.
- Until M8 the throttle is per-JVM. That is RES-11 as already recorded, and nothing new.
- `require-auth` is the property that protects A9's new authorization state, and it lands with A9 in M7, which is what RC-34.1 asked for.
- Condition: M8 gets the same "the `prod` profile resolves the property to `true`" test that M7 has (RC-54(b)).

**(c) RC-42.2: bump timeout of 500 ms per script call. Accepted.**
- It is about 100× the nominal cost of a 500-user batch (§9.4), and it stays under the 2 s platform default.
- A down Redis fails fast, and after the first failed batch the rest of the fan-out is enqueued rather than attempted. So a request pays at most one timeout on a down Redis.
- **Worst case on a slow Redis that still answers:** about 10 s of post-commit fan-out for 10,000 holders (20 × 500 ms), on an admin-only, rare path. That is acceptable, and there is no cap, which is correct: a cap would be a fail-open.
- **The drain cannot starve the audit retry buffer.** Virtual threads are enabled (E2), so each `@Scheduled` execution gets its own thread, and a fixed-delay task never overlaps itself.
- Condition: the scheduling-enablement coupling in E2 must be removed (RC-52).

**(d) RC-46: the three-way classification-flip race. Not accepted as a note. It must be recorded as a residual: RES-45, re-scoped, Low.**
- **The race is real in both directions.**
  - **Direction 1.** DELETE classifies R as non-admin-defining. A catalogue-completing attach then commits: the role is holder-less, so `RBAC_010` does not fire. Assign classifies R as admin-defining and takes M11. Now DELETE holds the role row X and waits on M11's range, while assign holds M11 and waits for the role row S.
  - **Direction 2.** The reverse happens through a demoting detach.
- **Integrity holds**, as §11.1 says: InnoDB rolls back a victim, and both the conditional insert and the holder check are current reads.
- **The victim still gets a 500 (E3).** This project has treated a reachable deadlock that surfaces as a 500 as a named item before (US-017 RES-10, in the `LastAdminLockoutIT` harness), not as a footnote.
- **Why a residual and not a design change.** The trigger is three concurrent admin-only calls on one role, and the outcome is detected and recoverable. A fix would mean either mapping 1213 to 409 (option (b) as a backstop) or re-classifying after the lock and retrying, and neither is proportionate here.
- **The cost of recording it is one row.** "It is not a residual in the Architect's reading" is not a disposition. Recorded in §12.5.

### 12.4 New threats (regressions introduced by Revision 2 only)

#### T-E46 — The per-IP failure bucket can suppress refresh-token reuse detection, while the attacker's own valid refreshes pass · **Medium** · ❌

- **The spec.** §9.7 lists a **reused** token among the failure outcomes that consume `REFRESH_IP_FAIL` "before writing `TOKEN_REFRESH_FAILURE`". When the bucket rejects, the request gets 429 and **no audit row**. Implemented literally, the consume and the 429 come before step 3 (E1), so `revokeFamily` never runs.
- **The attack.** An attacker holds a stolen refresh token and uses it first, so the rotated successor is theirs.
  - They keep the failure bucket of the victim's IP exhausted: 30 junk refreshes a minute from behind the same NAT or, behind the proxy (DF-1), from anywhere.
  - Their own valid refreshes pass, because "a valid token proceeds whatever `REFRESH_IP_FAIL` says". The family bucket allows 30 a minute.
  - When the legitimate owner refreshes with the old token, that is a reuse: it gets 429. The family is **not** revoked, and there is no `TOKEN_REFRESH_REUSE` row. The SPA clears the owner's session on the 429.
  - Net effect: T-4.2's theft response and its evidence are both disabled, and the stolen family lives for its full lifetime.
- **Why this is new.**
  - Today's single `REFRESH_IP` bucket also blocks the owner's refresh, but it blocks the attacker's too, when they share an IP.
  - Revision 2 is the first shape in which the attacker keeps refreshing while the reuse response is suppressed.
- **Severity.** Medium. It needs a stolen refresh token plus a shared IP or the proxied topology. The remedy is a text change in §9.7 and ADR-0022 D8. **Required: RC-51.**

#### T-E47 — Drain failures now trip the read-path state machine: a write-only Redis failure turns off readable epoch checks · **Low** · ❌

- **The combination.** RC-41 counts failures in a sliding window "whatever successes lie between them", and it counts "failures of the post-commit bump and of a drain". RC-42 drains every second in every state.
- **The failure mode.** Redis can fail on writes while reads still work:
  - OOM under `maxmemory-policy noeviction` (ADR-0016 D1);
  - a read-only replica after a misconfigured failover.
- **What happens.** Any instance with a queued bump then records one drain failure a second. It trips degraded-open in about 3 s, although every epoch read would still succeed. It then **skips checks that would have enforced already-recorded revocations**. Exit needs the drain to complete, so the instance stays degraded-open for the full window and then serves 503.
- **Why this is new.** Under Revision 1's "consecutive" rule, the successful reads in between reset the count, so a write-only failure never tripped the machine.
- **Bounds.** It is loud (`bump_failed` pages on every increase, and degraded-open pages after 1 minute), and per-revocation exposure stays bounded by token TTL plus cache TTL. **Required: RC-53.**

**Out-of-scope observation (a Revision 1 carry-over, not a Revision 2 regression).** The epoch task relies on the only `@EnableScheduling` in the codebase, and that one is conditional on the audit retry buffer's escape hatch (E2). With `nexus.identity.audit.retry-buffer.enabled=false`:
- no probe runs, so a degraded instance never recovers and serves 503 until it is restarted;
- no drain runs, so lost bumps are never replayed.

Revision 2 makes the task load-bearing in every state, so it is folded into RC-52.

### 12.5 Residual rows (changed or new)

| # | Residual | Severity | Owner | Disposition |
|---|---|---|---|---|
| **RES-45** *(re-scoped)* | C1 DELETE and admin-defining assign can deadlock only through a concurrent attach or detach that flips R's classification between the two paths' non-locking reads. The victim gets a 500; integrity holds | Low | Architect | Accept. Revisit if the 1213 rate on C1 is ever non-zero in production |
| RES-26 | Unchanged from §11.6 | Medium | Platform Security Owner | **Escalate: acceptance still pending at Gate 2** |
| RES-30 | Unchanged from §11.6; after RC-41 the window also bounds intermittent failure | Medium | SRE + PM | **Escalate: acceptance still pending at Gate 2** |
| RES-40 | Unchanged (Low after RC-43), **conditional on RC-51** | Low | Security | Accept after RC-51 |

### 12.6 Delta required changes

RC-51 is required **before Gate 2 closes** (text-level, M7). RC-52 to RC-54 land as `/breakdown` tasks.

**RC-51 — Reuse detection is never gated by the failure bucket (T-E46, Medium; M7)**
1. §9.7 and ADR-0022 D8: the reuse branch (a revoked token is presented) **always runs `revokeFamily` before the failure bucket is consulted**. Its `TOKEN_REFRESH_REUSE` row is written whenever that call revoked at least one active token. Only a reuse that revoked nothing is subject to `REFRESH_IP_FAIL`, like any other failure outcome.
2. `revokeFamily` returns the number of tokens it revoked (identity, no port change beyond the return type).
3. Tests:
   - `RefreshTokenUseCaseTest`: with the IP's failure bucket exhausted, a replay of a rotated token still revokes the family and writes exactly one `TOKEN_REFRESH_REUSE` row. The attacker's successor token then gets 401 `AUTH_004`.
   - A second replay of the same token, which revokes nothing, is throttled with no row.
   - The RC-43.3 k6 NAT-attacker case asserts that no reuse-detection revocation is suppressed.

**RC-52 — The epoch task does not depend on the retry buffer's escape hatch (§12.4 observation, Low; M7)**
1. §9.1: `PermissionFreshnessService`'s 1 s task is enabled by its own unconditional scheduling configuration, not by `SchedulingConfig`, which is conditional on `nexus.identity.audit.retry-buffer.enabled`.
2. A test: with `nexus.identity.audit.retry-buffer.enabled=false`, the probe and the drain still run.

**RC-53 — Only read-path failures drive the state machine (T-E47, Low; M7)**
1. §9.5 and ADR-0022 D5: only failures of the epoch read and of the probe count towards the 3-in-10 s entry and relapse window. Bump and drain failures keep their entries queued and page through `bump_failed`, as now, but do not by themselves move the instance out of Healthy or Recovering.
2. The exit condition "replay queue drained" is unchanged for an instance that entered degraded state through read failures.
3. `PermissionFreshnessServiceTest`: sustained drain failures with successful reads leave the instance Healthy with checks enforced, and `bump_failed` increments.

**RC-54 — Precision items (Low; tasks)**
- **(a)** §7.1 and §7.3 (M5): argument validation names its exit code. It writes a `ROLE_BREAK_GLASS_GRANT` FAILURE row (reason `INVALID_ARGUMENT`, null `tenant_id`) and emits the paging ERROR, **without the rejected argument values** in metadata or logs. The IT asserts that the padded value appears in neither.
- **(b)** §10.8 (M8): a test asserts that the `prod` profile resolves `nexus.rbac.throttle.require-shared-store=true`, as §9.11 does for `require-auth`.

### 12.7 Final Gate 2 verdict

**Pass, conditional. No Blocker and no High.**

- **Revision 2 outcome:** all ten required changes (RC-41 to RC-50) landed as specified, plus the optional wording item. None is Partial or Wrong.
- **Rulings:**
  - (a), (b) and (c) are accepted, with the precision conditions in RC-52 and RC-54.
  - (d) is not accepted as a note: it is recorded as RES-45 (Low, Architect).
- **New regressions:**
  - one Medium: T-E46 (reuse detection suppressible), which traces to Security's own RC-43 wording;
  - one Low: T-E47;
  - one Revision 1 carry-over folded into RC-52.
- **Before Gate 2 closes:**
  - Fold RC-51 into `03-design.md` §9.7 and ADR-0022 D8. Security spot-checks that one edit; no further pass is needed.
  - Record the RES-26 acceptance (Platform Security Owner) and the RES-30 acceptance (SRE and PM).
- **As `/breakdown` tasks:** RC-52 to RC-54.
- **Merge-checklist additions:**
  - **M7:** the RC-51 tests, including the k6 assertion, are green.
  - **M5:** RC-54(a) is covered.

## 13. Final spot-check — Revision 3 (2026-10-01)

_Narrow spot-check of the Revision 3 edits only: the `03-design.md` Revision 3 changelog, §0 #16, #19 and #26, §7.1, §7.3, §9.1, §9.3, §9.5, §9.7, §9.11, §10.8 and §11.1 (RES-45); ADR-0022 D3, D5 and D8; ADR-0025 items 1 and 6. §0 to §12 are not reopened. No PII._

### 13.1 Verification basis (new facts only)

| # | Claim under test | Verified at | Result |
|---|---|---|---|
| F1 | The reuse branch is unchanged since E1 | `RefreshTokenUseCase.java:114-122` | **Confirmed.** `revokeFamily`, then `TOKEN_REFRESH_REUSE` (FAILURE), then `AUTH_004`. No bucket is consulted today |
| F2 | The current `revokeFamily` signature, end to end | `SecureEventService.java:57-60` (`REQUIRES_NEW`, `void`); `RefreshTokenPort.java:37` (`void`); `JpaRefreshTokenAdapter.java:38-42` (`void`); `JpaRefreshTokenRepository.java:22-24` (`void` JPQL `UPDATE … WHERE familyId = :familyId AND revokedAt IS NULL`) | **`void` at all four layers.** A `@Modifying` JPQL update can return `int`, so "a return-type change only" holds. But the change crosses four layers, not just the port. The only production caller is `RefreshTokenUseCase:116` |
| F3 | What the count counts | The same query | It counts **unrevoked** rows and has no expiry filter. So an expired but unrevoked token counts as "revoked", while the design says "at least one **active** token" (L-1) |
| F4 | The family lookup is indexed | `V2__identity_schema.sql:51` `idx_refresh_tokens_family_id` | **Confirmed.** The pre-bucket `UPDATE` is one indexed statement |
| F5 | Lane of `TOKEN_REFRESH_REUSE` | `AuthEventType.java:89-93`; `AuditLane.java:14`; `application.yml:177` | It is in the **PRIORITY** lane (capacity 200; page at depth 180 or more). This bears on the event type of a reuse that revoked nothing (ruling R4) |

### 13.2 Verdicts

| Item | Verdict | Where | Note |
|---|---|---|---|
| RC-51 | **Landed** | §0 #19; §9.7 (reuse bullet ahead of the failure bullet, "a reuse that revoked nothing" folded into the failure list, the k6 RC-51 clause); §9.11 (three `RefreshTokenUseCaseTest` cases plus the k6 bullet); ADR-0022 D8 (bullet plus the merge-gate sentence) | Ordering, count rule and tests all match RC-51.1 to RC-51.3. Precision items L-1 to L-3 below |
| RC-52 | **Landed** | §0 #16; §9.1 (its own unconditional `@EnableScheduling` in `rbac`, citing `SchedulingConfig.java:21-27`); §9.11 scheduling-independence test; ADR-0022 D5 | "`@EnableScheduling` is idempotent" is correct: the post-processor is registered once, by bean name |
| RC-53 | **Landed** | §0 #16; §9.3 (both the enqueue and the partial-drain bullets); §9.5 entry-threshold text and **all three** failure edges of the diagram ("read or probe failures"); §9.11 `PermissionFreshnessServiceTest` case; ADR-0022 D3 and D5 | The "replay queue drained" exit is kept. Precision item L-4 below |
| RC-54(a) | **Landed** | §7.1 (exit 2, a FAILURE row with `INVALID_ARGUMENT`, null `tenant_id`, the paging ERROR, metadata `{actorType, reason}` only, `targetUserId` and `changeRef` omitted from the ERROR); §7.3 (the IT asserts `ABC-0001` is in neither the row nor the captured logs); ADR-0025 items 1 and 6 | Rulings R1 and R3 |
| RC-54(b) | **Landed** | §10.8 tests: the `prod` profile resolves `require-shared-store=true` | — |
| RES-45 | **Recorded as specified** | §11.1 (statement, both flip triggers, 500 via 1213, integrity holds, Low, Architect, Accept, revisit trigger); §0 #26; changelog | Every element of the §12.5 row is present. One stale reference: L-5 |

**Tally:** 5 of 5 landed (counting RC-54(a) and (b) separately), and RES-45 is recorded. None is Partial or Wrong.

### 13.3 Rulings

**R1. Exit code 2 for argument validation: accepted.**
- 0 is success and 3 to 6 are the refusals. 1 is what Spring Boot and the JVM return for a failed context refresh, which includes the RC-50(d) web-context guard, or for an uncaught exception.
- So 2 collides with nothing and keeps a usage error apart from a crash. That is the conventional meaning of exit 2, and the runbook can branch on it.
- No condition.

**R2. The §0 #26 wording "except through a concurrent classification flip, recorded as RES-45": accepted.**
- It is accurate: option (a) removes the two-path cycle, and the only remaining cycle needs the third, flipping call.
- It names the residual and its disposition.
- The longer §11.1 text carries the mechanism, so the one-line summary needs nothing more.

**R3. The ADR-0025 item 6 note: accepted.**
- "Every invocation writes `ROLE_BREAK_GLASS_GRANT` … including an argument-validation refusal …, whose row carries no argument values" keeps item 6's "every invocation, including refusals" invariant true for the new exit path.
- It matches item 1 and §7.1.
- The §7.2 *Alert* and *Audit* bullets still list `targetUserId` and `changeRef` without the exception. Implementers read §7.2 for the adapter, so a cross-reference is added (L-6). Low, because §7.1 and the §7.3 IT are explicit and would catch a raw echo.

**R4. Event type of a reuse that revoked nothing: accepted as designed, and pinned (L-2).**
- §9.7 routes it to the ordinary failure path, which writes `TOKEN_REFRESH_FAILURE`, so today's `TOKEN_REFRESH_REUSE` row for a repeat replay goes away.
- That is the better choice. A replay that revokes nothing is not a new theft signal: the family is already dead, and its first reuse row exists.
- `TOKEN_REFRESH_REUSE` sits in the PRIORITY lane (F5). Keeping repeat replays out of that lane stops one captured token from crowding out `LOCKOUT` rows during an audit-DB outage, which is the T-D1 hazard. The first, revoking replay keeps the priority row.

### 13.4 Regression check, inside the Revision 3 edits only

**RC-51 ordering (reuse → `revokeFamily` → bucket): sound.**
- **`revokeFamily` comes first and commits.** It is `REQUIRES_NEW` (F2), so the revocation is durable before the bucket is consulted, and a 429 or a later exception cannot undo it.
- **A revoking replay reports, the bucket is skipped.** When the count is 1 or more, the row is written and the bucket is never touched. When the count is 0, the replay takes the ordinary failure path through `tryConsume`.
- **Concurrent replays write exactly one row.** Two concurrent replays of one token serialise on InnoDB row locks in the conditional `UPDATE`: one sees N and the other sees 0. That is what the §9.11 "exactly one row" case asserts.
- **No new race.** An in-flight rotation's uncommitted successor is invisible to the `REQUIRES_NEW` revoke. That race exists in today's code (F1) and is not new.

**Can a reuse that revoked nothing be abused? No new abuse.**
- **The only unthrottled outcome is a replay that revokes at least one token.** It runs `revokeFamily`, gets 401 and writes a PRIORITY row, with no failure bucket.
- **Each one is single-use per family.** It needs a family that still has an unrevoked token, and the call that writes the row also kills that family.
- **Repeating it is costly.** Every repetition needs a new live family. For tokens the attacker does not hold, that means guessing 256-bit values. For their own families, it means a fresh login and one rotation, bounded by the login throttles and the 300/60 s per-IP total.
- **The audit-write bound holds.** The unauthenticated bound stays at today's 30/60 s per source plus at most one row per live family that is killed, and every such row is genuine theft-response evidence.
- **The pre-bucket `UPDATE` is cheap.** It is one indexed statement (F4) and is reachable only by someone holding a revoked token's value, not by guessing.

**Does the revoked count leak anything? No.**
- **The count stays out of the output.** It goes into no response, header, log line or metadata field in §9.7 or ADR-0022 D8. Both outcomes of a revoking replay return today's 401 `AUTH_004`.
- **The only observable difference is a destructive probe.** With the IP's failure bucket exhausted, a live family answers 401 and a dead one answers 429. That tells someone who already holds a revoked token value whether its family was alive. The probe destroys the state it reveals (the family is revoked by the asking), and it gives nothing a theft response would not give anyway.
- **Not a finding.** Recorded only so the count is never added to the response (L-3).

**Other Revision 3 edits: no regression.**
- **RC-53.** A Healthy instance with failing drains stays Healthy while bumps sit in the queue. That is the trade-off RC-53 itself chose, and it is still paged through `bump_failed` and bounded by token TTL plus cache TTL, as RES-31 already accepts.
- **RC-52.** A second, unconditional `@EnableScheduling` changes no existing schedule.
- **RC-54(a).** The new FAILURE row has a null `tenant_id`, the same shape as today's pre-lookup refresh failures (`RefreshTokenUseCase.java:102`, `:109`), so no tenant-scoped audit read can see it. It is reachable only with infra access.

### 13.5 Required changes

**None.** No defect of Medium or higher severity was found in the Revision 3 edits.

**`/breakdown` tasks (Low):**
- **L-1 (M7, RC-51).**
  - **Wording.** Change "at least one **active** token" in §0 #19, §9.7 and ADR-0022 D8 to "at least one **unrevoked** token", which is what the existing `revokedAt IS NULL` update counts (F3).
  - **Why not add an expiry filter.** Revoking and reporting a family whose only unrevoked tokens have expired is harmless, and it is the conservative choice.
- **L-2 (M7, RC-51).** Add a `RefreshTokenUseCaseTest` case: a replay that revoked nothing, with the bucket **not** exhausted, writes one `TOKEN_REFRESH_FAILURE` row (STANDARD lane) and no `TOKEN_REFRESH_REUSE` row (ruling R4).
- **L-3 (M7, RC-51).**
  - **Propagate the count.** It must travel through all four layers in F2: repository `int`, port, adapter, and `SecureEventService.revokeFamily`, which is `REQUIRES_NEW`, so the use case acts on the committed count.
  - **Assert the real count.** The "returns the number of tokens it revoked" assertion belongs in a `JpaRefreshTokenAdapter` / repository IT against MySQL that proves already-revoked rows are excluded. A mock in `RefreshTokenUseCaseTest` cannot prove that.
  - **Keep it out of the response.** The count never enters the HTTP response.
- **L-4 (M7, RC-53).** In §9.5, state whether a drain failure during Recovering resets the 60 s sustain. The recommendation is no, which is consistent with "does not by themselves move the instance out of … Recovering". Add the matching `PermissionFreshnessServiceTest` assertion.
- **L-5 (doc, §11.1).** "Option (b) … would add a residual (RES-45)" now reuses the id for the two-path deadlock that option (a) removed. Drop the id there, so RES-45 means only the three-way flip.
- **L-6 (M5, RC-54(a)).** Add "(omitted on `INVALID_ARGUMENT`, §7.1)" to the §7.2 *Alert* field list and *Audit* metadata list (ruling R3). The runner passes no raw argument to `BreakGlassAlertPort`.

### 13.6 Residual summary (after Revision 3)

| # | Residual | Severity | Owner | Disposition |
|---|---|---|---|---|
| RES-26 | Unchanged from §11.6 | Medium | Platform Security Owner | **Human acceptance required at Gate 2; not yet recorded** |
| RES-30 | Unchanged (a Redis outage longer than the window is a platform-wide authenticated 503; it also bounds intermittent failure) | Medium | SRE + PM | **Human acceptance required at Gate 2; not yet recorded** |
| RES-40 | Successful refreshes loosened by the bucket split | Low | Security | **Accepted.** Its condition (RC-51) is now met |
| RES-45 | Three-way classification-flip deadlock on C1 (a 500 via 1213; integrity holds) | Low | Architect | Accepted (§11.1) |
| RES-31 | Unchanged; with RC-53 it also covers a Healthy instance whose drains keep failing | Low | — | Unchanged |

T-E46 is **closed** by RC-51 and T-E47 by RC-53. No residual is above Medium.

### 13.7 Final Gate 2 verdict

**PASS. No Blocker, no High, no open Medium design defect.**

- RC-51, the only item required before Gate 2, has landed as specified. RC-52 to RC-54 have also landed, and RES-45 is recorded as specified.
- All three rulings are accepted: exit code 2, the §0 #26 wording, and the ADR-0025 item 6 note.
- **Gate 2 can close once these human acceptances are recorded:**
  - RES-26, by the Platform Security Owner;
  - RES-30, by SRE and PM.
  - Security does not accept either on anyone's behalf.
- L-1 to L-6 go to `/breakdown` (M5 or M7, as tagged). No further Security design pass is needed. Phase 7 audits the RC-51 implementation against §13.4.

### 13.8 Gate 2 decision (2026-10-02)

**Gate 2: APPROVED by the story owner.**

- **RES-26** (Medium): **accepted by the story owner**, 2026-10-02. The Platform Security Owner confirms at the M3 merge (re-pass). Review 2026-11-27; Epic-3 hard expiry unchanged.
- **RES-30** (Medium): **accepted by the story owner**, 2026-10-02. SRE + PM confirm at the M7 merge.
- L-1 to L-6 carried to `/breakdown`.
