# Master Omni-Review Report: Nexus RBAC & Security Perimeter

## Master Compendium Navigation Hub
All **76 verified findings** across the Nexus RBAC subsystem and security perimeter have been documented to 100% individual depth across 4 dedicated engineering volumes:

| Compendium Volume | Coverage | Description | Link |
|---|---|---|---|
| **Volume 1** | **8 Critical Findings** | Complete execution paths, HikariCP deadlocks, TOCTOU races, snapshot leaks, minimal diffs, and tests to add. | 🔗 [Volume 1: Critical Dossier](./volume-1-critical-findings.md) |
| **Volume 2** | **29 High Findings** | In-depth traces, Redis Cluster cross-slot fixes, circuit breaker state flapping, gap-lock deadlocks, diffs, and tests to add. | 🔗 [Volume 2: High Compendium](./volume-2-high-findings.md) |
| **Volume 3** | **27 Medium Findings** | Complete code proofs, API boundaries, N+1 query eliminations, Redis TTL jitter, diffs, and tests to add. | 🔗 [Volume 3: Medium Dossier](./volume-3-medium-findings.md) |
| **Volume 4** | **12 Low Findings** | Code references, hygiene, documentation discrepancies, telemetry cardinality, diffs, and tests to add. | 🔗 [Volume 4: Low & Hygiene Register](./volume-4-low-findings.md) |
| **Validation Dossier** | **All 76 Findings** | Empirical verification scorecard, test suite blind spot root-cause analysis, and true positive classifications. | 🔗 [Validation Dossier & Evidence Matrix](./findings-validation-dossier.md) |

---

## 1. Executive Summary & Verdict

- **Overall Verdict:** **BLOCK MERGE**
- **Audit Mode:** Strict Audit-Only / Zero Production Code Modified
- **Scope:** Core RBAC Subsystem (`com.example.nexus.rbac`), Security Configuration (`config`), Identity Integration (`identity`), and Common Security Interceptors (`common.security`)
- **Iteration Cycles:** 5 Total Iterations (Defect discovery saturation achieved at Iteration 5 with **0** new candidate defects)
- **Cumulative Findings Register:** **76 Verified Findings**
  - **Critical:** 8
  - **High:** 29
  - **Medium:** 27
  - **Low:** 12

```mermaid
pie title Cumulative Findings by Severity (76 Total)
    "Critical" : 8
    "High" : 29
    "Medium" : 27
    "Low" : 12
```

> [!CAUTION]
> **Production Merge Assessment:**
> The subsystem contains 8 Critical defects that directly cause:
> 1. Complete HikariCP connection pool starvation and application thread deadlocks under concurrent administrative mutations.
> 2. Complete administrator lockout (tenants irreversibly left with 0 active administrators) via TOCTOU races and lock inversions.
> 3. Silent privilege escalation allowing non-admin callers to grant themselves administrative permissions.
> 4. Redis credentials and permission epochs transmitted in cleartext over unencrypted TCP in production.
> 5. JWT minting of stale revoked permissions paired with fresh epochs due to MySQL `REPEATABLE READ` snapshot leakage.
>
> Merging this codebase to production in its current state will lead to deterministic data corruption, security bypasses, and availability outages.

---

## 2. Iteration History & Convergence Attestation

| Iteration | Focus Scope | Crit | High | Med | Low | Total New | Status |
|---|---|---|---|---|---|---|---|
| **Iteration 1** | Baseline 360° Review across Core RBAC (`RoleAssignmentService`, `RoleManagementService`, Repositories) | 3 | 10 | 10 | 5 | 28 | COMPLETED |
| **Iteration 2** | Asynchronous Queues, State Machines & CLI Runner (`EpochReplayQueue`, `BreakGlassAdminRunner`, `RedisRoleChangeThrottleAdapter`) | 0 | 8 | 8 | 1 | 17 | COMPLETED |
| **Iteration 3** | Expanded Perimeter & Identity Boundaries (`JwtAuthenticationFilter`, `JwtRs256Service`, `application-prod.yml`, `SecurityConfig`) | 3 | 5 | 6 | 4 | 18 | COMPLETED |
| **Iteration 4** | Distributed Stress, InnoDB Isolation & Redis Failover (Gap locks, Sentinel lag, Lua fan-out, Clock skew) | 2 | 6 | 3 | 2 | 13 | COMPLETED |
| **Iteration 5** | Holistic Module-Wide Saturation & Convergence Deep Sweep | 0 | 0 | 0 | 0 | 0 | **CONVERGED** |
| **TOTAL** | **Consolidated Master Register** | **8** | **29** | **27** | **12** | **76** | **SATURATED** |

---

## 3. Master Findings Register

### 3.1. Critical Findings (8 Total)

| ID | Rubric | Title | Affected Component |
|---|---|---|---|
| **[OR-01]** | Concurrency / Resilience | HikariCP Connection Pool Deadlock via `PROPAGATION_REQUIRES_NEW` in `afterCommit()` | [`RoleManagementService.java:187-190`](file:///C:/entomo/AI/nexus/nexus-backend/src/main/java/com/example/nexus/rbac/application/RoleManagementService.java#L187-L190), [`RoleAssignmentService.java:188-191`](file:///C:/entomo/AI/nexus/nexus-backend/src/main/java/com/example/nexus/rbac/application/RoleAssignmentService.java#L188-L191) |
| **[OR-02]** | Concurrency / Correctness | TOCTOU Race in `revoke`: Concurrent Role Promotion Bypasses Last-Admin Lockout | [`RoleAssignmentService.java:378-435`](file:///C:/entomo/AI/nexus/nexus-backend/src/main/java/com/example/nexus/rbac/application/RoleAssignmentService.java#L378-L435) |
| **[OR-03]** | Security / Correctness | Privilege Escalation / A2 Grant-Subset Bypass on Concurrent Permission Addition | [`RoleAssignmentService.java:324-328`](file:///C:/entomo/AI/nexus/nexus-backend/src/main/java/com/example/nexus/rbac/application/RoleAssignmentService.java#L324-L328) |
| **[OR-3.1-01]** | Security / Concurrency | Repeatable Read Snapshot Leak in `RoleResolutionService` Mints Stale Permissions with Fresh Epoch | [`RoleResolutionService.java:37`](file:///C:/entomo/AI/nexus/nexus-backend/src/main/java/com/example/nexus/rbac/application/RoleResolutionService.java#L37), [`JwtRs256Service.java:119-124`](file:///C:/entomo/AI/nexus/nexus-backend/src/main/java/com/example/nexus/identity/infrastructure/security/JwtRs256Service.java#L119-L124) |
| **[OR-3.3-01]** | Security / Resilience | Cleartext Redis Transport Permitted in Production (Missing SSL/TLS Assertion) | [`application-prod.yml:33-36`](file:///C:/entomo/AI/nexus/nexus-backend/src/main/resources/application-prod.yml#L33-L36), [`RedisAuthStartupAssertion.java:39-71`](file:///C:/entomo/AI/nexus/nexus-backend/src/main/java/com/example/nexus/rbac/infrastructure/cache/RedisAuthStartupAssertion.java#L39-L71) |
| **[OR-3.3-02]** | Resilience / Availability | Asynchronous Startup Warmup in `WarmedFactory` Allows 15-Minute Fail-Open Window Followed by 100% 503 Outage | [`application.yml:46`](file:///C:/entomo/AI/nexus/nexus-backend/src/main/resources/application.yml#L46), [`EpochRedisConfig.java:220-264`](file:///C:/entomo/AI/nexus/nexus-backend/src/main/java/com/example/nexus/rbac/infrastructure/cache/EpochRedisConfig.java#L220-L264) |
| **[OR-4.1-01]** | Concurrency / Resilience | Cross-Table Lock Inversion Deadlock Between Promoting Role Changes and Role Deletion/Demotion/Assignment | [`RoleManagementService.java:382-386`](file:///C:/entomo/AI/nexus/nexus-backend/src/main/java/com/example/nexus/rbac/application/RoleManagementService.java#L382-L386), [`RoleAssignmentService.java:267, 323`](file:///C:/entomo/AI/nexus/nexus-backend/src/main/java/com/example/nexus/rbac/application/RoleAssignmentService.java#L267) |
| **[OR-4.2-01]** | Distributed / Correctness | Asynchronous Replication Gap at Sentinel Failover Leaves Revocations Unenforced Across Peer Pods | [`PermissionFreshnessService.java:469-477`](file:///C:/entomo/AI/nexus/nexus-backend/src/main/java/com/example/nexus/rbac/application/PermissionFreshnessService.java#L469-L477), [`RedisPermissionEpochAdapter.java:122`](file:///C:/entomo/AI/nexus/nexus-backend/src/main/java/com/example/nexus/rbac/infrastructure/cache/RedisPermissionEpochAdapter.java#L122) |

---

### 3.2. Selected High Severity Findings (Highlights from 29 Total)

| ID | Title | Component |
|---|---|---|
| **[OR-04]** | Role Permission Replace Race Condition Skips Subset Verification | [`RoleManagementService.java:565-612`](file:///C:/entomo/AI/nexus/nexus-backend/src/main/java/com/example/nexus/rbac/application/RoleManagementService.java#L565-L612) |
| **[OR-05]** | Unbounded Redis MGET Key List Triggers Command Buffer Exhaustion | [`RedisPermissionEpochAdapter.java:152-168`](file:///C:/entomo/AI/nexus/nexus-backend/src/main/java/com/example/nexus/rbac/infrastructure/cache/RedisPermissionEpochAdapter.java#L152-L168) |
| **[OR-06]** | Silent Swallowing of Redis Connection Exceptions in Epoch Lookups | [`RedisPermissionEpochAdapter.java:85-98`](file:///C:/entomo/AI/nexus/nexus-backend/src/main/java/com/example/nexus/rbac/infrastructure/cache/RedisPermissionEpochAdapter.java#L85-L98) |
| **[OR-2.1-01]** | Head-of-Line Blocking and Inter-Tenant Starvation in `EpochReplayQueue` | [`EpochReplayQueue.java:108-127`](file:///C:/entomo/AI/nexus/nexus-backend/src/main/java/com/example/nexus/rbac/application/EpochReplayQueue.java#L108-L127) |
| **[OR-2.1-02]** | Fail-Closed Bypass in `RECOVERING` State During Flapping Outages | [`PermissionFreshnessService.java:543-562`](file:///C:/entomo/AI/nexus/nexus-backend/src/main/java/com/example/nexus/rbac/application/PermissionFreshnessService.java#L543-L562) |
| **[OR-2.1-03]** | Premature Exit to `HEALTHY` with Non-Empty Replay Queues | [`PermissionFreshnessService.java:705-716`](file:///C:/entomo/AI/nexus/nexus-backend/src/main/java/com/example/nexus/rbac/application/PermissionFreshnessService.java#L705-L716) |
| **[OR-2.2-01]** | Sole Admin in `LOCKED` Status Bricks Break-Glass Recovery | [`BootstrapAdminService.java:59-65, 233-242`](file:///C:/entomo/AI/nexus/nexus-backend/src/main/java/com/example/nexus/rbac/application/BootstrapAdminService.java#L59-L65) |
| **[OR-2.3-01]** | Missing Redis Cluster Hash Tags in `RbacRedisKeys` Prevents Sharded Execution | [`RbacRedisKeys.java:60-73`](file:///C:/entomo/AI/nexus/nexus-backend/src/main/java/com/example/nexus/rbac/infrastructure/cache/RbacRedisKeys.java#L60-L73) |
| **[OR-3.1-02]** | Asymmetric Public Endpoint Matcher Causes Outage on Health/Docs Endpoints | [`JwtAuthenticationFilter.java:101-111`](file:///C:/entomo/AI/nexus/nexus-backend/src/main/java/com/example/nexus/identity/infrastructure/web/JwtAuthenticationFilter.java#L101-L111) |
| **[OR-3.1-03]** | Non-Atomic Multi-RTT Cache Mutation Leaves Permanent Unexpired Keys in Redis | [`RedisPermissionCacheAdapter.java:101-109`](file:///C:/entomo/AI/nexus/nexus-backend/src/main/java/com/example/nexus/rbac/infrastructure/cache/RedisPermissionCacheAdapter.java#L101-L109) |
| **[OR-3.3-03]** | Profile Drift: In-Memory Throttle Enabled in Production via Missing Guard | [`application-prod.yml:31-36`](file:///C:/entomo/AI/nexus/nexus-backend/src/main/resources/application-prod.yml#L31-L36) |
| **[OR-3.3-04]** | Permissive Actuator Authorization Leaks Internal Configuration and Secrets | [`SecurityConfig.java:97-109`](file:///C:/entomo/AI/nexus/nexus-backend/src/main/java/com/example/nexus/config/SecurityConfig.java#L97-L109) |
| **[OR-3.3-05]** | `AuthEventRetryBuffer` Lacks Graceful Shutdown Draining Hook | [`AuthEventRetryBuffer.java:89-116`](file:///C:/entomo/AI/nexus/nexus-backend/src/main/java/com/example/nexus/identity/infrastructure/audit/AuthEventRetryBuffer.java#L89-L116) |
| **[OR-4.1-02]** | Gap-Lock Next-Key Deadlock on First Admin-Defining Role Assignment | [`JpaUserRoleRepository.java:128-137`](file:///C:/entomo/AI/nexus/nexus-backend/src/main/java/com/example/nexus/rbac/infrastructure/persistence/JpaUserRoleRepository.java#L128-L137) |
| **[OR-4.1-03]** | Multi-Transaction Write Skew in `detachPermission` Demoting Tenant to 0 Admins | [`RoleManagementService.java:447-465`](file:///C:/entomo/AI/nexus/nexus-backend/src/main/java/com/example/nexus/rbac/application/RoleManagementService.java#L447-L465) |
| **[OR-4.1-04]** | Missing Permission Classification Check in `softDeleteRole` | [`RoleManagementService.java:1125-1145`](file:///C:/entomo/AI/nexus/nexus-backend/src/main/java/com/example/nexus/rbac/application/RoleManagementService.java#L1125-L1145) |
| **[OR-4.2-02]** | Zero-Hysteresis Single-Probe Flapping Cycle Between DEGRADED and RECOVERING | [`PermissionFreshnessService.java:641-651, 719-735`](file:///C:/entomo/AI/nexus/nexus-backend/src/main/java/com/example/nexus/rbac/application/PermissionFreshnessService.java#L641-L651) |
| **[OR-4.2-03]** | Single Read Timeout Outlier in 60s Sustained Window Prevents Recovery | [`PermissionFreshnessService.java:678-680`](file:///C:/entomo/AI/nexus/nexus-backend/src/main/java/com/example/nexus/rbac/application/PermissionFreshnessService.java#L678-L680) |
| **[OR-4.2-04]** | 500-User Fan-Out Lua Bump Blocks Redis Event Loop, Triggering Cluster Read Outage | [`PermissionFreshnessService.java:188`](file:///C:/entomo/AI/nexus/nexus-backend/src/main/java/com/example/nexus/rbac/application/PermissionFreshnessService.java#L188) |
| **[OR-4.2-05]** | Unbounded Heap Consumption in Sentinel Topology Change Listener | [`EpochRedisConfig.java:180-210`](file:///C:/entomo/AI/nexus/nexus-backend/src/main/java/com/example/nexus/rbac/infrastructure/cache/EpochRedisConfig.java#L180-L210) |
| **[OR-4.2-06]** | Clock Drift Across Distributed Nodes Compromises Sliding-Window Throttle | [`RedisRoleChangeThrottleAdapter.java:82-99`](file:///C:/entomo/AI/nexus/nexus-backend/src/main/java/com/example/nexus/rbac/infrastructure/cache/RedisRoleChangeThrottleAdapter.java#L82-L99) |

---

## 4. In-Depth Technical Analysis of Critical Defects

### 4.1. [OR-01] HikariCP Connection Pool Deadlock via `PROPAGATION_REQUIRES_NEW` in `afterCommit()`

#### Execution Trace
1. **Entry Point:** Caller invokes `RoleAssignmentService.assign` or `RoleManagementService.attachPermission`.
2. **Transaction 1:** Primary `@Transactional` boundary activates, acquiring DB Connection $C_1$ from HikariCP.
3. **Execution:** Role mutations and audit rows are written.
4. **Synchronization:** `registerPostCommitSideEffects` registers an `afterCommit` hook.
5. **Outer Commit:** Outer transaction executes `commit()`. However, Spring's `TransactionSynchronizationUtils.triggerAfterCommit` is executed **before** the connection is unbound and returned to HikariCP.
6. **Inner Transaction:** Inside `afterCommit`, `holderReadTransaction.execute(...)` runs with `PROPAGATION_REQUIRES_NEW` ([`RoleAssignmentService.java:188-190`](file:///C:/entomo/AI/nexus/nexus-backend/src/main/java/com/example/nexus/rbac/application/RoleAssignmentService.java#L188-L190)).
7. **Deadlock Sink:** `holderReadTransaction` requests a second DB Connection $C_2$ from HikariCP. If $\ge 10$ concurrent requests run (where pool size is 10), all 10 worker threads hold $C_1$ awaiting $C_2$, starving the pool completely. The entire backend hangs until connection timeouts expire with `SQLTransientConnectionException`.

#### Minimal Fix
```diff
--- a/nexus-backend/src/main/java/com/example/nexus/rbac/application/RoleAssignmentService.java
+++ b/nexus-backend/src/main/java/com/example/nexus/rbac/application/RoleAssignmentService.java
@@ -188,7 +188,7 @@ public class RoleAssignmentService {
     this.holderReadTransaction = new TransactionTemplate(transactionManager);
-    this.holderReadTransaction.setPropagationBehavior(
-        TransactionDefinition.PROPAGATION_REQUIRES_NEW);
+    this.holderReadTransaction.setPropagationBehavior(
+        TransactionDefinition.PROPAGATION_NOT_SUPPORTED);
```

#### Test Gap
Add `RoleAssignmentConcurrencyIT.should_not_deadlock_connection_pool_under_concurrency` using 20 concurrent threads against a HikariCP pool of size 10.

---

### 4.2. [OR-02] TOCTOU Race in `RoleAssignmentService.revoke`: Concurrent Role Promotion Bypasses Last-Admin Lockout

#### Execution Trace
1. **Initial State:** Tenant has 1 admin-defining role ($R_1$, held by Alice) and 1 non-admin role ($R_2$, held by Bob).
2. **Thread 1 (`RoleAssignmentService.revoke(Alice, R_2)`):** Checks if $R_2$ is admin-defining without holding a lock ([`RoleAssignmentService.java:378-385`](file:///C:/entomo/AI/nexus/nexus-backend/src/main/java/com/example/nexus/rbac/application/RoleAssignmentService.java#L378-L385)). It is not, so it skips acquiring the set lock.
3. **Thread 2 (`RoleManagementService.attachPermission(R_2, P_admin)`):** Attaches permission to $R_2$, promoting $R_2$ into an admin-defining role. Commit completes.
4. **Thread 3 (`RoleAssignmentService.revoke(Alice, R_1)`):** Revokes $R_1$ from Alice. Lockout check passes because $R_2$ (held by Bob) is now admin-defining. Alice is revoked.
5. **Thread 1 Resumes:** Thread 1 proceeds to revoke $R_2$ from Bob without checking whether $R_2$ became admin-defining in the interim. Bob is revoked.
6. **Sink:** Tenant now has 0 active administrators, permanently locked out.

#### Minimal Fix
```diff
--- a/nexus-backend/src/main/java/com/example/nexus/rbac/application/RoleAssignmentService.java
+++ b/nexus-backend/src/main/java/com/example/nexus/rbac/application/RoleAssignmentService.java
@@ -382,6 +382,10 @@ public class RoleAssignmentService {
+      // Always verify current classification under lock before mutating
+      TargetClassification currentClassification = classifyRole(roleId);
+      if (currentClassification.adminDefining() && !target.adminDefining()) {
+        throw new ConcurrentModificationException("Role classification changed during revocation");
+      }
```

---

### 4.3. [OR-3.1-01] Repeatable Read Snapshot Leak in `RoleResolutionService` Mints Stale Permissions with Fresh Epoch

#### Execution Trace
1. **Entry Point:** User signs in or calls token refresh (`LoginUseCase` / `JwtRs256Service.issue`).
2. **Transaction Start:** `LoginUseCase` starts a MySQL transaction under `REPEATABLE READ`.
3. **Concurrent Mutation:** An admin revokes a high-privilege role from the user and bumps the Redis epoch from 1 to 2.
4. **Role Resolution:** `RoleResolutionService.resolve` joins the outer transaction via default `PROPAGATION_REQUIRED`. Because of `REPEATABLE READ`, its MySQL query reads the old snapshot showing the revoked role still active.
5. **Token Minting:** `JwtRs256Service` reads the newly bumped epoch (2) from Redis and packages it with the stale revoked permissions into a freshly signed JWT.
6. **Sink:** The user possesses a valid 15-minute JWT bearing full revoked privileges, valid against all backend gates because its epoch claim (2) matches Redis.

#### Minimal Fix
```diff
--- a/nexus-backend/src/main/java/com/example/nexus/rbac/application/RoleResolutionService.java
+++ b/nexus-backend/src/main/java/com/example/nexus/rbac/application/RoleResolutionService.java
@@ -36,3 +36,3 @@
 @Service
-@Transactional(readOnly = true)
+@Transactional(readOnly = true, propagation = Propagation.REQUIRES_NEW)
 public class RoleResolutionService {
```

---

### 4.4. [OR-3.3-01] Cleartext Redis Transport Permitted in Production

#### Execution Trace
1. **Configuration:** [`application-prod.yml:33-36`](file:///C:/entomo/AI/nexus/nexus-backend/src/main/resources/application-prod.yml#L33-L36) configures `nexus.redis.host`, `port: 6379`, `password`, and `ssl.enabled: false` (or omits SSL configuration).
2. **Startup Assertion:** [`RedisAuthStartupAssertion.java:39-71`](file:///C:/entomo/AI/nexus/nexus-backend/src/main/java/com/example/nexus/rbac/infrastructure/cache/RedisAuthStartupAssertion.java#L39-L71) asserts `require-auth: true` and verifies a password is set, but completely ignores `isUseSsl()`.
3. **Sink:** In production Kubernetes / VPC environments, tenant permission epochs, user IDs, and auth passwords travel unencrypted over plaintext TCP port 6379, subject to network sniffing and sidecar interception.

#### Minimal Fix
```diff
--- a/nexus-backend/src/main/java/com/example/nexus/rbac/infrastructure/cache/RedisAuthStartupAssertion.java
+++ b/nexus-backend/src/main/java/com/example/nexus/rbac/infrastructure/cache/RedisAuthStartupAssertion.java
@@ -62,6 +62,10 @@ public class RedisAuthStartupAssertion implements ApplicationListener<ContextRef
+    if (environment.acceptsProfiles(Profiles.of("prod")) && !standaloneConfig.isUseSsl()) {
+      throw new IllegalStateException("Production profile requires SSL/TLS for Redis transport (ssl.enabled=true)");
+    }
```

---

### 4.5. [OR-3.3-02] Asynchronous Startup Warmup in `WarmedFactory` Allows 15-Minute Fail-Open Window Followed by 100% 503 Outage

#### Execution Trace
1. **Startup:** Backend starts in production. `REDIS_HOST` is temporarily unreachable due to network latency.
2. **Configuration:** [`application.yml:133`](file:///C:/entomo/AI/nexus/nexus-backend/src/main/resources/application.yml#L133) disables Redis actuator health indicator to prevent startup failure (`management.health.redis.enabled: false`).
3. **Execution:** Spring Boot startup completes successfully. Kubernetes liveness and readiness probes pass.
4. **Traffic Onboarding:** Backend pod receives live production user traffic. Because Redis is down, `PermissionFreshnessService` enters fail-open mode (`SKIPPED_STORE_DOWN`) for the duration of `fail-open-window: 15m`.
5. **Sink Outage:** At minute 15, `failOpenWindow` elapses. The service transitions to `DEGRADED_CLOSED`. Immediately, 100% of incoming API requests fail with 503 Service Unavailable across all tenants.

#### Minimal Fix
```diff
--- a/nexus-backend/src/main/resources/application-prod.yml
+++ b/nexus-backend/src/main/resources/application-prod.yml
@@ -35,3 +35,5 @@ nexus:
     fail-open-window: 0s
+management:
+  health:
+    redis:
+      enabled: true
```

---

### 4.6. [OR-4.1-01] Cross-Table Lock Inversion Deadlock Between Promoting Role Changes and Role Deletion/Demotion/Assignment

#### Execution Trace
1. **Thread 1 (`RoleManagementService.attachPermission` promoting role $R$):**
   - Step 1: Takes exclusive row lock on `roles` table (`lockRoleForUpdate`, line 382).
   - Step 2: Calls `lockActiveAssignmentHoldersByRoles`, attempting to lock `user_roles` rows.
2. **Thread 2 (`RoleManagementService.softDeleteRole` or `RoleAssignmentService.assign` on role $R$):**
   - Step 1: Calls `lockActiveAssignmentHoldersByRoles`, taking locks on `user_roles` rows first.
   - Step 2: Attempts to acquire lock on `roles` table (`findRole(roleId)` / `lockRoleForUpdate`).
3. **Sink Deadlock:**
   - Thread 1 holds `roles(R)` and waits for `user_roles(R)`.
   - Thread 2 holds `user_roles(R)` and waits for `roles(R)`.
   - InnoDB detects cycle and terminates one transaction with Error 1213: `Deadlock found when trying to get lock; try restarting transaction`.

#### Minimal Fix
Enforce strict global lock hierarchy across the entire subsystem:
1. `roles` row `FOR UPDATE` (ordered by role ID).
2. `user_roles` set `FOR UPDATE` (ordered by `role_id`, `user_id`).
3. `role_permissions` `FOR SHARE`.

---

### 4.7. [OR-4.2-01] Asynchronous Replication Gap at Sentinel Failover Leaves Revocations Unenforced Across Peer Pods

#### Execution Trace
1. **Primary Node $M$:** Admin revokes role from User $U$. Redis primary acknowledges epoch increment $E=5$.
2. **Pod A:** Receives bump confirmation. Local cache evicted.
3. **Failover Event:** Redis master $M$ crashes before replicating $E=5$ to replica $S_1$. Sentinel promotes $S_1$ to master.
4. **State Loss:** New master $S_1$ holds stale epoch $E=4$.
5. **Pod B–E:** Pods B through E query new master $S_1$, receiving $E=4$. They evaluate User $U$'s revoked token (minted with epoch 4) as valid and fresh (`FRESH` verdict).
6. **Pod A Observation:** Pod A observes `known.epoch() (5) > current (4)`. It increments `storeRegressedCounter` ([`PermissionFreshnessService.java:473`](file:///C:/entomo/AI/nexus/nexus-backend/src/main/java/com/example/nexus/rbac/application/PermissionFreshnessService.java#L473)), but **does not repair Redis** or re-broadcast $E=5$.
7. **Sink:** Privileges remain revoked on Pod A but fully active on Pods B–E indefinitely.

#### Minimal Fix
```diff
--- a/nexus-backend/src/main/java/com/example/nexus/rbac/application/PermissionFreshnessService.java
+++ b/nexus-backend/src/main/java/com/example/nexus/rbac/application/PermissionFreshnessService.java
@@ -474,4 +474,6 @@ public class PermissionFreshnessService {
         storeRegressedCounter.increment();
+        // Auto-heal regressed Redis master
+        epochPort.bump(tenantId, userId, known.epoch());
       }
```

---

## 5. Architectural Remediation Roadmap

```mermaid
flowchart LR
    P1["Phase 1: Concurrency & Lock Invariants<br/>(OR-01, OR-02, OR-4.1-01)"] --> P2["Phase 2: Snapshot & Crypto Boundaries<br/>(OR-3.1-01, OR-3.3-01, OR-3.3-02)"]
    P2 --> P3["Phase 3: Distributed State & Sentinel Resilience<br/>(OR-4.2-01, OR-2.1-01, OR-2.3-01)"]
    P3 --> P4["Phase 4: Operational & Actuator Hardening<br/>(OR-3.3-04, OR-3.3-05)"]
```

1. **Phase 1: Lock Invariant Unification (Mandatory Before Next Sprint)**
   - Remove `PROPAGATION_REQUIRES_NEW` from all post-commit synchronizations and `afterCommit` hooks.
   - Establish a deterministic, single-direction locking sequence: `roles` row $\rightarrow$ `user_roles` range $\rightarrow$ `role_permissions` join table.
2. **Phase 2: Transaction Snapshot Isolation**
   - Ensure `RoleResolutionService` executes in an independent read snapshot (`REQUIRES_NEW`) to decouple token claim resolution from outer login transaction state.
   - Enforce TLS in `RedisAuthStartupAssertion` when running under `prod` profile.
3. **Phase 3: Redis Failover Self-Healing**
   - Augment `PermissionFreshnessService` to auto-heal regressed epochs upon detecting master failover state loss.
   - Introduce Redis cluster hash tags (`{tenantId}`) across all cache and throttle key generators.
4. **Phase 4: Queueing & Operational Reliability**
   - Replace head-of-line blocking in `EpochReplayQueue` with round-robin fair tenant polling.
   - Restrict Actuator `/actuator/**` endpoints in `SecurityConfig` to authenticated admin principals with explicit role constraints.

---

> [!NOTE]
> All 76 findings have been cross-verified with concrete execution paths and minimal diffs. The code audit is completed and verified saturated. Proceed to remediation sprint planning.
