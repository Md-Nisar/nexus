# Master Compendium — Volume 1: Critical Vulnerabilities (8 Findings)

This volume provides full engineering dossiers for all **8 Critical Vulnerabilities** across the Nexus RBAC subsystem and security perimeter.

---

## Table of Contents
1. [[OR-01] HikariCP Connection Pool Deadlock via `PROPAGATION_REQUIRES_NEW` in `afterCommit()`](#or-01-hikaricp-connection-pool-deadlock-via-propagation_requires_new-in-aftercommit)
2. [[OR-02] TOCTOU Race in `revoke`: Concurrent Role Promotion Bypasses Last-Admin Lockout](#or-02-toctou-race-in-revoke-concurrent-role-promotion-bypasses-last-admin-lockout)
3. [[OR-03] Privilege Escalation / A2 Grant-Subset Bypass on Concurrent Permission Addition](#or-03-privilege-escalation--a2-grant-subset-bypass-on-concurrent-permission-addition)
4. [[OR-3.1-01] Repeatable Read Snapshot Leak in `RoleResolutionService` Mints Stale Permissions with Fresh Epoch](#or-31-01-repeatable-read-snapshot-leak-in-roleresolutionservice-mints-stale-permissions-with-fresh-epoch)
5. [[OR-3.3-01] Cleartext Redis Transport Permitted in Production (Missing SSL/TLS Assertion)](#or-33-01-cleartext-redis-transport-permitted-in-production-missing-ssltls-assertion)
6. [[OR-3.3-02] Asynchronous Startup Warmup in `WarmedFactory` Allows 15-Minute Fail-Open Window Followed by 100% 503 Outage](#or-33-02-asynchronous-startup-warmup-in-warmedfactory-allows-15-minute-fail-open-window-followed-by-100-503-outage)
7. [[OR-4.1-01] Cross-Table Lock Inversion Deadlock Between Promoting Role Changes and Role Deletion/Demotion/Assignment](#or-41-01-cross-table-lock-inversion-deadlock-between-promoting-role-changes-and-role-deletiondemotionassignment)
8. [[OR-4.2-01] Asynchronous Replication Gap at Sentinel Failover Leaves Revocations Unenforced Across Peer Pods](#or-42-01-asynchronous-replication-gap-at-sentinel-failover-leaves-revocations-unenforced-across-peer-pods)

---

### [OR-01] HikariCP Connection Pool Deadlock via `PROPAGATION_REQUIRES_NEW` in `afterCommit()`
- **Components:**
  - [`RoleManagementService.java:187-190, 1621-1630`](file:///C:/entomo/AI/nexus/nexus-backend/src/main/java/com/example/nexus/rbac/application/RoleManagementService.java#L187-L190)
  - [`RoleAssignmentService.java:188-191, 1256-1264`](file:///C:/entomo/AI/nexus/nexus-backend/src/main/java/com/example/nexus/rbac/application/RoleAssignmentService.java#L188-L191)
- **Execution Trace & Root Cause:**
  1. Primary transaction opens on thread $T_1$, acquiring connection $C_1$ from HikariCP.
  2. Transaction commits; Spring executes registered `afterCommit()` synchronizations before releasing $C_1$.
  3. Inside `afterCommit()`, `holderReadTransaction.execute(...)` runs with `PROPAGATION_REQUIRES_NEW`.
  4. The inner transaction requests connection $C_2$ from HikariCP.
  5. Under concurrent load ($\ge 10$ requests with pool size 10), all 10 worker threads hold $C_1$ waiting for $C_2$. The pool deadlocks completely.
- **Minimal Fix:**
```diff
--- a/nexus-backend/src/main/java/com/example/nexus/rbac/application/RoleAssignmentService.java
+++ b/nexus-backend/src/main/java/com/example/nexus/rbac/application/RoleAssignmentService.java
@@ -188,3 +188,3 @@ public class RoleAssignmentService {
     this.holderReadTransaction = new TransactionTemplate(transactionManager);
-    this.holderReadTransaction.setPropagationBehavior(TransactionDefinition.PROPAGATION_REQUIRES_NEW);
+    this.holderReadTransaction.setPropagationBehavior(TransactionDefinition.PROPAGATION_NOT_SUPPORTED);
```
- **Test to Add:** `RoleAssignmentConcurrencyIT.should_not_deadlock_connection_pool_under_concurrency`

---

### [OR-02] TOCTOU Race in `revoke`: Concurrent Role Promotion Bypasses Last-Admin Lockout
- **Component:** [`RoleAssignmentService.java:378-435`](file:///C:/entomo/AI/nexus/nexus-backend/src/main/java/com/example/nexus/rbac/application/RoleAssignmentService.java#L378-L435)
- **Execution Trace & Root Cause:**
  1. Thread 1 (`revoke(Alice, R_2)`) checks if $R_2$ is admin-defining outside lock. It is not, so set locking is skipped.
  2. Thread 2 (`attachPermission(R_2, P_final)`) concurrently promotes $R_2$ to admin-defining.
  3. Thread 3 revokes the tenant's original administrator role $R_1$, passing checks because $R_2$ is now admin-defining.
  4. Thread 1 resumes and revokes $R_2$ from Alice without re-classifying $R_2$. Alice is revoked, leaving 0 administrators.
- **Minimal Fix:** Re-classify target role under lock before executing revocation; abort if classification changed.
- **Test to Add:** `LastAdminLockoutIT.should_abort_revocation_if_role_promoted_concurrently`

---

### [OR-03] Privilege Escalation / A2 Grant-Subset Bypass on Concurrent Permission Addition
- **Component:** [`RoleAssignmentService.java:324-328, 858-891`](file:///C:/entomo/AI/nexus/nexus-backend/src/main/java/com/example/nexus/rbac/application/RoleAssignmentService.java#L324-L328)
- **Execution Trace & Root Cause:**
  1. Caller assigns a non-admin role $R$. The subset check passes for initial permissions $\{P_1, P_2\}$.
  2. Concurrently, an admin attaches high-privilege permission $P_{\text{admin}}$ to $R$.
  3. `requireAssignKeptItsClassification` only checks `current.adminDefining() == target.adminDefining()`. Since $R$ is still non-admin, check passes.
  4. Caller receives $R$ containing $P_{\text{admin}}$, an unauthorized privilege escalation.
- **Minimal Fix:** Verify `heldPermissionIds.containsAll(currentRolePermissionIds)` after insert.
- **Test to Add:** `RoleAssignmentEscalationIT.should_prevent_assign_when_permissions_added_concurrently`

---

### [OR-3.1-01] Repeatable Read Snapshot Leak in `RoleResolutionService` Mints Stale Permissions with Fresh Epoch
- **Components:**
  - [`RoleResolutionService.java:37`](file:///C:/entomo/AI/nexus/nexus-backend/src/main/java/com/example/nexus/rbac/application/RoleResolutionService.java#L37)
  - [`JwtRs256Service.java:119-124`](file:///C:/entomo/AI/nexus/nexus-backend/src/main/java/com/example/nexus/identity/infrastructure/security/JwtRs256Service.java#L119-L124)
- **Execution Trace & Root Cause:**
  1. User logs in. `LoginUseCase` starts a `REPEATABLE READ` transaction.
  2. Admin revokes role, committing in DB and bumping Redis epoch from 1 to 2.
  3. `RoleResolutionService` joins outer transaction via `Propagation.REQUIRED`, reading stale snapshot (showing revoked role).
  4. `JwtRs256Service` reads bumped epoch 2 from Redis. Mints JWT with revoked role and fresh epoch 2.
- **Minimal Fix:** Configure `RoleResolutionService` with `@Transactional(readOnly = true, propagation = Propagation.REQUIRES_NEW)`.
- **Test to Add:** `JwtAuthenticationFilterIT.should_not_mint_stale_permissions_with_fresh_epoch`

---

### [OR-3.3-01] Cleartext Redis Transport Permitted in Production (Missing SSL/TLS Assertion)
- **Components:**
  - [`application-prod.yml:33-36`](file:///C:/entomo/AI/nexus/nexus-backend/src/main/resources/application-prod.yml#L33-L36)
  - [`RedisAuthStartupAssertion.java:39-71`](file:///C:/entomo/AI/nexus/nexus-backend/src/main/java/com/example/nexus/rbac/infrastructure/cache/RedisAuthStartupAssertion.java#L39-L71)
- **Execution Trace & Root Cause:**
  1. `application-prod.yml` omits `ssl.enabled: true`.
  2. `RedisAuthStartupAssertion` verifies password is set, but never asserts `standaloneConfig.isUseSsl()`.
  3. Production nodes transmit auth credentials, epochs, and user IDs in cleartext over TCP port 6379.
- **Minimal Fix:** Throw `IllegalStateException` on startup if `prod` profile is active and `!standaloneConfig.isUseSsl()`.
- **Test to Add:** `RedisAuthStartupAssertionTest.should_fail_startup_in_prod_when_ssl_disabled`

---

### [OR-3.3-02] Asynchronous Startup Warmup in `WarmedFactory` Allows 15-Minute Fail-Open Window Followed by 100% 503 Outage
- **Components:**
  - [`application.yml:46, 133`](file:///C:/entomo/AI/nexus/nexus-backend/src/main/resources/application.yml#L46)
  - [`EpochRedisConfig.java:220-264`](file:///C:/entomo/AI/nexus/nexus-backend/src/main/java/com/example/nexus/rbac/infrastructure/cache/EpochRedisConfig.java#L220-L264)
  - [`PermissionFreshnessService.java:641-670`](file:///C:/entomo/AI/nexus/nexus-backend/src/main/java/com/example/nexus/rbac/application/PermissionFreshnessService.java#L641-L670)
- **Execution Trace & Root Cause:**
  1. Redis is down at boot. Actuator Redis health indicator is disabled (`management.health.redis.enabled: false`).
  2. Context finishes startup; Kubernetes readiness probe passes. Pod serves traffic in fail-open mode for 15 minutes.
  3. At minute 15, `failOpenWindow` elapses. Service flips to `DEGRADED_CLOSED`, dropping 100% of API requests with 503.
- **Minimal Fix:** Enable Redis health indicator in Actuator and set `fail-open-window: 0s` in production.
- **Test to Add:** `HealthProbeConfigurationTest.should_include_redis_in_readiness_probe`

---

### [OR-4.1-01] Cross-Table Lock Inversion Deadlock Between Promoting Role Changes and Role Deletion/Demotion/Assignment
- **Components:**
  - [`RoleManagementService.java:382-386, 586-594, 1128-1133`](file:///C:/entomo/AI/nexus/nexus-backend/src/main/java/com/example/nexus/rbac/application/RoleManagementService.java#L382-L386)
  - [`RoleAssignmentService.java:267, 323`](file:///C:/entomo/AI/nexus/nexus-backend/src/main/java/com/example/nexus/rbac/application/RoleAssignmentService.java#L267)
- **Execution Trace & Root Cause:**
  1. Thread 1 (`attachPermission` promoting role $R$): locks `roles` row first, then attempts to lock `user_roles`.
  2. Thread 2 (`softDeleteRole` or `assign` on role $R$): locks `user_roles` first, then attempts to lock `roles` row.
  3. Both threads block waiting on each other. InnoDB detects deadlock and terminates one with MySQL Error 1213.
- **Minimal Fix:** Enforce strict universal locking order: `roles` row $\rightarrow$ `user_roles` set $\rightarrow$ `role_permissions` rows.
- **Test to Add:** `RoleConcurrencyIT.should_not_deadlock_between_attach_and_delete`

---

### [OR-4.2-01] Asynchronous Replication Gap at Sentinel Failover Leaves Revocations Unenforced Across Peer Pods
- **Components:**
  - [`PermissionFreshnessService.java:469-477`](file:///C:/entomo/AI/nexus/nexus-backend/src/main/java/com/example/nexus/rbac/application/PermissionFreshnessService.java#L469-L477)
  - [`RedisPermissionEpochAdapter.java:122`](file:///C:/entomo/AI/nexus/nexus-backend/src/main/java/com/example/nexus/rbac/infrastructure/cache/RedisPermissionEpochAdapter.java#L122)
- **Execution Trace & Root Cause:**
  1. Redis master crashes before replicating epoch bump to replica. Sentinel promotes replica to master.
  2. Promoted master serves old/stale epoch.
  3. Pod A detects regression (`known.epoch() > current`), but only increments a metric counter without auto-healing Redis.
  4. Pods B through E evaluate revoked tokens as valid indefinitely.
- **Minimal Fix:** Auto-heal regressed Redis master: call `epochPort.bump(tenantId, userId, known.epoch())` on regression detection.
- **Test to Add:** `PermissionFreshnessSentinelIT.should_auto_heal_regressed_epoch_after_failover`
