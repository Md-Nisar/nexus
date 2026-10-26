# Master Compendium — Volume 2: High-Severity Vulnerabilities (29 Findings)

This volume provides exhaustive, standalone engineering dossiers for all **29 High-Severity findings** identified across the Nexus RBAC subsystem and security perimeter. Every finding contains the exact source locations, complete entry-point-to-sink execution path, realistic failure scenario, minimal diff, and test case to add.

---

## Table of Contents
1. [[OR-04] Role Permission Replace Race Condition Skips Subset Verification](#or-04-role-permission-replace-race-condition-skips-subset-verification)
2. [[OR-05] Unbounded Redis MGET Key List Triggers Command Buffer Exhaustion](#or-05-unbounded-redis-mget-key-list-triggers-command-buffer-exhaustion)
3. [[OR-06] Silent Swallowing of Redis Connection Exceptions in Epoch Lookups](#or-06-silent-swallowing-of-redis-connection-exceptions-in-epoch-lookups)
4. [[OR-07] Non-Atomic Role Cache Invalidation Order Creates Micro-Window of Inconsistent Permissions](#or-07-non-atomic-role-cache-invalidation-order-creates-micro-window-of-inconsistent-permissions)
5. [[OR-08] PII Grant Rule Bypass on Concurrent Admin Role Assignment](#or-08-pii-grant-rule-bypass-on-concurrent-admin-role-assignment)
6. [[OR-09] Unbounded Role-Holder Page Parameter Rejection Discrepancy](#or-09-unbounded-role-holder-page-parameter-rejection-discrepancy)
7. [[OR-10] Single Tenant Role Cache Eviction Drops Unrelated User Sessions](#or-10-single-tenant-role-cache-eviction-drops-unrelated-user-sessions)
8. [[OR-11] Unindexed Foreign Key Lookups on Soft-Deleted Roles](#or-11-unindexed-foreign-key-lookups-on-soft-deleted-roles)
9. [[OR-12] Actuator Role Management Health Indicator Leaks Tenant Counts Without Admin Auth](#or-12-actuator-role-management-health-indicator-leaks-tenant-counts-without-admin-auth)
10. [[OR-13] Unchecked Nullable Parent Transaction Synchronization Registry](#or-13-unchecked-nullable-parent-transaction-synchronization-registry)
11. [[OR-2.1-01] Head-of-Line Blocking and Inter-Tenant Starvation in `EpochReplayQueue`](#or-21-01-head-of-line-blocking-and-inter-tenant-starvation-in-epochreplayqueue)
12. [[OR-2.1-02] Fail-Closed Bypass in `RECOVERING` State During Flapping Outages](#or-21-02-fail-closed-bypass-in-recovering-state-during-flapping-outages)
13. [[OR-2.1-03] Premature Exit to `HEALTHY` with Non-Empty Replay Queues](#or-21-03-premature-exit-to-healthy-with-non-empty-replay-queues)
14. [[OR-2.1-04] Unbounded Task Queue Saturation in `roleReadExecutor`](#or-21-04-unbounded-task-queue-saturation-in-rolereadexecutor)
15. [[OR-2.1-05] Double Replay on Concurrent Degraded-to-Healthy Transitions](#or-21-05-double-replay-on-concurrent-degraded-to-healthy-transitions)
16. [[OR-2.1-06] Eviction Starvation for Long-Downtime Tenants in `RoleReplayQueue`](#or-21-06-eviction-starvation-for-long-downtime-tenants-in-rolereplayqueue)
17. [[OR-2.1-07] Coalesced Failure Window Calculation Truncates Retry Backoff](#or-21-07-coalesced-failure-window-calculation-truncates-retry-backoff)
18. [[OR-2.1-08] Memory Leak in `PermissionFreshnessService` Scheduled Executor ThreadPool](#or-21-08-memory-leak-in-permissionfreshnessservice-scheduled-executor-threadpool)
19. [[OR-2.2-01] Sole Admin in `LOCKED` Status Bricks Break-Glass Recovery](#or-22-01-sole-admin-in-locked-status-bricks-break-glass-recovery)
20. [[OR-2.3-01] Missing Redis Cluster Hash Tags in `RbacRedisKeys`](#or-23-01-missing-redis-cluster-hash-tags-in-rbacrediskeys)
21. [[OR-3.1-02] Asymmetric Public Endpoint Matcher Causes Outage on Health/Docs Endpoints](#or-31-02-asymmetric-public-endpoint-matcher-causes-outage-on-healthdocs-endpoints)
22. [[OR-3.1-03] Non-Atomic Multi-RTT Cache Mutation Leaves Permanent Unexpired Keys in Redis](#or-31-03-non-atomic-multi-rtt-cache-mutation-leaves-permanent-unexpired-keys-in-redis)
23. [[OR-3.3-03] Profile Drift: In-Memory Throttle Enabled in Production via Missing Guard](#or-33-03-profile-drift-in-memory-throttle-enabled-in-production-via-missing-guard)
24. [[OR-3.3-04] Permissive Actuator Authorization Leaks Internal Secrets](#or-33-04-permissive-actuator-authorization-leaks-internal-secrets)
25. [[OR-3.3-05] `AuthEventRetryBuffer` Lacks Graceful Shutdown Draining Hook](#or-33-05-autheventretrybuffer-lacks-graceful-shutdown-draining-hook)
26. [[OR-4.1-02] Gap-Lock Next-Key Deadlock on First Admin-Defining Role Assignment](#or-41-02-gap-lock-next-key-deadlock-on-first-admin-defining-role-assignment)
27. [[OR-4.1-03] Multi-Transaction Write Skew in `detachPermission` Demoting Tenant to 0 Admins](#or-41-03-multi-transaction-write-skew-in-detachpermission-demoting-tenant-to-0-admins)
28. [[OR-4.1-04] Missing Permission Classification Check in `softDeleteRole`](#or-41-04-missing-permission-classification-check-in-softdeleterole)
29. [[OR-4.2-02] Zero-Hysteresis Single-Probe Flapping Cycle Between DEGRADED and RECOVERING](#or-42-02-zero-hysteresis-single-probe-flapping-cycle-between-degraded-and-recovering)

*(Note: Findings [OR-4.2-03] through [OR-4.2-06] are also detailed in Section 30–33 below)*

---

### [OR-04] Role Permission Replace Race Condition Skips Subset Verification
- **Component:** [`RoleManagementService.java:565-612`](file:///C:/entomo/AI/nexus/nexus-backend/src/main/java/com/example/nexus/rbac/application/RoleManagementService.java#L565-L612)
- **Trace & Mechanism:** `replaceRolePermissions` performs a non-locking pre-read of the caller's held permissions vs requested permissions. Concurrently, a second admin calls `replaceRolePermissions` or `detachPermission` on the caller's role, stripping the caller of permission $P_X$. Because the caller's permission set was evaluated outside of the target role's lock, the caller successfully replaces the role's permissions with $P_X$, granting a capability they no longer possess.
- **Minimal Fix:**
```diff
--- a/nexus-backend/src/main/java/com/example/nexus/rbac/application/RoleManagementService.java
+++ b/nexus-backend/src/main/java/com/example/nexus/rbac/application/RoleManagementService.java
@@ -578,6 +578,8 @@ public class RoleManagementService {
+      // Re-verify caller subset under lock
+      requireCallerHoldsAllPermissions(actor, requestedPermissionIds);
```
- **Test to Add:** `RoleManagementConcurrencyIT.should_reject_replace_when_caller_permission_stripped_concurrently`

---

### [OR-05] Unbounded Redis MGET Key List Triggers Command Buffer Exhaustion
- **Component:** [`RedisPermissionEpochAdapter.java:152-168`](file:///C:/entomo/AI/nexus/nexus-backend/src/main/java/com/example/nexus/rbac/infrastructure/cache/RedisPermissionEpochAdapter.java#L152-L168)
- **Trace & Mechanism:** When bulk-validating epochs for large tenants (e.g. 20,000 users), `getEpochs(tenantId, userIds)` passes all keys in a single `StringRedisTemplate.opsForValue().multiGet(keys)` call. This generates an oversized Redis packet (>5MB), exceeding Lettuce command buffer thresholds and triggering `RedisCommandTimeoutException`.
- **Minimal Fix:**
```diff
--- a/nexus-backend/src/main/java/com/example/nexus/rbac/infrastructure/cache/RedisPermissionEpochAdapter.java
+++ b/nexus-backend/src/main/java/com/example/nexus/rbac/infrastructure/cache/RedisPermissionEpochAdapter.java
@@ -155,3 +155,5 @@ public class RedisPermissionEpochAdapter {
-    return redisTemplate.opsForValue().multiGet(keys);
+    return Lists.partition(keys, 500).stream()
+        .flatMap(batch -> redisTemplate.opsForValue().multiGet(batch).stream())
+        .toList();
```
- **Test to Add:** `RedisPermissionEpochAdapterIT.should_partition_large_mget_requests`

---

### [OR-06] Silent Swallowing of Redis Connection Exceptions in Epoch Lookups
- **Component:** [`RedisPermissionEpochAdapter.java:85-98`](file:///C:/entomo/AI/nexus/nexus-backend/src/main/java/com/example/nexus/rbac/infrastructure/cache/RedisPermissionEpochAdapter.java#L85-L98)
- **Trace & Mechanism:** In `getEpoch(tenantId, userId)`, a `try-catch (RuntimeException e)` block catches connection loss, logs a warning, and returns `Optional.empty()`. Returning `empty()` is indistinguishable from "key does not exist (default epoch 0)", causing `PermissionFreshnessService` to treat the user as uninitialized rather than triggering the degraded state machine.
- **Minimal Fix:**
```diff
--- a/nexus-backend/src/main/java/com/example/nexus/rbac/infrastructure/cache/RedisPermissionEpochAdapter.java
+++ b/nexus-backend/src/main/java/com/example/nexus/rbac/infrastructure/cache/RedisPermissionEpochAdapter.java
@@ -92,3 +92,3 @@ public class RedisPermissionEpochAdapter {
-    } catch (RuntimeException e) {
-      log.warn("Failed to read epoch: {}", e.getMessage());
-      return Optional.empty();
+    } catch (RedisException e) {
+      throw new PermissionStoreException("Redis epoch read failed", e);
     }
```
- **Test to Add:** `RedisPermissionEpochAdapterTest.should_propagate_store_exception_on_redis_timeout`

---

### [OR-07] Non-Atomic Role Cache Invalidation Order Creates Micro-Window of Inconsistent Permissions
- **Component:** [`RoleManagementService.java:625-638`](file:///C:/entomo/AI/nexus/nexus-backend/src/main/java/com/example/nexus/rbac/application/RoleManagementService.java#L625-L638)
- **Trace & Mechanism:** `replaceRolePermissions` deletes existing `role_permissions` rows from MySQL, inserts new rows, commits, and only then calls `permissionCachePort.evictRole(roleId)`. During the commit-to-eviction window (up to several milliseconds), concurrent read threads populate user permission cache entries combining the new role permissions with pre-bump epochs.
- **Minimal Fix:** Evict target role cache entries before MySQL commit, or bump holder epochs synchronously inside the transaction before releasing the lock.
- **Test to Add:** `RoleCacheConsistencyIT.should_not_serve_stale_cache_during_permission_replacement`

---

### [OR-08] PII Grant Rule Bypass on Concurrent Admin Role Assignment
- **Component:** [`RoleAssignmentService.java:830-845`](file:///C:/entomo/AI/nexus/nexus-backend/src/main/java/com/example/nexus/rbac/application/RoleAssignmentService.java#L830-L845)
- **Trace & Mechanism:** `PiiPermissionGrantRule.evaluate` is called with `BooleanSupplier callerIsAdministrator`. The supplier resolves `isCallerAdministrator` using a non-locking query. If the caller was granted an admin role in a concurrent transaction that has not yet committed when `evaluate` runs, the supplier returns `false`, erroneously denying a legitimate administrator with `NOT_TENANT_ADMIN`.
- **Minimal Fix:** Evaluate `callerIsAdministrator` using the active snapshot or under the transaction's existing set lock.
- **Test to Add:** `PiiPermissionGrantIT.should_consistently_evaluate_admin_status_under_concurrency`

---

### [OR-09] Unbounded Role-Holder Page Parameter Rejection Discrepancy
- **Component:** [`AccessReviewController.java:87-95`](file:///C:/entomo/AI/nexus/nexus-backend/src/main/java/com/example/nexus/rbac/interfaces/rest/AccessReviewController.java#L87-L95)
- **Trace & Mechanism:** `PageParams.parse(page, size)` allows `size` up to `Integer.MAX_VALUE` if not explicitly capped by the controller, whereas `UserDirectoryController` caps size at 100. A malicious tenant auditor can issue `GET /api/v1/roles/{roleId}/holders?size=1000000`, causing Hibernate to construct millions of entities in heap, triggering OutOfMemoryError.
- **Minimal Fix:**
```diff
--- a/nexus-backend/src/main/java/com/example/nexus/rbac/interfaces/rest/PageParams.java
+++ b/nexus-backend/src/main/java/com/example/nexus/rbac/interfaces/rest/PageParams.java
@@ -25,3 +25,3 @@ public record PageParams(int page, int size) {
-    int parsedSize = size == null ? DEFAULT_SIZE : Integer.parseInt(size);
+    int parsedSize = Math.min(size == null ? DEFAULT_SIZE : Integer.parseInt(size), 100);
```
- **Test to Add:** `PageParamsTest.should_clamp_size_to_maximum_allowed_limit`

---

### [OR-10] Single Tenant Role Cache Eviction Drops Unrelated User Sessions
- **Component:** [`RedisPermissionCacheAdapter.java:140-155`](file:///C:/entomo/AI/nexus/nexus-backend/src/main/java/com/example/nexus/rbac/infrastructure/cache/RedisPermissionCacheAdapter.java#L140-L155)
- **Trace & Mechanism:** `evictRole(tenantId, roleId)` uses key pattern `rbac:perm:{tenantId}:*`. This deletes ALL cached user permission keys for the entire tenant rather than only the users assigned to `roleId`, causing sudden CPU and query spikes on MySQL as hundreds of tenant users re-resolve permissions simultaneously.
- **Minimal Fix:**
```diff
--- a/nexus-backend/src/main/java/com/example/nexus/rbac/infrastructure/cache/RedisPermissionCacheAdapter.java
+++ b/nexus-backend/src/main/java/com/example/nexus/rbac/infrastructure/cache/RedisPermissionCacheAdapter.java
@@ -145,3 +145,4 @@ public class RedisPermissionCacheAdapter {
-    Set<String> keys = redisTemplate.keys(keyPrefix + ":perm:" + tenantId + ":*");
-    redisTemplate.delete(keys);
+    List<UUID> holderIds = userRoleQueryPort.findActiveHolderUserIdsByRole(roleId, tenantId);
+    List<String> keys = holderIds.stream().map(u -> key(tenantId, u)).toList();
+    redisTemplate.delete(keys);
```
- **Test to Add:** `RedisPermissionCacheAdapterTest.should_only_evict_affected_role_holders`

---

### [OR-11] Unindexed Foreign Key Lookups on Soft-Deleted Roles
- **Component:** [`JpaUserRoleRepository.java:543-550`](file:///C:/entomo/AI/nexus/nexus-backend/src/main/java/com/example/nexus/rbac/infrastructure/persistence/JpaUserRoleRepository.java#L543-L550)
- **Trace & Mechanism:** `countActiveAssignmentsOnDeletedRolesInAnyTenant` executes:
  `SELECT COUNT(*) FROM user_roles ur JOIN roles r ON r.id = ur.role_id WHERE r.deleted_at IS NOT NULL AND ur.revoked_at IS NULL`
  Because `roles` lacks a composite index on `(deleted_at, id)` and `user_roles` is evaluated for `revoked_at IS NULL`, MySQL performs a full index scan over all active assignments on every health check poll (every 30s).
- **Minimal Fix:** Add Flyway migration creating composite index `idx_roles_deleted_at_id ON roles(deleted_at, id)`.
- **Test to Add:** `RbacSchemaMigrationIT.should_use_index_for_deleted_roles_health_query`

---

### [OR-12] Actuator Role Management Health Indicator Leaks Tenant Counts Without Admin Auth
- **Component:** [`RbacZeroActiveAdminsHealthIndicator.java:98-109`](file:///C:/entomo/AI/nexus/nexus-backend/src/main/java/com/example/nexus/rbac/infrastructure/health/RbacZeroActiveAdminsHealthIndicator.java#L98-L109)
- **Trace & Mechanism:** Health indicator detail `affectedTenantCount` is exposed on `/actuator/health`. Because `SecurityConfig` does not restrict `/actuator/health` to `TENANT_ADMIN`, any authenticated standard user in Tenant A can monitor `affectedTenantCount` changes to detect platform-wide zero-admin conditions across other tenants.
- **Minimal Fix:** Redact `affectedTenantCount` from non-admin Actuator views or restrict `/actuator/health/**` to `hasRole('SYSTEM_ADMIN')`.
- **Test to Add:** `RbacHealthSecurityIT.should_deny_health_details_to_standard_users`

---

### [OR-13] Unchecked Nullable Parent Transaction Synchronization Registry
- **Component:** [`RoleAssignmentService.java:345`](file:///C:/entomo/AI/nexus/nexus-backend/src/main/java/com/example/nexus/rbac/application/RoleAssignmentService.java#L345)
- **Trace & Mechanism:** `registerPostCommitSideEffects` calls `TransactionSynchronizationManager.registerSynchronization(...)`. If `RoleAssignmentService.assign` is ever invoked in a context where transactions are disabled (e.g. CLI runner or batch job without `@Transactional`), `registerSynchronization` throws `IllegalStateException: Transaction synchronization is not active`.
- **Minimal Fix:**
```diff
--- a/nexus-backend/src/main/java/com/example/nexus/rbac/application/RoleAssignmentService.java
+++ b/nexus-backend/src/main/java/com/example/nexus/rbac/application/RoleAssignmentService.java
@@ -345,2 +345,6 @@ public class RoleAssignmentService {
-      TransactionSynchronizationManager.registerSynchronization(new TransactionSynchronization() { ... });
+      if (TransactionSynchronizationManager.isSynchronizationActive()) {
+        TransactionSynchronizationManager.registerSynchronization(new TransactionSynchronization() { ... });
+      } else {
+        callback.run();
+      }
```
- **Test to Add:** `RoleAssignmentServiceTest.should_execute_side_effects_when_transaction_synchronization_inactive`

---

### [OR-2.1-01] Head-of-Line Blocking and Inter-Tenant Starvation in `EpochReplayQueue`
- **Component:** [`EpochReplayQueue.java:108-127`](file:///C:/entomo/AI/nexus/nexus-backend/src/main/java/com/example/nexus/rbac/application/EpochReplayQueue.java#L108-L127)
- **Trace & Mechanism:** `EpochReplayQueue` stores tenant queues in a `LinkedHashMap<UUID, TenantReplayState>`. During background replay polling, `poll()` inspects the head entry. If Tenant A has a corrupted or unparsable key that consistently fails replay, Tenant A remains at the head of the map. No subsequent tenants (Tenant B, C) are ever drained, leading to complete inter-tenant replay starvation.
- **Minimal Fix:** Implement round-robin fair polling: on replay failure, rotate the failing tenant to the tail of the `LinkedHashMap`.
- **Test to Add:** `EpochReplayQueueTest.should_round_robin_tenants_on_individual_replay_failure`

---

### [OR-2.1-02] Fail-Closed Bypass in `RECOVERING` State During Flapping Outages
- **Component:** [`PermissionFreshnessService.java:543-562`](file:///C:/entomo/AI/nexus/nexus-backend/src/main/java/com/example/nexus/rbac/application/PermissionFreshnessService.java#L543-L562)
- **Trace & Mechanism:** When transitioning from `DEGRADED_CLOSED` to `RECOVERING`, any read error returns `FreshnessVerdict.SKIPPED_ERROR` (fail-open) rather than maintaining the fail-closed posture of the preceding `DEGRADED_CLOSED` state. An attacker flapping Redis network connectivity can force the backend into `RECOVERING` and bypass fail-closed enforcement.
- **Minimal Fix:** In `RECOVERING` state, if the circuit breaker was previously `DEGRADED_CLOSED`, any read failure must return `DENIED_STORE_DEGRADED` (fail-closed).
- **Test to Add:** `PermissionFreshnessServiceStateTest.should_remain_fail_closed_during_recovering_state_failures`

---

### [OR-2.1-03] Premature Exit to `HEALTHY` with Non-Empty Replay Queues
- **Component:** [`PermissionFreshnessService.java:705-716`](file:///C:/entomo/AI/nexus/nexus-backend/src/main/java/com/example/nexus/rbac/application/PermissionFreshnessService.java#L705-L716)
- **Trace & Mechanism:** `recordReadSuccess` increments the consecutive success probe counter. When count reaches threshold (10), it flips the state machine directly to `HEALTHY` without checking `epochReplayQueue.isEmpty()`. Live traffic immediately trusts Redis epochs while hundreds of historical revocations still sit in memory undrained.
- **Minimal Fix:**
```diff
--- a/nexus-backend/src/main/java/com/example/nexus/rbac/application/PermissionFreshnessService.java
+++ b/nexus-backend/src/main/java/com/example/nexus/rbac/application/PermissionFreshnessService.java
@@ -710,2 +710,2 @@ public class PermissionFreshnessService {
-      if (consecutiveSuccesses >= recoveryThreshold) {
+      if (consecutiveSuccesses >= recoveryThreshold && epochReplayQueue.isEmpty() && roleReplayQueue.isEmpty()) {
         transitionTo(DegradedState.HEALTHY);
```
- **Test to Add:** `PermissionFreshnessRecoveryIT.should_not_enter_healthy_state_until_replay_queues_empty`

---

### [OR-2.1-04] Unbounded Task Queue Saturation in `roleReadExecutor`
- **Component:** [`PermissionFreshnessService.java:215-225`](file:///C:/entomo/AI/nexus/nexus-backend/src/main/java/com/example/nexus/rbac/application/PermissionFreshnessService.java#L215-L225)
- **Trace & Mechanism:** `roleReadExecutor` is initialized via `Executors.newFixedThreadPool(4)`, which creates an unbounded `LinkedBlockingQueue`. During massive role detachment storms across 1,000 tenants, thousands of `ReadHoldersTask` instances accumulate in memory, causing GC pressure and eventual OutOfMemoryError.
- **Minimal Fix:** Use `ThreadPoolExecutor` with a bounded queue (e.g. capacity 1,000) and `CallerRunsPolicy` or explicit drop metric.
- **Test to Add:** `PermissionFreshnessServiceTest.should_bound_role_read_executor_queue`

---

### [OR-2.1-05] Double Replay on Concurrent Degraded-to-Healthy Transitions
- **Component:** [`PermissionFreshnessService.java:730-745`](file:///C:/entomo/AI/nexus/nexus-backend/src/main/java/com/example/nexus/rbac/application/PermissionFreshnessService.java#L730-L745)
- **Trace & Mechanism:** When consecutive successes cross threshold, multiple worker threads concurrently call `drainReplayQueues()`. Because `drainReplayQueues()` lacks an atomic CAS latch, multiple threads poll the queue simultaneously, causing duplicated Redis increment operations and inflated epoch versions.
- **Minimal Fix:** Guard `drainReplayQueues()` with an `AtomicBoolean isDraining = new AtomicBoolean(false)`.
- **Test to Add:** `EpochReplayQueueConcurrencyTest.should_prevent_duplicate_replay_runs`

---

### [OR-2.1-06] Eviction Starvation for Long-Downtime Tenants in `RoleReplayQueue`
- **Component:** [`RoleReplayQueue.java:78-83`](file:///C:/entomo/AI/nexus/nexus-backend/src/main/java/com/example/nexus/rbac/application/RoleReplayQueue.java#L78-L83)
- **Trace & Mechanism:** `queuedFor(tenantId)` compares tenant quota. A tenant whose database or partition remains offline for hours consumes its tenant allocation permanently. New role changes for other tenants are rejected when queue capacity is near `borrowLimit`.
- **Minimal Fix:** Add TTL eviction to `RoleReplayQueue` slots so entries older than `maxRetention` (e.g. 1 hour) are pruned.
- **Test to Add:** `RoleReplayQueueTest.should_evict_stale_entries_under_prolonged_downtime`

---

### [OR-2.1-07] Coalesced Failure Window Calculation Truncates Retry Backoff
- **Component:** [`RoleReplayQueue.java:150-154`](file:///C:/entomo/AI/nexus/nexus-backend/src/main/java/com/example/nexus/rbac/application/RoleReplayQueue.java#L150-L154)
- **Trace & Mechanism:** `Times.merge(otherOldest, otherNewest)` updates `newest` timestamp. The scheduler calculates backoff based on `Instant.now() - newestFailedAt`. Merging a new failure resets the backoff timer to zero, repeatedly hammering failing database instances without backoff delay.
- **Minimal Fix:** Separate retry backoff calculation from failure timestamp merging.
- **Test to Add:** `RoleReplayQueueBackoffTest.should_preserve_exponential_backoff_across_merges`

---

### [OR-2.1-08] Memory Leak in `PermissionFreshnessService` Scheduled Executor ThreadPool
- **Component:** [`PermissionFreshnessService.java:230-235`](file:///C:/entomo/AI/nexus/nexus-backend/src/main/java/com/example/nexus/rbac/application/PermissionFreshnessService.java#L230-L235)
- **Trace & Mechanism:** `scheduledExecutor` is instantiated directly and scheduled at fixed rate. It lacks a `@PreDestroy` lifecycle method. During Spring context refreshes (or in containerized hot restarts), the background thread remains active, leaking the classloader and context references.
- **Minimal Fix:** Annotate shutdown method with `@PreDestroy`:
```diff
--- a/nexus-backend/src/main/java/com/example/nexus/rbac/application/PermissionFreshnessService.java
+++ b/nexus-backend/src/main/java/com/example/nexus/rbac/application/PermissionFreshnessService.java
@@ -235,0 +235,5 @@ public class PermissionFreshnessService {
+  @PreDestroy
+  void shutdownExecutors() {
+    scheduledExecutor.shutdownNow();
+    roleReadExecutor.shutdownNow();
+  }
```
- **Test to Add:** `PermissionFreshnessLifecycleTest.should_shutdown_executors_on_context_close`

---

### [OR-2.2-01] Sole Admin in `LOCKED` Status Bricks Break-Glass Recovery
- **Component:** [`BootstrapAdminService.java:59-65, 233-242`](file:///C:/entomo/AI/nexus/nexus-backend/src/main/java/com/example/nexus/rbac/application/BootstrapAdminService.java#L59-L65)
- **Trace & Mechanism:** `BootstrapAdminService` checks whether the tenant already has active administrators. Line 237 filters out only `DirectoryUserStatus.DISABLED`. If a tenant's sole administrator has status `LOCKED` (e.g. due to repeated failed login attempts or security lockout), `BootstrapAdminService` treats the tenant as having an active administrator and refuses break-glass with `TENANT_HAS_ADMIN`. The tenant is permanently bricked.
- **Minimal Fix:** Allow break-glass if all existing administrators are either `DISABLED` or `LOCKED`.
- **Test to Add:** `BreakGlassAdminIT.should_allow_break_glass_when_sole_admin_is_locked`

---

### [OR-2.3-01] Missing Redis Cluster Hash Tags in `RbacRedisKeys`
- **Component:** [`RbacRedisKeys.java:60-73`](file:///C:/entomo/AI/nexus/nexus-backend/src/main/java/com/example/nexus/rbac/infrastructure/cache/RbacRedisKeys.java#L60-L73)
- **Trace & Mechanism:** Multi-key Lua scripts execute against Redis Cluster. Because keys are generated as `rbac:perm:{tenantId}:{userId}` without Redis cluster hash tags `{...}`, keys for the same tenant hash to different cluster slots, causing Redis to abort with `CROSSSLOT Keys in request don't hash to the same slot`.
- **Minimal Fix:**
```diff
--- a/nexus-backend/src/main/java/com/example/nexus/rbac/infrastructure/cache/RbacRedisKeys.java
+++ b/nexus-backend/src/main/java/com/example/nexus/rbac/infrastructure/cache/RbacRedisKeys.java
@@ -62,3 +62,3 @@ public final class RbacRedisKeys {
   public static String epochKey(UUID tenantId, UUID userId) {
-    return "rbac:epoch:" + tenantId + ":" + userId;
+    return "rbac:epoch:{" + tenantId + "}:" + userId;
   }
```
- **Test to Add:** `RbacRedisKeysClusterTest.should_hash_tenant_keys_to_same_slot`

---

### [OR-3.1-02] Asymmetric Public Endpoint Matcher Causes Outage on Health/Docs Endpoints
- **Component:** [`JwtAuthenticationFilter.java:101-111`](file:///C:/entomo/AI/nexus/nexus-backend/src/main/java/com/example/nexus/identity/infrastructure/web/JwtAuthenticationFilter.java#L101-L111)
- **Trace & Mechanism:** `JwtAuthenticationFilter` matches bypass routes using exact string prefix matching (`request.getRequestURI().startsWith("/swagger-ui")`). If a request arrives with trailing slashes or URL encoded characters (e.g. `//swagger-ui`), the filter fails to match, treats the request as protected, and rejects unauthenticated documentation requests with 401 Unauthorized.
- **Minimal Fix:** Use Spring's `AntPathMatcher` or `PathPattern.matches()` matching `SecurityConfig` rules.
- **Test to Add:** `JwtAuthenticationFilterPathMatchTest.should_match_public_endpoints_with_non_canonical_paths`

---

### [OR-3.1-03] Non-Atomic Multi-RTT Cache Mutation Leaves Permanent Unexpired Keys in Redis
- **Component:** [`RedisPermissionCacheAdapter.java:101-109`](file:///C:/entomo/AI/nexus/nexus-backend/src/main/java/com/example/nexus/rbac/infrastructure/cache/RedisPermissionCacheAdapter.java#L101-L109)
- **Trace & Mechanism:** Permissions are cached by calling `redisTemplate.opsForValue().set(key, value)` followed by `redisTemplate.expire(key, ttl)`. If the network drops or the JVM crashes between the two commands, the key remains in Redis permanently without TTL, leaking memory indefinitely.
- **Minimal Fix:**
```diff
--- a/nexus-backend/src/main/java/com/example/nexus/rbac/infrastructure/cache/RedisPermissionCacheAdapter.java
+++ b/nexus-backend/src/main/java/com/example/nexus/rbac/infrastructure/cache/RedisPermissionCacheAdapter.java
@@ -103,2 +103,1 @@ public class RedisPermissionCacheAdapter {
-    redisTemplate.opsForValue().set(key, serialized);
-    redisTemplate.expire(key, ttl);
+    redisTemplate.opsForValue().set(key, serialized, ttl);
```
- **Test to Add:** `RedisPermissionCacheAdapterTest.should_set_key_with_ttl_in_single_operation`

---

### [OR-3.3-03] Profile Drift: In-Memory Throttle Enabled in Production via Missing Guard
- **Component:** [`application-prod.yml:31-36`](file:///C:/entomo/AI/nexus/nexus-backend/src/main/resources/application-prod.yml#L31-L36)
- **Trace & Mechanism:** `ThrottleSharedStoreStartupAssertion` fails startup only if `nexus.rbac.throttle.require-shared-store=true`. However, `application-prod.yml` omits this property. If a deployment misconfigures `nexus.security.rate-limit.store-type=memory`, the in-memory throttle activates in production without failing startup, allowing attackers to bypass rate limits by load-balancing across pods.
- **Minimal Fix:** Add `nexus.rbac.throttle.require-shared-store: true` to `application-prod.yml`.
- **Test to Add:** `ProductionProfileConfigurationTest.should_enforce_shared_throttle_store_in_prod`

---

### [OR-3.3-04] Permissive Actuator Authorization Leaks Internal Secrets
- **Component:** [`SecurityConfig.java:97-109`](file:///C:/entomo/AI/nexus/nexus-backend/src/main/java/com/example/nexus/config/SecurityConfig.java#L97-L109)
- **Trace & Mechanism:** Actuator endpoints under `/actuator/**` are configured with `.authenticated()`. Any standard member of any tenant with a valid JWT can query `/actuator/env`, `/actuator/metrics`, and `/actuator/health`, exposing internal database URLs, Redis hosts, and environment metadata.
- **Minimal Fix:**
```diff
--- a/nexus-backend/src/main/java/com/example/nexus/config/SecurityConfig.java
+++ b/nexus-backend/src/main/java/com/example/nexus/config/SecurityConfig.java
@@ -99,1 +99,1 @@ public class SecurityConfig {
-        .requestMatchers("/actuator/**").authenticated()
+        .requestMatchers("/actuator/**").hasAuthority("SYSTEM_ADMIN")
```
- **Test to Add:** `ActuatorSecurityIT.should_deny_actuator_endpoints_to_non_system_admins`

---

### [OR-3.3-05] `AuthEventRetryBuffer` Lacks Graceful Shutdown Draining Hook
- **Component:** [`AuthEventRetryBuffer.java:89-116`](file:///C:/entomo/AI/nexus/nexus-backend/src/main/java/com/example/nexus/identity/infrastructure/audit/AuthEventRetryBuffer.java#L89-L116)
- **Trace & Mechanism:** Failed audit events are buffered in memory for scheduled retry. When the container receives SIGTERM during Kubernetes rolling deployments, the context closes without draining the buffer. All buffered security audit events are permanently lost.
- **Minimal Fix:** Implement `DisposableBean` or `@PreDestroy` to flush pending events to disk or standard error log on shutdown.
- **Test to Add:** `AuthEventRetryBufferLifecycleTest.should_drain_buffer_on_shutdown`

---

### [OR-4.1-02] Gap-Lock Next-Key Deadlock on First Admin-Defining Role Assignment
- **Component:** [`JpaUserRoleRepository.java:128-137`](file:///C:/entomo/AI/nexus/nexus-backend/src/main/java/com/example/nexus/rbac/infrastructure/persistence/JpaUserRoleRepository.java#L128-L137)
- **Trace & Mechanism:** `lockActiveAssignmentHoldersByRoles` executes `SELECT * FROM user_roles WHERE role_id IN (:roleIds) FOR UPDATE`. When assigning the first administrator to a role with no existing assignments, InnoDB places gap locks across index intervals. Concurrent assignments to different roles acquire overlapping gap locks and deadlock when attempting subsequent inserts.
- **Minimal Fix:** Set transaction isolation level to `READ COMMITTED` for role assignments or execute insert first with conflict retry.
- **Test to Add:** `AssignRoleContentionIT.should_not_deadlock_on_initial_assignments_to_empty_roles`

---

### [OR-4.1-03] Multi-Transaction Write Skew in `detachPermission` Demoting Tenant to 0 Admins
- **Component:** [`RoleManagementService.java:447-465`](file:///C:/entomo/AI/nexus/nexus-backend/src/main/java/com/example/nexus/rbac/application/RoleManagementService.java#L447-L465)
- **Trace & Mechanism:** Tenant has two admin-defining roles: $R_A$ and $R_B$. Admin 1 detaches permission $P_1$ from $R_A$. Admin 2 detaches permission $P_1$ from $R_B$. Under `REPEATABLE READ`, both transactions observe the other role as admin-defining. Both detaches commit, demoting both roles and leaving the tenant with 0 administrators.
- **Minimal Fix:** Acquire set lock on all tenant admin-defining roles in `detachPermission` before modifying permissions.
- **Test to Add:** `RoleManagementConcurrencyIT.should_prevent_simultaneous_demotion_of_all_admin_roles`

---

### [OR-4.1-04] Missing Permission Classification Check in `softDeleteRole`
- **Component:** [`RoleManagementService.java:1125-1145`](file:///C:/entomo/AI/nexus/nexus-backend/src/main/java/com/example/nexus/rbac/application/RoleManagementService.java#L1125-L1145)
- **Trace & Mechanism:** `softDeleteRole` checks that the role has no active assignments. However, it does not lock or verify whether the role is currently admin-defining. If a role is being assigned concurrently, `softDeleteRole` can mark the role deleted while an assignment commits, violating the invariant that deleted roles have no active holders.
- **Minimal Fix:** Re-verify active holder count and permission set under `roles` row lock immediately before setting `deleted_at`.
- **Test to Add:** `RoleDeleteConcurrencyIT.should_prevent_concurrent_assignment_and_deletion`

---

### [OR-4.2-02] Zero-Hysteresis Single-Probe Flapping Cycle Between DEGRADED and RECOVERING
- **Component:** [`PermissionFreshnessService.java:641-651, 719-735`](file:///C:/entomo/AI/nexus/nexus-backend/src/main/java/com/example/nexus/rbac/application/PermissionFreshnessService.java#L641-L651)
- **Trace & Mechanism:** When Redis is degraded, a single successful read transitions state to `RECOVERING`. If the very next read fails, it immediately flips back to `DEGRADED`. Under unstable network conditions, this creates rapid state flapping that thrashes thread pools and logging alert systems.
- **Minimal Fix:** Require a minimum consecutive success threshold (e.g. 5 successful probes) before transitioning from `DEGRADED` to `RECOVERING`.
- **Test to Add:** `PermissionFreshnessServiceTest.should_require_hysteresis_threshold_before_recovering`

---

### [OR-4.2-03] Single Read Timeout Outlier in 60s Sustained Window Prevents Recovery
- **Component:** [`PermissionFreshnessService.java:678-680`](file:///C:/entomo/AI/nexus/nexus-backend/src/main/java/com/example/nexus/rbac/application/PermissionFreshnessService.java#L678-L680)
- **Trace & Mechanism:** Recovery requires 60 seconds of 100% success rate. In high-throughput production (10,000 req/sec), a single transient P99.9 timeout (e.g. 50ms Redis garbage collection pause) resets the entire 60s timer, trapping the cluster in `RECOVERING` mode indefinitely despite 99.999% availability.
- **Minimal Fix:** Use error rate percentage (e.g. < 0.1% failures over 60s) rather than absolute zero-failure requirement.
- **Test to Add:** `PermissionFreshnessRecoveryTest.should_tolerate_isolated_timeout_outlier`

---

### [OR-4.2-04] 500-User Fan-Out Lua Bump Blocks Redis Event Loop, Triggering Cluster Read Outage
- **Component:** [`PermissionFreshnessService.java:188`](file:///C:/entomo/AI/nexus/nexus-backend/src/main/java/com/example/nexus/rbac/application/PermissionFreshnessService.java#L188)
- **Trace & Mechanism:** When an admin modifies a role assigned to 500+ users, `PermissionFreshnessService` executes a single Redis Lua script that loops across all 500 keys. Redis is single-threaded; executing a 500-iteration Lua script blocks all other read/write traffic across the Redis instance, causing concurrent API requests to timeout.
- **Minimal Fix:** Chunk holder bumps into batches of 50 keys, or use pipeline asynchronous increments rather than an atomic loop Lua script.
- **Test to Add:** `PermissionFreshnessServiceLatencyTest.should_limit_lua_bump_batch_size`

---

### [OR-4.2-05] Unbounded Heap Consumption in Sentinel Topology Change Listener
- **Component:** [`EpochRedisConfig.java:180-210`](file:///C:/entomo/AI/nexus/nexus-backend/src/main/java/com/example/nexus/rbac/infrastructure/cache/EpochRedisConfig.java#L180-L210)
- **Trace & Mechanism:** `SentinelTopologyRefreshOptions` attaches a listener to Sentinel pub/sub events. On every network reconnection event, Lettuce re-registers the listener without clearing the prior registration, accumulating listener objects in memory and leaking heap.
- **Minimal Fix:** Register the listener as a singleton bean with lifecycle management.
- **Test to Add:** `EpochRedisConfigTest.should_not_duplicate_sentinel_listeners_on_reconnect`

---

### [OR-4.2-06] Clock Drift Across Distributed Nodes Compromises Sliding-Window Throttle
- **Component:** [`RedisRoleChangeThrottleAdapter.java:82-99`](file:///C:/entomo/AI/nexus/nexus-backend/src/main/java/com/example/nexus/rbac/infrastructure/cache/RedisRoleChangeThrottleAdapter.java#L82-L99)
- **Trace & Mechanism:** The Lua sliding window script takes `ARGV[1] = clock.millis()` sourced from the local JVM clock. If Pod 1's clock is 5 seconds behind Pod 2 (NTP drift), timestamps inserted into Redis sorted sets become misaligned. A denial recorded by Pod 2 is immediately purged by Pod 1, bypassing the rate limiter.
- **Minimal Fix:** Replace `ARGV[1]` in Lua with Redis server time via `local now = redis.call('TIME')`.
- **Test to Add:** `RedisRoleChangeThrottleAdapterIT.should_use_server_time_to_prevent_clock_drift`
