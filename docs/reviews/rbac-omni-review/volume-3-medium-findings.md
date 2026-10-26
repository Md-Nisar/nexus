# Master Compendium — Volume 3: Medium-Severity Defect Dossier (27 Findings)

This volume provides full engineering dossiers for all **27 Medium-Severity findings** across the Nexus RBAC subsystem and security perimeter.

---

## Table of Contents
1. [[OR-14] Sensitive Permission Matching Bypassed by Case-Sensitivity / ID Lookup Inflexibility](#or-14-sensitive-permission-matching-bypassed-by-case-sensitivity--id-lookup-inflexibility)
2. [[OR-15] Role Replay Queue Entries Lost Across Pod Restarts](#or-15-role-replay-queue-entries-lost-across-pod-restarts)
3. [[OR-16] Prometheus Lock Hold Duration Metric Lacks Upper Bound Histogram Buckets](#or-16-prometheus-lock-hold-duration-metric-lacks-upper-bound-histogram-buckets)
4. [[OR-17] Role Name Case-Insensitive Uniqueness Collation Mismatch in MySQL](#or-17-role-name-case-insensitive-uniqueness-collation-mismatch-in-mysql)
5. [[OR-18] N+1 Database Queries in `RoleAssignmentService.listActive` When Resolving AssignedBy User Details](#or-18-n1-database-queries-in-roleassignmentservicelistactive-when-resolving-assignedby-user-details)
6. [[OR-19] Missing Query Timeout on Lock Acquisition in `lockActiveAssignmentHoldersByRoles`](#or-19-missing-query-timeout-on-lock-acquisition-in-lockactiveassignmentholdersbyroles)
7. [[OR-20] Unpaginated `getEffectivePermissions` Endpoint Vulnerable to Memory Exhaustion](#or-20-unpaginated-geteffectivepermissions-endpoint-vulnerable-to-memory-exhaustion)
8. [[OR-21] `TenantAwarePermissionEvaluator` Silently Trusts `Authentication.getDetails()` Without Cryptographic Validation](#or-21-tenantawarepermissionevaluator-silently-trusts-authenticationgetdetails-without-cryptographic-validation)
9. [[OR-22] User Directory Pagination Multiplier Arithmetic Overflow / Constraint Bypass](#or-22-user-directory-pagination-multiplier-arithmetic-overflow--constraint-bypass)
10. [[OR-23] Missing Foreign Key Index on `user_roles(assigned_by)`](#or-23-missing-foreign-key-index-on-user_rolesassigned_by)
11. [[OR-24] Method Security `@RequiresPermission` Silently Ignored on Non-Public Methods](#or-24-method-security-requirespermission-silently-ignored-on-non-public-methods)
12. [[OR-25] Unstructured Standard Out Logging in `BreakGlassAdminRunner`](#or-25-unstructured-standard-out-logging-in-breakglassadminrunner)
13. [[OR-26] Missing Idempotency Key Handling on Role Creation](#or-26-missing-idempotency-key-handling-on-role-creation)
14. [[OR-27] Missing TTL Jitter in `RedisPermissionCacheAdapter` Creates Thundering Herd](#or-27-missing-ttl-jitter-in-redispermissioncacheadapter-creates-thundering-herd)
15. [[OR-28] `CallerAuthorizationController` Returns 200 with Empty Collections on Deleted Tenant](#or-28-callerauthorizationcontroller-returns-200-with-empty-collections-on-deleted-tenant)
16. [[OR-2.1-09] Circuit Breaker State Transition Listeners Lack Async Decoupling](#or-21-09-circuit-breaker-state-transition-listeners-lack-async-decoupling)
17. [[OR-2.1-10] Non-Atomic Epoch Read-Then-Increment in Fallback Mode](#or-21-10-non-atomic-epoch-read-then-increment-in-fallback-mode)
18. [[OR-2.2-02] `BreakGlassAdminRunner.waitForLogFlush` Uses Thread Sleep Instead of Output Flush Probe](#or-22-02-breakglassadminrunnerwaitforlogflush-uses-thread-sleep-instead-of-output-flush-probe)
19. [[OR-2.2-03] `BootstrapAdminService` Failure Audit Does Not Retry on Transient Network Drops](#or-22-03-bootstrapadminservice-failure-audit-does-not-retry-on-transient-network-drops)
20. [[OR-2.3-02] `RedisRoleChangeThrottleAdapter` Omits TTL Update on Rejected Requests](#or-23-02-redisrolechangethrottleadapter-omits-ttl-update-on-rejected-requests)
21. [[OR-2.3-03] Unbounded Sorted Set Key Growth in Rate Limit Store Under Random Principal Spam](#or-23-03-unbounded-sorted-set-key-growth-in-rate-limit-store-under-random-principal-spam)
22. [[OR-3.1-04] Case-Sensitive Bearer Prefix Check in `JwtAuthenticationFilter`](#or-31-04-case-sensitive-bearer-prefix-check-in-jwtauthenticationfilter)
23. [[OR-3.1-05] Redundant Sequential Database Queries in `RoleResolutionService.resolveUncached`](#or-31-05-redundant-sequential-database-queries-in-roleresolutionserviceresolveuncached)
24. [[OR-3.2-01] Token Minting Lacks Tenant Active Status Check](#or-32-01-token-minting-lacks-tenant-active-status-check)
25. [[OR-3.3-06] `GlobalExceptionHandler` Maps Database Unique Constraint Violations to HTTP 500](#or-33-06-globalexceptionhandler-maps-database-unique-constraint-violations-to-http-500)
26. [[OR-4.1-05] `lockActiveAssignmentHoldersByRoles` Incomplete Scope When Role Code Changed in In-Flight Transaction](#or-41-05-lockactiveassignmentholdersbyroles-incomplete-scope-when-role-code-changed-in-in-flight-transaction)
27. [[OR-4.1-06] Inconsistent Tenant Filtering on Role Replay Recovery](#or-41-06-inconsistent-tenant-filtering-on-role-replay-recovery)

---

### [OR-14] Sensitive Permission Matching Bypassed by Case-Sensitivity / ID Lookup Inflexibility
- **Component:** [`PiiPermissionGrantRule.java:87-89`](file:///C:/entomo/AI/nexus/nexus-backend/src/main/java/com/example/nexus/rbac/application/PiiPermissionGrantRule.java#L87-L89)
- **Trace & Mechanism:** `evaluate` checks `grantedPermissionIds.contains(RbacSeededPermissionIds.USER_DIRECTORY_READ)`. If a database migration re-seeds permissions or an environment uses dynamic IDs, the hardcoded UUID constant fails to match, allowing sensitive PII permissions to be granted without administrator authorization.
- **Minimal Fix:**
```diff
--- a/nexus-backend/src/main/java/com/example/nexus/rbac/application/PiiPermissionGrantRule.java
+++ b/nexus-backend/src/main/java/com/example/nexus/rbac/application/PiiPermissionGrantRule.java
@@ -87,2 +87,2 @@ public class PiiPermissionGrantRule {
-    if (!grantedPermissionIds.contains(RbacSeededPermissionIds.USER_DIRECTORY_READ)) {
+    if (!userRoleAssignmentPort.containsPiiPermission(grantedPermissionIds)) {
       return Outcome.NOT_A_PII_GRANT;
```
- **Test to Add:** `PiiPermissionGrantRuleTest.should_resolve_pii_permissions_dynamically`

---

### [OR-15] Role Replay Queue Entries Lost Across Pod Restarts
- **Component:** [`RoleReplayQueue.java:31-33`](file:///C:/entomo/AI/nexus/nexus-backend/src/main/java/com/example/nexus/rbac/application/RoleReplayQueue.java#L31-L33)
- **Trace & Mechanism:** `RoleReplayQueue` holds failed role holder invalidations in an in-memory `LinkedHashMap`. If the pod restarts or is rescheduled during a Redis partition, all queued role updates are lost, leaving downstream user cache entries stale until TTL expiry.
- **Minimal Fix:** Back `RoleReplayQueue` with a local persistent SQLite or Redis write-ahead log, or query un-replayed database audit events on boot.
- **Test to Add:** `RoleReplayQueuePersistenceTest.should_recover_unreplayed_roles_after_restart`

---

### [OR-16] Prometheus Lock Hold Duration Metric Lacks Upper Bound Histogram Buckets
- **Component:** [`RoleAssignmentService.java:219`](file:///C:/entomo/AI/nexus/nexus-backend/src/main/java/com/example/nexus/rbac/application/RoleAssignmentService.java#L219)
- **Trace & Mechanism:** `Timer.Sample lockHoldSample` records lock duration. In high-contention environments where lock wait approaches the 30-second InnoDB timeout, the metric buckets clip at 10 seconds, obscuring database locking latency spikes in Prometheus alerts.
- **Minimal Fix:** Configure explicit SLA buckets up to 35 seconds for `nexus.rbac.role_change.lock_hold`.
- **Test to Add:** `RbacMetricCardinalityTest.should_configure_adequate_histogram_buckets`

---

### [OR-17] Role Name Case-Insensitive Uniqueness Collation Mismatch in MySQL
- **Component:** [`JpaRoleRepository.java:45-50`](file:///C:/entomo/AI/nexus/nexus-backend/src/main/java/com/example/nexus/rbac/infrastructure/persistence/JpaRoleRepository.java#L45-L50)
- **Trace & Mechanism:** The database column `roles.name` uses collation `utf8mb4_0900_ai_ci` (case-insensitive), but Java string checks in `RoleManagementService` use exact equality `equals()`. An administrator can create `Manager` and `manager` without triggering application-level duplicate checks, causing unpredictable downstream 500 DB constraint errors.
- **Minimal Fix:** Normalize role names to lowercase or perform `equalsIgnoreCase()` in Java validation before persistence.
- **Test to Add:** `RoleManagementIT.should_reject_case_variant_duplicate_role_names`

---

### [OR-18] N+1 Database Queries in `RoleAssignmentService.listActive` When Resolving AssignedBy User Details
- **Component:** [`RoleAssignmentService.java:512-516`](file:///C:/entomo/AI/nexus/nexus-backend/src/main/java/com/example/nexus/rbac/application/RoleAssignmentService.java#L512-L516)
- **Trace & Mechanism:** In `listActive(actor, targetUserId, page, size)`, for each assignment in the page, the service issues a separate query to check `isCallerAdministrator` and resolve `assignedBy`. A page of 100 assignments produces 101 database queries.
- **Minimal Fix:** Fetch caller administrator status once per request and join `users` via projection in a single JPQL query.
- **Test to Add:** `RoleAssignmentPerformanceIT.should_execute_single_query_for_active_assignments_page`

---

### [OR-19] Missing Query Timeout on Lock Acquisition in `lockActiveAssignmentHoldersByRoles`
- **Component:** [`JpaUserRoleRepository.java:128-137`](file:///C:/entomo/AI/nexus/nexus-backend/src/main/java/com/example/nexus/rbac/infrastructure/persistence/JpaUserRoleRepository.java#L128-L137)
- **Trace & Mechanism:** The native query `SELECT * FROM user_roles FOR UPDATE` does not specify `SET Statement_timeout` or `@QueryHints`. Under heavy locking contention, worker threads block for the full default MySQL `innodb_lock_wait_timeout` (50 seconds), exhausting the Tomcat HTTP thread pool.
- **Minimal Fix:** Add `@QueryHints({@QueryHint(name = "jakarta.persistence.query.timeout", value = "5000")})`.
- **Test to Add:** `JpaUserRoleRepositoryTest.should_enforce_query_timeout_on_locking_reads`

---

### [OR-20] Unpaginated `getEffectivePermissions` Endpoint Vulnerable to Memory Exhaustion
- **Component:** [`AccessReviewService.java:127-147`](file:///C:/entomo/AI/nexus/nexus-backend/src/main/java/com/example/nexus/rbac/application/AccessReviewService.java#L127-L147)
- **Trace & Mechanism:** `GET /api/v1/users/{userId}/effective-permissions` returns all permissions. While currently bounded by catalogue size, as permissions expand to thousands across complex tenant roles, the unpaginated in-memory grouping in `rolesByPermission` consumes significant heap.
- **Minimal Fix:** Implement pagination or compress permission responses using compact binary bitmaps.
- **Test to Add:** `AccessReviewPerformanceTest.should_bound_effective_permissions_heap_usage`

---

### [OR-21] `TenantAwarePermissionEvaluator` Silently Trusts `Authentication.getDetails()` Without Cryptographic Validation
- **Component:** [`TenantAwarePermissionEvaluator.java:44-51`](file:///C:/entomo/AI/nexus/nexus-backend/src/main/java/com/example/nexus/common/security/TenantAwarePermissionEvaluator.java#L44-L51)
- **Trace & Mechanism:** The evaluator extracts `tenantId` and `permissions` from `authentication.getDetails()`. If an upstream filter or rogue security interceptor mutates the details map, the evaluator accepts the spoofed tenant and permissions without re-checking the JWT signature or claims.
- **Minimal Fix:** Assert that the authentication principal is an instance of `JwtAuthenticationToken` and re-validate signature context before granting access.
- **Test to Add:** `TenantAwarePermissionEvaluatorTest.should_reject_unverified_authentication_details`

---

### [OR-22] User Directory Pagination Multiplier Arithmetic Overflow / Constraint Bypass
- **Component:** [`UserDirectoryController.java:120-138`](file:///C:/entomo/AI/nexus/nexus-backend/src/main/java/com/example/nexus/identity/interfaces/rest/UserDirectoryController.java#L120-L138)
- **Trace & Mechanism:** Line 96 states "page times size over 10,000 rejected", but integer multiplication `page * size` can overflow `Integer.MAX_VALUE` if `page = 300000` and `size = 100`, resulting in a negative number that bypasses the `<= 10000` check.
- **Minimal Fix:**
```diff
--- a/nexus-backend/src/main/java/com/example/nexus/identity/interfaces/rest/DirectoryPageRequest.java
+++ b/nexus-backend/src/main/java/com/example/nexus/identity/interfaces/rest/DirectoryPageRequest.java
@@ -40,3 +40,3 @@ public record DirectoryPageRequest {
-    if (page * size > 10000) {
+    if ((long) page * (long) size > 10000L) {
       throw new FieldValidationException("page * size must not exceed 10,000");
     }
```
- **Test to Add:** `DirectoryPageRequestTest.should_prevent_integer_overflow_bypass`

---

### [OR-23] Missing Foreign Key Index on `user_roles(assigned_by)`
- **Component:** [`V8__user_roles.sql`](file:///C:/entomo/AI/nexus/nexus-backend/src/main/resources/db/migration/V8__user_roles.sql)
- **Trace & Mechanism:** The column `assigned_by` references `users(id)` but lacks an index on `user_roles(assigned_by)`. When an administrator account is purged or deleted in compliance with GDPR, MySQL locks the entire `user_roles` table to verify foreign key integrity, halting role assignments.
- **Minimal Fix:** Add Flyway migration creating `CREATE INDEX idx_user_roles_assigned_by ON user_roles(assigned_by)`.
- **Test to Add:** `RbacSchemaMigrationIT.should_have_index_on_assigned_by_column`

---

### [OR-24] Method Security `@RequiresPermission` Silently Ignored on Non-Public Methods
- **Component:** [`RequiresPermission.java:28-31`](file:///C:/entomo/AI/nexus/nexus-backend/src/main/java/com/example/nexus/common/security/RequiresPermission.java#L28-L31)
- **Trace & Mechanism:** Spring AOP cannot intercept `private` or `protected` methods. If a developer accidentally places `@RequiresPermission` on a package-private service method, authorization is silently omitted without error, granting unauthenticated access.
- **Minimal Fix:** Add an ArchUnit test asserting that `@RequiresPermission` is placed strictly on `public` methods.
- **Test to Add:** `HexagonalArchitectureTest.requires_permission_must_only_be_placed_on_public_methods`

---

### [OR-25] Unstructured Standard Out Logging in `BreakGlassAdminRunner`
- **Component:** [`BreakGlassAdminRunner.java:120-130`](file:///C:/entomo/AI/nexus/nexus-backend/src/main/java/com/example/nexus/rbac/interfaces/cli/BreakGlassAdminRunner.java#L120-L130)
- **Trace & Mechanism:** The CLI runner writes raw text exit codes to stdout. Automated Kubernetes auditing pipelines expecting structured JSON fail to parse the CLI execution outcome, obscuring security break-glass events.
- **Minimal Fix:** Format runner completion output as structured JSON matching ECS logging standards.
- **Test to Add:** `BreakGlassAdminRunnerTest.should_emit_structured_json_to_stdout`

---

### [OR-26] Missing Idempotency Key Handling on Role Creation
- **Component:** [`RoleController.java:80-100`](file:///C:/entomo/AI/nexus/nexus-backend/src/main/java/com/example/nexus/rbac/interfaces/rest/RoleController.java#L80-L100)
- **Trace & Mechanism:** `POST /api/v1/roles` lacks `Idempotency-Key` header support. If a network blip occurs after insertion, the client retries and receives `409 DUPLICATE_ROLE_NAME`, preventing transparent client retries.
- **Minimal Fix:** Introduce `Idempotency-Key` caching header matching ADR-0012 standards.
- **Test to Add:** `RoleControllerTest.should_support_idempotent_role_creation`

---

### [OR-27] Missing TTL Jitter in `RedisPermissionCacheAdapter` Creates Thundering Herd
- **Component:** [`RedisPermissionCacheAdapter.java:101-109`](file:///C:/entomo/AI/nexus/nexus-backend/src/main/java/com/example/nexus/rbac/infrastructure/cache/RedisPermissionCacheAdapter.java#L101-L109)
- **Trace & Mechanism:** All user permission cache keys are set with exact 15-minute TTL (`Duration.ofMinutes(15)`). When 1,000 users log in at 9:00 AM, all 1,000 keys expire at exactly 9:15 AM, creating a thundering herd on MySQL.
- **Minimal Fix:** Apply random jitter: `ttl.plusSeconds(ThreadLocalRandom.current().nextLong(-60, 60))`.
- **Test to Add:** `RedisPermissionCacheAdapterTest.should_apply_jitter_to_cache_ttl`

---

### [OR-28] `CallerAuthorizationController` Returns 200 with Empty Collections on Deleted Tenant
- **Component:** [`CallerAuthorizationController.java:61-71`](file:///C:/entomo/AI/nexus/nexus-backend/src/main/java/com/example/nexus/rbac/interfaces/rest/CallerAuthorizationController.java#L61-L71)
- **Trace & Mechanism:** `GET /api/v1/users/me/authorization` queries roles for the caller's tenant. If the tenant was soft-deleted, it returns `200 OK` with empty roles and permissions instead of `403 TENANT_SUSPENDED` or `404 TENANT_NOT_FOUND`, confusing UI client routing.
- **Minimal Fix:** Validate that caller's tenant is active before building authorization response.
- **Test to Add:** `CallerAuthorizationIT.should_return_error_when_tenant_is_inactive`

---

### [OR-2.1-09] Circuit Breaker State Transition Listeners Lack Async Decoupling
- **Component:** [`PermissionFreshnessService.java:650-670`](file:///C:/entomo/AI/nexus/nexus-backend/src/main/java/com/example/nexus/rbac/application/PermissionFreshnessService.java#L650-L670)
- **Trace & Mechanism:** State transition callbacks (e.g. logging and metrics registration) execute synchronously inside the critical path of the probe thread, adding latency to Redis probe cycles.
- **Minimal Fix:** Publish state transition events asynchronously via `ApplicationEventPublisher`.
- **Test to Add:** `PermissionFreshnessEventTest.should_publish_state_transitions_asynchronously`

---

### [OR-2.1-10] Non-Atomic Epoch Read-Then-Increment in Fallback Mode
- **Component:** [`PermissionFreshnessService.java:480-495`](file:///C:/entomo/AI/nexus/nexus-backend/src/main/java/com/example/nexus/rbac/application/PermissionFreshnessService.java#L480-L495)
- **Trace & Mechanism:** In fallback mode, the service reads the current epoch, increments it in Java, and calls `set()`. Concurrent revocations on the same user can overwrite each other's increments.
- **Minimal Fix:** Use atomic Redis `INCR` or Lua script exclusively.
- **Test to Add:** `PermissionFreshnessServiceTest.should_increment_epoch_atomically_in_fallback`

---

### [OR-2.2-02] `BreakGlassAdminRunner.waitForLogFlush` Uses Thread Sleep Instead of Output Flush Probe
- **Component:** [`BreakGlassAdminRunner.java:131-140`](file:///C:/entomo/AI/nexus/nexus-backend/src/main/java/com/example/nexus/rbac/interfaces/cli/BreakGlassAdminRunner.java#L131-L140)
- **Trace & Mechanism:** `waitForLogFlush` executes `Thread.sleep(logFlushWait)`. If log shipping is delayed due to network backpressure, the container terminates immediately after sleep, dropping security alert logs.
- **Minimal Fix:** Call `LogbackLoggingSystem.flushAppenders()` or poll log shipper queue length.
- **Test to Add:** `BreakGlassAdminRunnerTest.should_verify_flush_completion_before_exit`

---

### [OR-2.2-03] `BootstrapAdminService` Failure Audit Does Not Retry on Transient Network Drops
- **Component:** [`BootstrapAdminService.java:282-300`](file:///C:/entomo/AI/nexus/nexus-backend/src/main/java/com/example/nexus/rbac/application/BootstrapAdminService.java#L282-L300)
- **Trace & Mechanism:** Refusal rows are written using a `REQUIRES_NEW` transaction. If the database is under transient failover, the refusal row write fails and logs a warning without retrying, losing critical forensic audit records of unauthorized break-glass attempts.
- **Minimal Fix:** Implement an in-memory fallback retry loop for refusal audit logging in the CLI runner.
- **Test to Add:** `BootstrapAdminServiceTest.should_retry_audit_write_on_transient_failure`

---

### [OR-2.3-02] `RedisRoleChangeThrottleAdapter` Omits TTL Update on Rejected Requests
- **Component:** [`sliding_window_rate_limit.lua:17-25`](file:///C:/entomo/AI/nexus/nexus-backend/src/main/resources/scripts/sliding_window_rate_limit.lua#L17-L25)
- **Trace & Mechanism:** When rate limit requests are rejected (`count >= maxAttempts`), the Lua script returns `{0, retryAfter}` but does NOT call `PEXPIRE` on the key. If an attacker continuously spams requests after being rejected, the key eventually expires while still being bombarded, resetting the rate limit window prematurely.
- **Minimal Fix:**
```diff
--- a/nexus-backend/src/main/resources/scripts/sliding_window_rate_limit.lua
+++ b/nexus-backend/src/main/resources/scripts/sliding_window_rate_limit.lua
@@ -19,2 +19,3 @@ if count >= maxAttempts then
   local retryAfterMs = window - (now - tonumber(oldest[2]))
+  redis.call('PEXPIRE', key, window)
   return {0, math.max(1, math.ceil(retryAfterMs / 1000))}
```
- **Test to Add:** `RedisRateLimitStoreIT.should_refresh_ttl_on_rejected_requests`

---

### [OR-2.3-03] Unbounded Sorted Set Key Growth in Rate Limit Store Under Random Principal Spam
- **Component:** [`RedisRateLimitStore.java:58-75`](file:///C:/entomo/AI/nexus/nexus-backend/src/main/java/com/example/nexus/identity/infrastructure/security/RedisRateLimitStore.java#L58-L75)
- **Trace & Mechanism:** An unauthenticated attacker sending millions of requests with random spoofed user IDs creates millions of distinct Redis sorted sets. Even with TTL, the creation rate can exhaust Redis memory.
- **Minimal Fix:** Add IP-level rate limiting before user-level rate limiting in the filter chain.
- **Test to Add:** `RateLimitProtectionIT.should_throttle_ip_before_allocating_user_rate_limit_keys`

---

### [OR-3.1-04] Case-Sensitive Bearer Prefix Check in `JwtAuthenticationFilter`
- **Component:** [`JwtAuthenticationFilter.java:85-95`](file:///C:/entomo/AI/nexus/nexus-backend/src/main/java/com/example/nexus/identity/infrastructure/web/JwtAuthenticationFilter.java#L85-L95)
- **Trace & Mechanism:** The filter checks `header.startsWith("Bearer ")`. RFC 6750 permits case-insensitive scheme matching (`bearer`). Clients sending `bearer <token>` are rejected with 401 Unauthorized.
- **Minimal Fix:** Use case-insensitive prefix match: `header.regionMatches(true, 0, "Bearer ", 0, 7)`.
- **Test to Add:** `JwtAuthenticationFilterTest.should_accept_lowercase_bearer_prefix`

---

### [OR-3.1-05] Redundant Sequential Database Queries in `RoleResolutionService.resolveUncached`
- **Component:** [`RoleResolutionService.java:84-90`](file:///C:/entomo/AI/nexus/nexus-backend/src/main/java/com/example/nexus/rbac/application/RoleResolutionService.java#L84-L90)
- **Trace & Mechanism:** `resolveUncached` calls `findActiveRoleNames` and `findActivePermissionNames` in two separate roundtrips. Both queries perform joins across `user_roles`, `roles`, and `role_permissions`.
- **Minimal Fix:** Combine role names and permission names into a single composite projection query.
- **Test to Add:** `RoleResolutionServiceTest.should_fetch_roles_and_permissions_in_single_roundtrip`

---

### [OR-3.2-01] Token Minting Lacks Tenant Active Status Check
- **Component:** [`JwtRs256Service.java:110-130`](file:///C:/entomo/AI/nexus/nexus-backend/src/main/java/com/example/nexus/identity/infrastructure/security/JwtRs256Service.java#L110-L130)
- **Trace & Mechanism:** When minting a refresh token, `JwtRs256Service` validates user credentials but fails to query the tenant's current lifecycle state. Suspended or deleted tenants can continue refreshing tokens until the refresh token expires.
- **Minimal Fix:** Verify tenant status is `ACTIVE` before issuing new JWT tokens.
- **Test to Add:** `JwtRs256ServiceTest.should_reject_token_minting_for_suspended_tenant`

---

### [OR-3.3-06] `GlobalExceptionHandler` Maps Database Unique Constraint Violations to HTTP 500
- **Component:** [`GlobalExceptionHandler.java:110-125`](file:///C:/entomo/AI/nexus/nexus-backend/src/main/java/com/example/nexus/common/web/GlobalExceptionHandler.java#L110-L125)
- **Trace & Mechanism:** Uncaught `DataIntegrityViolationException` from race conditions (e.g. `uq_user_role_active`) falls through to generic exception handler, returning `500 INTERNAL_SERVER_ERROR` instead of `409 CONFLICT`.
- **Minimal Fix:** Catch `DataIntegrityViolationException` and map constraint names to structured 409 Problem Details.
- **Test to Add:** `GlobalExceptionHandlerTest.should_map_unique_constraint_to_409_conflict`

---

### [OR-4.1-05] `lockActiveAssignmentHoldersByRoles` Incomplete Scope When Role Code Changed in In-Flight Transaction
- **Component:** [`JpaUserRoleRepository.java:130-135`](file:///C:/entomo/AI/nexus/nexus-backend/src/main/java/com/example/nexus/rbac/infrastructure/persistence/JpaUserRoleRepository.java#L130-L135)
- **Trace & Mechanism:** If a role ID list is sorted using Java signed `UUID.compareTo` instead of unsigned byte order, lock acquisition order does not match MySQL binary index order, causing deadlock on index leaf page traversal.
- **Minimal Fix:** Assert unsigned byte array sorting comparator before executing locking queries.
- **Test to Add:** `JpaUserRoleRepositoryDeadlockTest.should_sort_role_ids_strictly_by_unsigned_bytes`

---

### [OR-4.1-06] Inconsistent Tenant Filtering on Role Replay Recovery
- **Component:** [`EpochReplayQueue.java:85-105`](file:///C:/entomo/AI/nexus/nexus-backend/src/main/java/com/example/nexus/rbac/application/EpochReplayQueue.java#L85-L105)
- **Trace & Mechanism:** `drain()` filters entries by tenant ID. If an entry has a null tenant ID due to a corrupted memory event, `key.tenantId().equals(tenantId)` throws `NullPointerException`, crashing the background scheduled replay worker thread.
- **Minimal Fix:** Add null safety filter: `filter(e -> e.tenantId() != null && e.tenantId().equals(tenantId))`.
- **Test to Add:** `EpochReplayQueueTest.should_handle_corrupted_entries_gracefully`
