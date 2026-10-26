# Master Compendium — Volume 4: Low-Severity Defects & Hygiene Register (12 Findings)

This volume provides full engineering dossiers for all **12 Low-Severity findings** across the Nexus RBAC subsystem and security perimeter.

---

## Table of Contents
1. [[OR-29] Log message in `RoleAssignmentService` emits `targetUserId` as raw UUID without masking in trace logs](#or-29-log-message-in-roleassignmentservice-emits-targetuserid-as-raw-uuid-without-masking-in-trace-logs)
2. [[OR-30] `PageParams` parsing treats negative page number as page 0 rather than returning 400 Bad Request](#or-30-pageparams-parsing-treats-negative-page-number-as-page-0-rather-than-returning-400-bad-request)
3. [[OR-31] Inconsistent error message between `ROLE_NOT_FOUND` and `USER_NOT_FOUND` on cross-tenant access](#or-31-inconsistent-error-message-between-role_not_found-and-user_not_found-on-cross-tenant-access)
4. [[OR-32] Redundant `@Transactional` annotation on repository default query methods](#or-32-redundant-transactional-annotation-on-repository-default-query-methods)
5. [[OR-33] OpenAPI Swagger schema documentation missing error response schemas for 429 Too Many Requests](#or-33-openapi-swagger-schema-documentation-missing-error-response-schemas-for-429-too-many-requests)
6. [[OR-34] Unused import in `JpaUserRoleAssignmentAdapter`](#or-34-unused-import-in-jpauserroleassignmentadapter)
7. [[OR-3.1-06] Hardcoded token expiration claim key string literal rather than shared constant](#or-31-06-hardcoded-token-expiration-claim-key-string-literal-rather-than-shared-constant)
8. [[OR-3.2-02] Redundant casting in `AuthenticatedRequestDetails.fromAuthentication`](#or-32-02-redundant-casting-in-authenticatedrequestdetailsfromauthentication)
9. [[OR-3.3-07] Inconsistent indentation in `application-prod.yml` logging properties](#or-33-07-inconsistent-indentation-in-application-prodyml-logging-properties)
10. [[OR-4.1-07] Phantom Read in `JpaUserRoleRepository.countActiveRoleHolders` under default REPEATABLE READ](#or-41-07-phantom-read-in-jpauserrolerepositorycountactiveroleholders-under-default-repeatable-read)
11. [[OR-4.2-07] Metrics tag cardinality for `tenantId` in debug counters](#or-42-07-metrics-tag-cardinality-for-tenantid-in-debug-counters)
12. [[OR-4.2-08] Redundant Redis PING health probe interval configured below driver timeout](#or-42-08-redundant-redis-ping-health-probe-interval-configured-below-driver-timeout)

---

### [OR-29] Log message in `RoleAssignmentService` emits `targetUserId` as raw UUID without masking in trace logs
- **Component:** [`RoleAssignmentService.java:211`](file:///C:/entomo/AI/nexus/nexus-backend/src/main/java/com/example/nexus/rbac/application/RoleAssignmentService.java#L211)
- **Proof:** Trace level logs emit `.addKeyValue(LOG_KEY_TARGET_USER_ID, targetUserId)` without redaction when DEBUG level is enabled, which can expose user IDs into unstructured text streams.
- **Minimal Fix:** Standardize structured masking or ensure trace logs conform to `LoggingStandardsTest`.
- **Test to Add:** `LoggingStandardsTest.should_not_leak_raw_user_identifiers_in_trace_logs`

---

### [OR-30] `PageParams` parsing treats negative page number as page 0 rather than returning 400 Bad Request
- **Component:** [`PageParams.java:28-32`](file:///C:/entomo/AI/nexus/nexus-backend/src/main/java/com/example/nexus/rbac/interfaces/rest/PageParams.java#L28-L32)
- **Proof:** `PageParams.parse(page, size)` sets `parsedPage = Math.max(0, parsedPage)`. A client sending `page=-1` receives a 200 OK with page 0 results instead of 400 VALIDATION_FAILED, contradicting the REST API guideline contract.
- **Minimal Fix:**
```diff
--- a/nexus-backend/src/main/java/com/example/nexus/rbac/interfaces/rest/PageParams.java
+++ b/nexus-backend/src/main/java/com/example/nexus/rbac/interfaces/rest/PageParams.java
@@ -28,3 +28,3 @@ public record PageParams(int page, int size) {
-    int parsedPage = page == null ? 0 : Math.max(0, Integer.parseInt(page));
+    if (page != null && Integer.parseInt(page) < 0) throw new FieldValidationException("page must be non-negative");
```
- **Test to Add:** `PageParamsTest.should_reject_negative_page_with_400`

---

### [OR-31] Inconsistent error message between `ROLE_NOT_FOUND` and `USER_NOT_FOUND` on cross-tenant access
- **Component:** [`AccessReviewService.java:95, 133`](file:///C:/entomo/AI/nexus/nexus-backend/src/main/java/com/example/nexus/rbac/application/AccessReviewService.java#L95)
- **Proof:** When a resource belongs to another tenant, `listRoleHolders` returns `No such role` while `getEffectivePermissions` returns `User not found`. The slight discrepancy in casing and phrasing leaks resource type enumeration across tenants.
- **Minimal Fix:** Harmonize error messages to `Resource not found` across all cross-tenant 404 responses.
- **Test to Add:** `CrossTenantNotFoundEquivalenceIT.should_return_identical_messages_for_all_entities`

---

### [OR-32] Redundant `@Transactional` annotation on repository default query methods
- **Component:** [`JpaUserRoleRepository.java:54`](file:///C:/entomo/AI/nexus/nexus-backend/src/main/java/com/example/nexus/rbac/infrastructure/persistence/JpaUserRoleRepository.java#L54)
- **Proof:** Redundant `@Transactional` placed on read-only Spring Data query interface methods where the caller service already defines the transaction boundary, causing minor overhead in Spring AOP transaction interceptors.
- **Minimal Fix:** Remove redundant `@Transactional` annotations from repository query method interfaces.
- **Test to Add:** `RbacArchitecturalRulesTest.repositories_should_not_declare_transactional`

---

### [OR-33] OpenAPI Swagger schema documentation missing error response schemas for 429 Too Many Requests
- **Component:** [`RoleController.java:110`](file:///C:/entomo/AI/nexus/nexus-backend/src/main/java/com/example/nexus/rbac/interfaces/rest/RoleController.java#L110)
- **Proof:** `RoleController` endpoints do not declare `@ProblemResponse(status = 429, codes = {"ROLE_CHANGE_THROTTLED"})`, causing generated Swagger UI / OpenAPI schemas to omit the 429 rate limit response schema.
- **Minimal Fix:** Add `@ProblemResponse(status = 429, codes = {"ROLE_CHANGE_THROTTLED"})` to role mutation controller handlers.
- **Test to Add:** `OpenApiDocumentationTest.should_document_429_on_throttled_endpoints`

---

### [OR-34] Unused import in `JpaUserRoleAssignmentAdapter`
- **Component:** [`JpaUserRoleAssignmentAdapter.java:8`](file:///C:/entomo/AI/nexus/nexus-backend/src/main/java/com/example/nexus/rbac/infrastructure/persistence/JpaUserRoleAssignmentAdapter.java#L8)
- **Proof:** `import java.util.Collections;` is declared but never referenced in the class body.
- **Minimal Fix:** Remove unused import statement.
- **Test to Add:** Checkstyle / Sonar import cleanliness rule verification.

---

### [OR-3.1-06] Hardcoded token expiration claim key string literal rather than shared constant
- **Component:** [`JwtRs256Service.java:125`](file:///C:/entomo/AI/nexus/nexus-backend/src/main/java/com/example/nexus/identity/infrastructure/security/JwtRs256Service.java#L125)
- **Proof:** Claims builder uses string literal `"epoch"` instead of referencing `AuthenticationDetailKeys.EPOCH`.
- **Minimal Fix:** Replace string literal with constant reference `AuthenticationDetailKeys.EPOCH`.
- **Test to Add:** `JwtRs256ServiceTest.should_use_constant_for_epoch_claim`

---

### [OR-3.2-02] Redundant casting in `AuthenticatedRequestDetails.fromAuthentication`
- **Component:** [`AuthenticatedRequestDetails.java:60`](file:///C:/entomo/AI/nexus/nexus-backend/src/main/java/com/example/nexus/common/security/AuthenticatedRequestDetails.java#L60)
- **Proof:** `rawPermissions.stream().map(String.class::cast)` is preceded by `allMatch(String.class::isInstance)`. Using `(String) s` in stream map simplifies bytecode.
- **Minimal Fix:** Streamline mapping expression.
- **Test to Add:** `AuthenticatedRequestDetailsTest.should_parse_valid_details_without_redundant_casts`

---

### [OR-3.3-07] Inconsistent indentation in `application-prod.yml` logging properties
- **Component:** [`application-prod.yml:45`](file:///C:/entomo/AI/nexus/nexus-backend/src/main/resources/application-prod.yml#L45)
- **Proof:** YAML indentation for `logging.level.com.example.nexus` has 4 spaces instead of standard 2 spaces, causing parsing warnings in strict YAML formatters.
- **Minimal Fix:** Re-format `application-prod.yml` to standard 2-space indentation.
- **Test to Add:** `YamlConfigurationSyntaxTest.should_conform_to_two_space_indentation`

---

### [OR-4.1-07] Phantom Read in `JpaUserRoleRepository.countActiveRoleHolders` under default REPEATABLE READ
- **Component:** [`JpaUserRoleRepository.java:464`](file:///C:/entomo/AI/nexus/nexus-backend/src/main/java/com/example/nexus/rbac/infrastructure/persistence/JpaUserRoleRepository.java#L464)
- **Proof:** Non-locking count query `countActiveRoleHolders` reads from InnoDB snapshot. A concurrent insert committed by another transaction is invisible to the snapshot read, leading to slightly stale counts in access review displays.
- **Minimal Fix:** Document snapshot isolation semantics on access review read-only contracts.
- **Test to Add:** `AccessReviewIT.should_document_repeatable_read_snapshot_behavior`

---

### [OR-4.2-07] Metrics tag cardinality for `tenantId` in debug counters
- **Component:** [`RoleManagementService.java:312`](file:///C:/entomo/AI/nexus/nexus-backend/src/main/java/com/example/nexus/rbac/application/RoleManagementService.java#L312)
- **Proof:** Debug metric counter registers tag `tenantId`. In a multi-tenant platform with 50,000 tenants, this creates 50,000 time series in Prometheus, triggering memory alerts on Prometheus server.
- **Minimal Fix:** Remove `tenantId` tag from high-frequency metric counters; keep tenant IDs in logs only.
- **Test to Add:** `RbacMetricCardinalityTest.should_not_include_tenant_tag_in_prometheus_metrics`

---

### [OR-4.2-08] Redundant Redis PING health probe interval configured below driver timeout
- **Component:** [`EpochRedisConfig.java:145`](file:///C:/entomo/AI/nexus/nexus-backend/src/main/java/com/example/nexus/rbac/infrastructure/cache/EpochRedisConfig.java#L145)
- **Proof:** `pingInterval` is set to 500ms while socket timeout is 1000ms. An unresponsive Redis causes overlapping PING probes to stack up in Lettuce channel handlers.
- **Minimal Fix:** Set `pingInterval` to at least `socketTimeout * 2` (e.g. 2000ms).
- **Test to Add:** `EpochRedisConfigTest.should_configure_ping_interval_greater_than_socket_timeout`
