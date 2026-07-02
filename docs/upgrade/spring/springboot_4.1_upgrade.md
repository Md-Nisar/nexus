# Spring Boot 4.1.0 Upgrade Documentation

This document records the upgrade of the `nexus-backend` service to **Spring Boot 4.1.0** while retaining **Java 25 (LTS)**.

---

## 1. Upgrade Summary

* **Date:** June 28, 2026
* **Changes:**
  * Upgraded `spring-boot-starter-parent` from `4.0.6` to `4.1.0` in [pom.xml](nexus/nexus-backend/pom.xml).
  * Maintained Java version at `25`.
  * Preserved existing Docker configuration in [Dockerfile](nexus/nexus-backend/Dockerfile) (retains `eclipse-temurin:25-jdk` and `eclipse-temurin:25-jre`).

---

## 2. Verification & Validation

The upgrade was verified using the following automated steps:

1. **Compilation Check:**
   ```powershell
   .\mvnw.cmd clean test-compile
   ```
   *Result:* Compiled successfully. Verified Lombok compatibility with the new Spring Boot parent version.

2. **Full Test Suite & Quality Gates:**
   ```powershell
   .\mvnw.cmd clean verify
   ```
   *Result:* **Build Success**.
   * **83/83 Tests Passed:** Both unit and integration tests (using Testcontainers for database integration) passed.
   * **Spring Context Bootstrapping:** `NexusApplicationIT` successfully booted the entire Spring Boot context, validating:
     * Successful application of Flyway database migrations.
     * JPA Hibernate schema validation against the database.
     * Spring Security filter chain initialization.
   * **Static Analysis:** SpotBugs and Checkstyle completed with 0 errors/violations.
   * **Code Coverage:** JaCoCo verified all coverage rules were met.

---

## 3. Unlocked Features

With the upgrade to Spring Boot 4.1.0, the following new capabilities are now available for the `nexus-backend` project:

### A. Native Spring gRPC Support
* **Built-in Starters:** Spring Boot 4.1.0 introduces native support for writing and testing gRPC server and client applications without requiring third-party starters.
* **Deployment Options:** Out-of-the-box support for standalone Netty-based gRPC servers or Servlet-based integration to expose gRPC over HTTP/2.
* **Testing:** Use the new `@GrpcTest` slice to write isolated integration tests for gRPC services.

### B. HTTP Client SSRF Mitigation
* **`InetAddressFilter`:** You can now configure blocking and reactive HTTP clients (`RestClient`, `RestTemplate`, and `WebClient`) with an `InetAddressFilter` to restrict outgoing requests to allowed/disallowed IP addresses or subnets. This hardens the backend against Server-Side Request Forgery (SSRF) attacks.

### C. Observability & Context Propagation
* **Async Context Propagation:** Tracing and security context are now automatically propagated to `@Async` methods via Micrometer's `ContextRegistry`.
* **OTLP SSL Bundles:** Configure SSL/TLS certificates for OpenTelemetry (OTLP) exporters using Spring Boot’s standard SSL bundles.

### D. Advanced Log4j File Rotation
* Configure file rotation strategies (size, time, size-and-time, or cron-based) directly in `application.properties` or `application.yml`.

### E. Lazy JDBC Connection Fetching
* Optimizes database connection pool utilization by deferring physical connection acquisition from the pool until the first SQL statement is executed.

---

## 4. Local Run & Verification

To run the application locally and perform manual sanity checks:

1. **Run the Backend:**
   ```powershell
   .\mvnw.cmd spring-boot:run
   ```
2. **Verify Swagger UI / OpenAPI:**
   Access the API documentation at [http://localhost:1000/swagger-ui/index.html](http://localhost:1000/swagger-ui/index.html).
3. **Verify Actuator Health:**
   Check the liveness and readiness endpoints at [http://localhost:1000/actuator/health](http://localhost:1000/actuator/health).
4. **IDE Synchronization:**
   * **IntelliJ IDEA:** Right-click the project root and select **Maven -> Reload Project** to update the dependency index.
   * **VS Code:** Run the command `Java: Clean Java Language Server Workspace`.
