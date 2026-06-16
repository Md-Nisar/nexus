package com.example.nexus;

import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.context.annotation.Bean;
import org.springframework.test.context.DynamicPropertyRegistrar;
import org.testcontainers.containers.MySQLContainer;
import org.testcontainers.utility.MountableFile;

/**
 * Shared Testcontainers setup for integration tests (*IT). {@code @ServiceConnection} wires the
 * container's JDBC URL and credentials into the Spring context automatically. The
 * {@link DynamicPropertyRegistrar} bean overrides Flyway and ddl-auto so no profile-specific file
 * (e.g. {@code application-smoke.yml}) can silently disable migrations in the IT context.
 */
@TestConfiguration(proxyBeanMethods = false)
public class TestcontainersConfiguration {

    @Bean
    @ServiceConnection
    MySQLContainer<?> mysqlContainer() {
        // testcontainers-mysql.cnf sets log_bin_trust_function_creators=1.
        // MySQL 8.4 enables binary logging by default and removed SUPER, so
        // trigger creation fails (error 1419) without this config override.
        return new MySQLContainer<>("mysql:8.4")
            .withCopyFileToContainer(
                MountableFile.forClasspathResource("testcontainers-mysql.cnf"),
                "/etc/mysql/conf.d/testcontainers.cnf");
    }

    // DynamicPropertyRegistrar (@Bean) is the Spring Framework 6.2+ / 7.x canonical way to
    // register dynamic test properties from an imported @TestConfiguration.  The static
    // @DynamicPropertySource approach (SF 6.1) is not picked up in SF 7.x when the class is
    // imported via @Import rather than being the test class itself.
    @Bean
    DynamicPropertyRegistrar itProperties() {
        return registry -> {
            // Pin Flyway + ddl-auto regardless of which profile files load (e.g. application-smoke.yml
            // sets flyway.enabled=false for the H2 smoke test; we must not inherit that here).
            registry.add("spring.flyway.enabled", () -> "true");
            registry.add("spring.jpa.hibernate.ddl-auto", () -> "validate");
            registry.add(
                "nexus.identity.encryption.password",
                () -> "test-not-a-secret-encryption-password");
            registry.add(
                "nexus.identity.encryption.salt",
                () -> "cafebabecafebabecafebabecafebabe");
            registry.add(
                "nexus.identity.hmac-key",
                () -> "test-not-a-secret-hmac-key-min-32-bytes!!");
        };
    }
}
