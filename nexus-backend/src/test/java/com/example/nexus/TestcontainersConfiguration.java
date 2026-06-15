package com.example.nexus;

import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.context.annotation.Bean;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.containers.MySQLContainer;

/**
 * Shared Testcontainers setup for integration tests (*IT). {@code @ServiceConnection} wires the
 * container's JDBC URL and credentials into the Spring context automatically — no property
 * overrides needed.
 */
@TestConfiguration(proxyBeanMethods = false)
public class TestcontainersConfiguration {

    @Bean
    @ServiceConnection
    MySQLContainer<?> mysqlContainer() {
        return new MySQLContainer<>("mysql:8.4");
    }

    @DynamicPropertySource
    static void itProperties(DynamicPropertyRegistry registry) {
        // Pin Flyway + ddl-auto so no profile file (e.g. application-test.yml with
        // flyway.enabled=false) can silently disable migrations in the IT context.
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
    }
}
