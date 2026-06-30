package com.example.nexus;

import com.example.nexus.common.web.LogMaskingUtil;
import com.example.nexus.identity.application.port.out.MailSenderPort;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;
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
            // US-002: default tenant, fast Argon2 params, stub mail, feature flag on for ITs
            registry.add(
                "nexus.identity.default-tenant-id",
                () -> "00000000-0000-7000-8000-000000000001");
            registry.add("nexus.identity.argon2.memory-kb",   () -> "4096");
            registry.add("nexus.identity.argon2.iterations",  () -> "1");
            registry.add("nexus.identity.argon2.parallelism", () -> "1");
            // Use loopback IP (not "disabled") to avoid Windows DNS resolution blocking.
            // Connection to 127.0.0.1:1025 is refused immediately when MailHog is not running.
            registry.add("spring.mail.host",                  () -> "127.0.0.1");
            registry.add("spring.mail.properties.mail.smtp.connectiontimeout", () -> "500");
            registry.add("spring.mail.properties.mail.smtp.timeout",           () -> "500");
            registry.add("nexus.mail.from-address",           () -> "test@nexus.test");
            registry.add("nexus.frontend.base-url",           () -> "http://localhost:2000");
            registry.add(
                "feature.nexus-us002-auth-registration.enabled",
                () -> "true");
        };
    }

    // @ConditionalOnProperty on LoggingMailSenderAdapter is evaluated before DynamicPropertyRegistrar
    // runs, so it never activates in IT contexts. @Primary here wins over SmtpMailSenderAdapter.
    @Bean
    @Primary
    MailSenderPort stubMailSenderPort() {
        Logger log = LoggerFactory.getLogger("TestMailStub");
        return new MailSenderPort() {
            @Override
            public void sendVerificationEmail(String toEmail, String rawToken) {
                log.info("[MAIL-STUB] Verification email → {}", LogMaskingUtil.maskEmail(toEmail));
            }

            @Override
            public void sendAccountExistsEmail(String toEmail) {
                log.info("[MAIL-STUB] AccountExists email → {}", LogMaskingUtil.maskEmail(toEmail));
            }

            @Override
            public void sendPasswordResetEmail(String toEmail, String rawToken) {
                log.info("[MAIL-STUB] PasswordReset email → {}", LogMaskingUtil.maskEmail(toEmail));
            }
        };
    }
}
