package com.example.nexus;

import com.example.nexus.common.domain.LogMaskingUtil;
import com.example.nexus.identity.application.port.out.MailSenderPort;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.sql.Statement;
import org.flywaydb.core.api.callback.Callback;
import org.flywaydb.core.api.callback.Context;
import org.flywaydb.core.api.callback.Event;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;
import org.springframework.test.context.DynamicPropertyRegistrar;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.MySQLContainer;
import org.testcontainers.utility.DockerImageName;
import org.testcontainers.utility.MountableFile;

/**
 * Shared Testcontainers setup for integration tests (*IT). {@code @ServiceConnection} wires the
 * container's JDBC URL and credentials into the Spring context automatically — this stays the
 * default application-user credential ({@code test}) that Flyway and every existing *IT use; it
 * is deliberately NOT changed by the {@code nexus_app} provisioning added below (US-008
 * T-08-10). Note that this default credential is NOT root and has no {@code GRANT OPTION} — see
 * {@link #nexusAppGrantsCallback} for why the {@code nexus_app} grants need a separate root
 * connection. The {@link DynamicPropertyRegistrar} bean overrides Flyway and ddl-auto so no
 * profile-specific file (e.g. {@code application-smoke.yml}) can silently disable migrations in
 * the IT context.
 */
@TestConfiguration(proxyBeanMethods = false)
public class TestcontainersConfiguration {

    @Bean
    @ServiceConnection
    MySQLContainer<?> mysqlContainer() {
        // testcontainers-mysql.cnf sets log_bin_trust_function_creators=1.
        // MySQL 8.4 enables binary logging by default and removed SUPER, so
        // trigger creation fails (error 1419) without this config override.
        //
        // nexus-app-grants.sql (CREATE USER only) is copied into
        // /docker-entrypoint-initdb.d, MySQL's OWN first-boot init mechanism, which runs as
        // root before any JDBC connection is accepted (US-008 T-08-10, ADR 0012). This is
        // deliberately NOT MySQLContainer.withInitScript(...): that Testcontainers convenience
        // method executes its script over JDBC using the container's configured application
        // user ("test"), which lacks CREATE USER privilege and fails with
        // "Access denied; you need (at least one of) the CREATE USER privilege(s)" —
        // empirically confirmed when this was first tried. /docker-entrypoint-initdb.d runs as
        // root, matching the mechanism already used on the docker-compose side
        // (mysql/init/01-grants.sql). It intentionally does NOT grant table-scoped privileges
        // here: empirically verified against mysql:8.4 that GRANT ... ON db.table fails with
        // ERROR 1146 if the table does not exist yet, and the identity schema doesn't exist
        // until Flyway runs. The table-scoped GRANTs are applied by the nexusAppGrantsCallback
        // bean below, which fires on Flyway's AFTER_MIGRATE event.
        //
        // withDatabaseName("nexus") pins the schema name to match dev/prod (both use "nexus" —
        // see docker-compose.yml MYSQL_DATABASE, ADR 0012 §1's grant SQL). Without this, the
        // Testcontainers MySQL module defaults to a database named "test", and the
        // nexusAppGrantsCallback's hardcoded "nexus.<table>" GRANT statements fail with
        // ERROR 1146 "Table 'nexus.auth_events' doesn't exist" (empirically confirmed).
        return new MySQLContainer<>("mysql:8.4")
            .withDatabaseName("nexus")
            .withCopyFileToContainer(
                MountableFile.forClasspathResource("testcontainers-mysql.cnf"),
                "/etc/mysql/conf.d/testcontainers.cnf")
            .withCopyFileToContainer(
                MountableFile.forClasspathResource("nexus-app-grants.sql"),
                "/docker-entrypoint-initdb.d/01-nexus-app-user.sql");
    }

    /**
     * {@code RedisPermissionCacheAdapter} is an unconditional {@code @Component} (unlike {@code
     * RedisRateLimitStore}, which is {@code @ConditionalOnProperty}-gated), so every *IT context
     * that imports this class always autoconfigures a real {@code LettuceConnectionFactory}. With
     * no Redis reachable (CI never provisions one; locally, whenever the compose {@code redis}
     * service is stopped), Lettuce's default auto-reconnect keeps retrying against
     * {@code localhost:6379} in the background, and its failure-notification callbacks race this
     * class's own context teardown between *IT classes — surfacing as {@code
     * RejectedExecutionException: event executor terminated} log spam (harmless: every Redis-backed
     * adapter already fails open per ADR 0016, but noisy on every CI run). Gives every such
     * context a real, reachable Redis instead via {@code @ServiceConnection}. {@code name =
     * "redis"} is required (empirically confirmed): {@code RedisContainerConnectionDetailsFactory}
     * only recognizes the dedicated {@code com.redis.testcontainers.RedisContainer} type by image
     * name, not a plain {@link GenericContainer} — omitting {@code name} fails context startup
     * with {@code ConnectionDetailsNotFoundException}, unlike {@code mysqlContainer()} below,
     * whose dedicated {@code MySQLContainer} type is recognized without one.
     */
    @Bean
    @ServiceConnection(name = "redis")
    GenericContainer<?> redisContainer() {
        return new GenericContainer<>(DockerImageName.parse("redis:7.4-alpine"))
            .withExposedPorts(6379);
    }

    /**
     * US-008 T-08-10 (ADR 0012 §2, §5 CI-provisioning requirement): grants {@code nexus_app} its
     * scoped privileges once the identity schema exists. Registered as a Flyway {@link Callback}
     * (auto-collected by Spring Boot's {@code FlywayAutoConfiguration}, which takes an {@code
     * ObjectProvider<Callback>} — verified against {@code spring-boot-flyway} 4.1.0) rather than
     * via the {@link DynamicPropertyRegistrar} above, because a DynamicPropertyRegistrar only
     * registers properties — it has no hook to run SQL after migration — and, per this project's
     * known Spring Boot 4 gotcha, runs after component scan, which is the wrong timing for a step
     * that must happen strictly after Flyway completes. Flyway's {@code AFTER_MIGRATE} callback
     * fires exactly once per migration run.
     *
     * <p><b>Does NOT reuse {@code context.getConnection()}.</b> That connection is credentialed
     * as whatever {@code @ServiceConnection} wired for the container — Testcontainers'
     * {@code MySQLContainer} default application user ({@code test}), NOT root — which lacks
     * {@code GRANT OPTION} and fails the GRANT statements below with "GRANT command denied"
     * (empirically confirmed when this was first tried). {@code GRANT ... TO 'nexus_app'@'%'}
     * requires a principal that itself holds {@code GRANT OPTION}, so this callback opens a
     * separate, short-lived JDBC connection specifically as {@code root} (empirically confirmed:
     * Testcontainers' {@code MySQLContainer} sets {@code MYSQL_ROOT_PASSWORD} to the same
     * password as the configured application user whenever that user is not itself
     * {@code root}, and {@code root@'%'} — reachable over the container's exposed TCP port —
     * holds {@code GRANT OPTION} on {@code *.*}). This is a one-shot bootstrap connection, opened
     * and closed within this callback; it is not a second {@code DataSource} bean and does not
     * change which credential the application itself, Flyway's own migration connection, or any
     * other *IT connects as. This exists solely so the privilege-level *IT (T-08-11) can open a
     * connection as {@code nexus_app} against a real schema.
     */
    @Bean
    Callback nexusAppGrantsCallback(MySQLContainer<?> mysqlContainer) {
        return new Callback() {
            @Override
            public boolean supports(Event event, Context context) {
                return event == Event.AFTER_MIGRATE;
            }

            @Override
            public boolean canHandleInTransaction(Event event, Context context) {
                return false;
            }

            @Override
            public void handle(Event event, Context context) {
                try (Connection connection =
                        DriverManager.getConnection(
                            mysqlContainer.getJdbcUrl(), "root", mysqlContainer.getPassword());
                    Statement statement = connection.createStatement()) {
                    statement.execute(
                        "GRANT INSERT, SELECT ON nexus.auth_events TO 'nexus_app'@'%'");
                    statement.execute(
                        "GRANT SELECT, INSERT, UPDATE, DELETE ON nexus.users TO 'nexus_app'@'%'");
                    statement.execute(
                        "GRANT SELECT, INSERT, UPDATE, DELETE ON nexus.refresh_tokens TO"
                            + " 'nexus_app'@'%'");
                    statement.execute(
                        "GRANT SELECT, INSERT, UPDATE, DELETE ON nexus.auth_tokens TO"
                            + " 'nexus_app'@'%'");
                    statement.execute(
                        "GRANT SELECT ON nexus.permissions TO 'nexus_app'@'%'");
                    statement.execute(
                        "GRANT SELECT, INSERT ON nexus.roles TO 'nexus_app'@'%'");
                    statement.execute(
                        "GRANT SELECT, INSERT, DELETE ON nexus.role_permissions TO"
                            + " 'nexus_app'@'%'");
                    statement.execute(
                        "GRANT SELECT, INSERT ON nexus.user_roles TO 'nexus_app'@'%'");
                    statement.execute(
                        "GRANT UPDATE (revoked_at) ON nexus.user_roles TO 'nexus_app'@'%'");
                    statement.execute("FLUSH PRIVILEGES");
                } catch (SQLException e) {
                    throw new IllegalStateException(
                        "US-008 T-08-10: failed to grant nexus_app privileges after Flyway"
                            + " migration",
                        e);
                }
            }

            @Override
            public String getCallbackName() {
                return "nexusAppGrantsCallback";
            }
        };
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
