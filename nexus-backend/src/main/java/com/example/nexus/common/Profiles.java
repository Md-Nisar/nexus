package com.example.nexus.common;

/**
 * Spring profile name constants for this application.
 *
 * <p>Use these in {@code @Profile}, {@code @ActiveProfiles}, and programmatic profile checks
 * instead of raw string literals.
 *
 * <ul>
 *   <li>{@link #DEV} — local development: SQL logging, debug log level, placeholder crypto keys.
 *       Not active by default; applied to local {@code spring-boot:run} via the
 *       spring-boot-maven-plugin config in {@code pom.xml}. Deployments must set
 *       {@code SPRING_PROFILES_ACTIVE} explicitly, so an unconfigured run fails closed.
 *   <li>{@link #SMOKE} — H2 in-memory context smoke test: Flyway disabled, {@code
 *       ddl-auto=create-drop}. Active only for {@code NexusBackendApplicationTests} via {@code
 *       @ActiveProfiles}. Named "smoke" rather than "test" to avoid confusion with integration
 *       tests ({@code *IT}) which do not use a named profile.
 * </ul>
 *
 * <p>Integration tests ({@code *IT}) do not use a named profile — they activate Testcontainers
 * MySQL and override properties via {@code TestcontainersConfiguration}.
 *
 * @see MavenProfiles for build-time Maven profile constants
 */
public final class Profiles {

  /** Local development profile. SQL logging on, debug level, non-secret placeholder crypto keys. */
  public static final String DEV = "dev";

  /**
   * H2 in-memory context smoke-test profile. Flyway disabled, Hibernate {@code create-drop},
   * placeholder crypto keys. Named "smoke" to distinguish from integration tests ({@code *IT}).
   * Never use in shared, staging, or production environments.
   */
  public static final String SMOKE = "smoke";

  private Profiles() {}
}
