package com.example.nexus.common;

/**
 * Spring profile name constants for this application.
 *
 * <p>Use these in {@code @Profile}, {@code @ActiveProfiles}, and programmatic profile checks
 * instead of raw string literals.
 *
 * <ul>
 *   <li>{@link #DEV} — local development: SQL logging, debug log level, placeholder crypto keys.
 *       Active by default (see {@code application.yml → spring.profiles.active}).
 *   <li>{@link #TEST} — H2 in-memory smoke test: Flyway disabled, {@code ddl-auto=create-drop}.
 *       Active only for {@code NexusBackendApplicationTests} via {@code @ActiveProfiles}.
 * </ul>
 *
 * <p>Integration tests ({@code *IT}) do not use a named profile — they activate Testcontainers
 * MySQL and override properties via {@code TestcontainersConfiguration}.
 */
public final class Profiles {

  /** Local development profile. SQL logging on, debug level, non-secret placeholder crypto keys. */
  public static final String DEV = "dev";

  /**
   * H2 in-memory smoke-test profile. Flyway disabled, Hibernate {@code create-drop}, placeholder
   * crypto keys. Never use in shared, staging, or production environments.
   */
  public static final String TEST = "test";

  private Profiles() {}
}
