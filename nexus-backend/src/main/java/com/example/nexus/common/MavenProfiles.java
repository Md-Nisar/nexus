package com.example.nexus.common;

/**
 * Maven build profile name constants for this project.
 *
 * <p>Maven profiles are build-time only and are activated via the {@code -P} flag — they are not
 * Spring profiles and have no runtime effect. Constants here serve as a single source of truth
 * for profile names referenced in documentation, CI scripts, and tooling.
 *
 * <p>Usage:
 *
 * <pre>{@code
 * # Run with extra static analysis
 * ./mvnw verify -Pquality
 *
 * # Run CVE dependency scan (requires NVD_API_KEY)
 * ./mvnw verify -Psecurity
 * }</pre>
 *
 * @see Profiles for runtime Spring profile constants
 */
public final class MavenProfiles {

  /**
   * Activates PMD static analysis on top of the default quality gates (Checkstyle, SpotBugs).
   * Not included in the default build — run explicitly before opening a PR on complex changes.
   *
   * <p>Activation: {@code ./mvnw verify -Pquality}
   */
  public static final String QUALITY = "quality";

  /**
   * Activates the OWASP Dependency-Check CVE scan. Fails the build on any dependency with CVSS
   * score ≥ 7. Requires the {@code NVD_API_KEY} environment variable to avoid NVD rate limits.
   * Slow — downloads the NVD vulnerability database on first run.
   *
   * <p>Activation: {@code ./mvnw verify -Psecurity}
   *
   * <p>CI: runs on every push via the {@code backend-build} workflow.
   */
  public static final String SECURITY = "security";

  private MavenProfiles() {}
}
