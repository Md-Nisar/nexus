package com.example.nexus.rbac.application;

/**
 * The result of one break-glass invocation and its process exit code (ADR-0025 1, 03-design.md
 * §7.1). The runner maps {@link #exitCode()} to {@code SpringApplication.exit}; the service never
 * exits the process itself.
 */
public enum BreakGlassOutcome {
  GRANTED(0),
  INVALID_ARGUMENT(2),
  USER_NOT_FOUND(3),
  USER_NOT_ACTIVE(3),
  NO_SYSTEM_ADMIN_ROLE(4),
  TENANT_HAS_ADMIN(5),
  CHANGE_REF_REUSED(6);

  private final int exitCode;

  BreakGlassOutcome(int exitCode) {
    this.exitCode = exitCode;
  }

  public int exitCode() {
    return exitCode;
  }

  /** The refusal reason written to the audit row and the page; {@code null} for a grant. */
  public String reason() {
    return this == GRANTED ? null : name();
  }
}
