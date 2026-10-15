package com.example.nexus.rbac.application;

/**
 * Why a break-glass first-administrator grant was refused (US-018 A7, 03-design.md §7.1), with the
 * process exit code the CLI runner reports. The constant name is persisted as {@code reason} in
 * the {@code ROLE_BREAK_GLASS_GRANT} FAILURE row and in the {@code RBAC_BREAK_GLASS_USED} page.
 *
 * <p>Exit codes: 0 is a grant; 2 to 7 are refusals; 1 is an unexpected failure of the grant
 * transaction, the same code Spring Boot and the JVM report for a failed start or an uncaught
 * exception (T-008; 7 and 1 confirmed by the user, 03-design.md §7.1). Exit 1 is therefore
 * ambiguous; the runbook tells the two cases apart by the {@code RBAC_BREAK_GLASS_USED} page.
 */
public enum BreakGlassRefusalReason {
  /** A missing, repeated or malformed argument (RC-54(a)); no argument value is recorded. */
  INVALID_ARGUMENT(2),
  TARGET_USER_NOT_FOUND(3),
  TARGET_USER_NOT_ACTIVE(3),
  NO_SYSTEM_ADMIN_ROLE(4),
  TENANT_HAS_ADMIN(5),
  /** The change reference is already on a SUCCESS grant in any tenant (RC-37.2, RC-47). */
  CHANGE_REF_REUSED(6),
  /** The grant transaction lost a lock race (deadlock or lock wait timeout) and rolled back. */
  CONCURRENT_INVOCATION(7),
  /** The grant transaction failed for any other reason and rolled back. */
  UNEXPECTED_ERROR(1);

  private final int exitCode;

  BreakGlassRefusalReason(int exitCode) {
    this.exitCode = exitCode;
  }

  public int exitCode() {
    return exitCode;
  }
}
