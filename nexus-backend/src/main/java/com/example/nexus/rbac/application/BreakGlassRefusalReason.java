package com.example.nexus.rbac.application;

/**
 * Why a break-glass first-administrator grant was refused (US-018 A7, 03-design.md §7.1), with the
 * process exit code the CLI runner reports. The constant name is persisted as {@code reason} in
 * the {@code ROLE_BREAK_GLASS_GRANT} FAILURE row and in the {@code RBAC_BREAK_GLASS_USED} page.
 */
public enum BreakGlassRefusalReason {
  TARGET_USER_NOT_FOUND(3),
  TARGET_USER_NOT_ACTIVE(3),
  NO_SYSTEM_ADMIN_ROLE(4),
  TENANT_HAS_ADMIN(5);

  private final int exitCode;

  BreakGlassRefusalReason(int exitCode) {
    this.exitCode = exitCode;
  }

  public int exitCode() {
    return exitCode;
  }
}
