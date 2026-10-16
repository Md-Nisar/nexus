package com.example.nexus.rbac.application;

import java.util.UUID;

/**
 * Result of {@link BootstrapAdminService#grantFirstAdmin} (US-018 A7, 03-design.md §7.1). Carries
 * the process exit code the CLI runner maps to {@code SpringApplication.exit}.
 */
public sealed interface BreakGlassOutcome {

  int exitCode();

  /** The target now holds the tenant's system {@code TENANT_ADMIN} role. Exit 0. */
  record Granted(UUID tenantId, UUID targetUserId, UUID roleId) implements BreakGlassOutcome {
    @Override
    public int exitCode() {
      return 0;
    }
  }

  /** Nothing was granted; the refusal was audited and paged. Exit {@code reason.exitCode()}. */
  record Refused(BreakGlassRefusalReason reason) implements BreakGlassOutcome {
    @Override
    public int exitCode() {
      return reason.exitCode();
    }
  }
}
