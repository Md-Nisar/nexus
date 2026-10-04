package com.example.nexus.common.security;

/**
 * Classifies why an {@link InsufficientPermissionException} was thrown, so that logs, metrics,
 * and callers can distinguish "authenticated but lacks permission" from failures upstream of the
 * permission check itself (threat-model T-08 / Condition 5).
 */
public enum DenialReason {
  PERMISSION_ABSENT,
  MALFORMED_AUTHENTICATION,
  MISSING_TENANT,
  // US-012: the target of a role assignment/revocation/read does not belong to the caller's tenant.
  CROSS_TENANT_TARGET,
  // US-012 AC8: caller lacks an active TENANT_ADMIN assignment and attempted to grant TENANT_ADMIN.
  NOT_TENANT_ADMIN,
  // US-018 A2 (ADR-0021 D2): the target role carries a permission the caller does not hold, or
  // (A3) the permission being attached to a role is one the caller does not hold.
  GRANT_EXCEEDS_CALLER,
  // US-018 A4 (ADR-0021): a caller who is not an administrator assigned a role to themselves.
  SELF_ASSIGNMENT
}
