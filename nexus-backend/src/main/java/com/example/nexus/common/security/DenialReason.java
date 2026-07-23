package com.example.nexus.common.security;

/**
 * Classifies why an {@link InsufficientPermissionException} was thrown, so that logs, metrics,
 * and callers can distinguish "authenticated but lacks permission" from failures upstream of the
 * permission check itself (threat-model T-08 / Condition 5).
 */
public enum DenialReason {
  PERMISSION_ABSENT,
  MALFORMED_AUTHENTICATION,
  MISSING_TENANT
}
