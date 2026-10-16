package com.example.nexus.rbac.application.port.out;

/**
 * A user's lifecycle status as {@code rbac} sees it through {@link UserDirectoryPort} (US-018 A7,
 * O-7 and L-2). Port-local, with the same constants as {@code identity.domain.UserStatus}, so
 * {@code rbac} never imports {@code identity}.
 */
public enum DirectoryUserStatus {
  PENDING,
  ACTIVE,
  LOCKED,
  DISABLED
}
