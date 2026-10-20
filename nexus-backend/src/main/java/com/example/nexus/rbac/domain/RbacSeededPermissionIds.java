package com.example.nexus.rbac.domain;

import java.util.UUID;

/**
 * Fixed ids of catalogue permissions that authorization code checks by id against the fresh M13
 * read (US-018 07-security-review.md L-1). The values are the literals the migrations insert and
 * never change: {@code permissions} is migration-defined and read-only (ADR-0013 D1). Local until
 * the typed catalogue (B5) lands.
 *
 * <p>Test fixtures that address one specific permission use these constants rather than a literal
 * (US-019 03-design.md §3.5, enforced by {@code SeededPermissionLiteralScanTest}); fixtures that
 * mean "an administrator" enumerate the live catalogue instead.
 */
public final class RbacSeededPermissionIds {

  /** {@code tenant:write}, inserted by {@code V5__rbac_schema.sql}. */
  public static final UUID TENANT_WRITE = UUID.fromString("019f6839-1801-7000-8000-000000000002");

  /** {@code user:read}, inserted by {@code V5__rbac_schema.sql}. */
  public static final UUID USER_READ = UUID.fromString("019f6839-1802-7000-8000-000000000003");

  /** {@code user:write}, inserted by {@code V5__rbac_schema.sql}. */
  public static final UUID USER_WRITE = UUID.fromString("019f6839-1803-7000-8000-000000000004");

  /** {@code role:read}, inserted by {@code V5__rbac_schema.sql}. */
  public static final UUID ROLE_READ = UUID.fromString("019f6839-1804-7000-8000-000000000005");

  /** {@code role:write}, inserted by {@code V5__rbac_schema.sql}. */
  public static final UUID ROLE_WRITE = UUID.fromString("019f6839-1805-7000-8000-000000000006");

  /** {@code audit:read}, inserted by {@code V5__rbac_schema.sql}. */
  public static final UUID AUDIT_READ = UUID.fromString("019f6839-1806-7000-8000-000000000007");

  /** {@code user:role:assign}, inserted by {@code V6__rbac_user_role_assign_permission.sql}. */
  public static final UUID USER_ROLE_ASSIGN =
      UUID.fromString("019f6839-1807-7000-8000-000000000008");

  /**
   * {@code user:directory:read}, inserted by {@code V11__rbac_user_directory_read_permission.sql};
   * the RC-60 delegation rule checks it by id (US-019 03-design.md §4.8).
   */
  public static final UUID USER_DIRECTORY_READ =
      UUID.fromString("019f6839-1808-7000-8000-000000000009");

  private RbacSeededPermissionIds() {}
}
