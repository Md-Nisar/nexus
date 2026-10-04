package com.example.nexus.rbac.domain;

import java.util.UUID;

/**
 * Fixed ids of catalogue permissions that authorization code checks by id against the fresh M13
 * read (US-018 07-security-review.md L-1). The values are the literals the migrations insert and
 * never change: {@code permissions} is migration-defined and read-only (ADR-0013 D1). Local until
 * the typed catalogue (B5) lands.
 */
public final class RbacSeededPermissionIds {

  /** {@code user:role:assign}, inserted by {@code V6__rbac_user_role_assign_permission.sql}. */
  public static final UUID USER_ROLE_ASSIGN =
      UUID.fromString("019f6839-1807-7000-8000-000000000008");

  /** {@code role:write}, inserted by {@code V5__rbac_schema.sql}. */
  public static final UUID ROLE_WRITE = UUID.fromString("019f6839-1805-7000-8000-000000000006");

  private RbacSeededPermissionIds() {}
}
