package com.example.nexus.common.security;

import java.util.Set;

/**
 * The permission catalogue as compile-time constants: one {@code String} per row of the {@code
 * permissions} table (V5 seeds seven, V6 and V11 add one each). Every {@code
 * @RequiresPermission} value and every service-level {@code requiredPermission} references a
 * constant here, so a typo is a compile error and a name that is not in the catalogue is caught by
 * {@code PermissionsCatalogueTest}, not by a silently unguardable endpoint (US-018 B5).
 *
 * <p>Lives in {@code common} because {@code identity} controllers may need it and {@code rbac ->
 * identity} is forbidden. The frontend mirrors this list in {@code shared/types/permission.ts}; the
 * two are kept in step by hand, and each side's test fails when a referenced name is unknown.
 * Adding a catalogue row means adding a constant here, to {@link #ALL}, and to the TypeScript
 * list; {@code PermissionsCatalogueIT} fails when {@link #ALL} and the table disagree.
 */
public final class Permissions {

  public static final String TENANT_READ = "tenant:read";
  public static final String TENANT_WRITE = "tenant:write";
  public static final String USER_READ = "user:read";
  public static final String USER_WRITE = "user:write";
  public static final String ROLE_READ = "role:read";
  public static final String ROLE_WRITE = "role:write";
  public static final String AUDIT_READ = "audit:read";
  public static final String USER_ROLE_ASSIGN = "user:role:assign";
  public static final String USER_DIRECTORY_READ = "user:directory:read";

  /** Every catalogue entry. Immutable. */
  public static final Set<String> ALL =
      Set.of(
          TENANT_READ,
          TENANT_WRITE,
          USER_READ,
          USER_WRITE,
          ROLE_READ,
          ROLE_WRITE,
          AUDIT_READ,
          USER_ROLE_ASSIGN,
          USER_DIRECTORY_READ);

  /**
   * Permissions whose holder controls identities, role assignments, role definitions or the
   * tenant, or can read personal data or the audit trail. A display hint only: no server rule may
   * read it (US-019 RC-63(k), enforced by ArchUnit). Together with {@link #NON_SENSITIVE} it
   * partitions {@link #ALL}.
   */
  public static final Set<String> SENSITIVE =
      Set.of(TENANT_WRITE, USER_WRITE, ROLE_WRITE, USER_ROLE_ASSIGN, USER_DIRECTORY_READ, AUDIT_READ);

  /** The rest of the catalogue; see {@link #SENSITIVE}. */
  public static final Set<String> NON_SENSITIVE = Set.of(TENANT_READ, USER_READ, ROLE_READ);

  private Permissions() {}
}
