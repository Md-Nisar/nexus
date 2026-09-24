package com.example.nexus.rbac.infrastructure.health;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.mockito.Mockito.when;

import com.example.nexus.rbac.domain.RbacDangerousPermissions;
import com.example.nexus.rbac.domain.RbacRoleNames;
import com.example.nexus.rbac.infrastructure.persistence.ZeroAdminTenantReader;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.boot.health.contributor.Status;
import org.springframework.dao.QueryTimeoutException;

/**
 * Unit coverage for the T-015 / T-D4 / US-017 FR-2 zero-active-admins detection control, in
 * isolation from a real database (Mockito {@link ZeroAdminTenantReader}; no Spring context).
 *
 * <p>Re-scoped post-06-code-review.md H-1 (2026-09-24) from the ANY-admin-equivalent predicate to
 * the caller-qualifying (literal {@code TENANT_ADMIN} OR ALL THREE dangerous permissions)
 * predicate — see {@link ZeroAdminTenantReader}'s Javadoc.
 */
@ExtendWith(MockitoExtension.class)
@Tag("UnitTest")
class RbacZeroActiveAdminsHealthIndicatorTest {

  private static final long DANGEROUS_NAMES_COUNT = RbacDangerousPermissions.NAMES.size();

  @Mock private ZeroAdminTenantReader zeroAdminTenantReader;

  private RbacZeroActiveAdminsHealthIndicator indicator() {
    return new RbacZeroActiveAdminsHealthIndicator(zeroAdminTenantReader);
  }

  @Test
  void should_report_up_when_every_caller_qualifying_role_has_an_active_holder() {
    UUID tenantId = UUID.randomUUID();
    when(zeroAdminTenantReader.findTenantsWithAFullyAdminEquivalentRole(
            RbacRoleNames.TENANT_ADMIN, RbacDangerousPermissions.NAMES, DANGEROUS_NAMES_COUNT))
        .thenReturn(List.of(tenantId));
    when(zeroAdminTenantReader.findTenantsWithActiveFullyAdminEquivalentHolders(
            RbacRoleNames.TENANT_ADMIN, RbacDangerousPermissions.NAMES, DANGEROUS_NAMES_COUNT))
        .thenReturn(List.of(tenantId));

    var health = indicator().health();

    assertThat(health.getStatus()).isEqualTo(Status.UP);
  }

  @Test
  void should_report_up_when_no_tenant_has_any_caller_qualifying_role() {
    when(zeroAdminTenantReader.findTenantsWithAFullyAdminEquivalentRole(
            RbacRoleNames.TENANT_ADMIN, RbacDangerousPermissions.NAMES, DANGEROUS_NAMES_COUNT))
        .thenReturn(List.of());
    when(zeroAdminTenantReader.findTenantsWithActiveFullyAdminEquivalentHolders(
            RbacRoleNames.TENANT_ADMIN, RbacDangerousPermissions.NAMES, DANGEROUS_NAMES_COUNT))
        .thenReturn(List.of());

    var health = indicator().health();

    assertThat(health.getStatus()).isEqualTo(Status.UP);
  }

  // 07-security-review.md M-1: the detail exposes only a COUNT, never the tenant ids
  // themselves — /actuator/health is readable by any authenticated principal of any tenant
  // (management.endpoint.health.roles is unset), so publishing other tenants' UUIDs there
  // would be a cross-tenant disclosure. The full id list is asserted via the WARN log instead.

  @Test
  void should_report_down_withCountOnly_never_theTenantIds_when_aTenantHasZeroActiveAdmins() {
    UUID lockedOutTenantId = UUID.randomUUID();
    when(zeroAdminTenantReader.findTenantsWithAFullyAdminEquivalentRole(
            RbacRoleNames.TENANT_ADMIN, RbacDangerousPermissions.NAMES, DANGEROUS_NAMES_COUNT))
        .thenReturn(List.of(lockedOutTenantId));
    when(zeroAdminTenantReader.findTenantsWithActiveFullyAdminEquivalentHolders(
            RbacRoleNames.TENANT_ADMIN, RbacDangerousPermissions.NAMES, DANGEROUS_NAMES_COUNT))
        .thenReturn(List.of());

    var health = indicator().health();

    assertThat(health.getStatus()).isEqualTo(Status.DOWN);
    assertThat(health.getDetails()).containsEntry("affectedTenantCount", 1);
    assertThat(health.getDetails()).doesNotContainKey("tenantIds");
    assertThat(health.getDetails().toString()).doesNotContain(lockedOutTenantId.toString());
  }

  @Test
  void should_report_down_withCorrectCount_when_multipleTenantsAreLockedOut() {
    UUID tenantA = UUID.randomUUID();
    UUID tenantB = UUID.randomUUID();
    when(zeroAdminTenantReader.findTenantsWithAFullyAdminEquivalentRole(
            RbacRoleNames.TENANT_ADMIN, RbacDangerousPermissions.NAMES, DANGEROUS_NAMES_COUNT))
        .thenReturn(List.of(tenantA, tenantB));
    when(zeroAdminTenantReader.findTenantsWithActiveFullyAdminEquivalentHolders(
            RbacRoleNames.TENANT_ADMIN, RbacDangerousPermissions.NAMES, DANGEROUS_NAMES_COUNT))
        .thenReturn(List.of());

    var health = indicator().health();

    assertThat(health.getStatus()).isEqualTo(Status.DOWN);
    assertThat(health.getDetails()).containsEntry("affectedTenantCount", 2);
  }

  /**
   * FR-2's tenant-level, not role-level, question: a tenant with TWO caller-qualifying roles
   * where only one has holders is healthy — the driving set minus the holder set correctly
   * excludes it.
   */
  @Test
  void should_report_up_when_tenantHasOneHolderlessCallerQualifyingRoleButAnotherWithAHolder() {
    UUID tenantId = UUID.randomUUID();
    when(zeroAdminTenantReader.findTenantsWithAFullyAdminEquivalentRole(
            RbacRoleNames.TENANT_ADMIN, RbacDangerousPermissions.NAMES, DANGEROUS_NAMES_COUNT))
        .thenReturn(List.of(tenantId));
    when(zeroAdminTenantReader.findTenantsWithActiveFullyAdminEquivalentHolders(
            RbacRoleNames.TENANT_ADMIN, RbacDangerousPermissions.NAMES, DANGEROUS_NAMES_COUNT))
        .thenReturn(List.of(tenantId));

    var health = indicator().health();

    assertThat(health.getStatus()).isEqualTo(Status.UP);
  }

  @Test
  void should_report_unknown_not_throw_when_the_driving_set_query_fails() {
    when(zeroAdminTenantReader.findTenantsWithAFullyAdminEquivalentRole(
            RbacRoleNames.TENANT_ADMIN, RbacDangerousPermissions.NAMES, DANGEROUS_NAMES_COUNT))
        .thenThrow(new QueryTimeoutException("db unavailable"));

    var indicator = indicator();

    assertThatCode(indicator::health).doesNotThrowAnyException();
    assertThat(indicator.health().getStatus()).isEqualTo(Status.UNKNOWN);
  }

  @Test
  void should_report_unknown_not_throw_when_the_holder_set_query_fails() {
    when(zeroAdminTenantReader.findTenantsWithAFullyAdminEquivalentRole(
            RbacRoleNames.TENANT_ADMIN, RbacDangerousPermissions.NAMES, DANGEROUS_NAMES_COUNT))
        .thenReturn(List.of(UUID.randomUUID()));
    when(zeroAdminTenantReader.findTenantsWithActiveFullyAdminEquivalentHolders(
            RbacRoleNames.TENANT_ADMIN, RbacDangerousPermissions.NAMES, DANGEROUS_NAMES_COUNT))
        .thenThrow(new QueryTimeoutException("db unavailable"));

    var indicator = indicator();

    assertThatCode(indicator::health).doesNotThrowAnyException();
    assertThat(indicator.health().getStatus()).isEqualTo(Status.UNKNOWN);
  }
}
