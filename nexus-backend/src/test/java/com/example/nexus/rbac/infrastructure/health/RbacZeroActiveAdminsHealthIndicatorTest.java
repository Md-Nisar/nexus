package com.example.nexus.rbac.infrastructure.health;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.mockito.Mockito.when;

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
 * <p>Re-targeted by US-018 T-019 (row 15) onto the one definition of "administrator": the reader
 * reports tenants with an admin-defining role (every permission of the catalogue) and tenants with
 * an active holder of one, no names passed. The SQL itself is proven by the IT beside this class.
 */
@ExtendWith(MockitoExtension.class)
@Tag("UnitTest")
class RbacZeroActiveAdminsHealthIndicatorTest {

  @Mock private ZeroAdminTenantReader zeroAdminTenantReader;

  private RbacZeroActiveAdminsHealthIndicator indicator() {
    return new RbacZeroActiveAdminsHealthIndicator(zeroAdminTenantReader);
  }

  @Test
  void should_report_up_when_every_admin_defining_role_has_an_active_holder() {
    UUID tenantId = UUID.randomUUID();
    when(zeroAdminTenantReader.findTenantsWithAnAdminDefiningRole())
        .thenReturn(List.of(tenantId));
    when(zeroAdminTenantReader.findTenantsWithActiveAdminDefiningHolders())
        .thenReturn(List.of(tenantId));

    var health = indicator().health();

    assertThat(health.getStatus()).isEqualTo(Status.UP);
  }

  @Test
  void should_report_up_when_no_tenant_has_any_admin_defining_role() {
    when(zeroAdminTenantReader.findTenantsWithAnAdminDefiningRole())
        .thenReturn(List.of());
    when(zeroAdminTenantReader.findTenantsWithActiveAdminDefiningHolders())
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
    when(zeroAdminTenantReader.findTenantsWithAnAdminDefiningRole())
        .thenReturn(List.of(lockedOutTenantId));
    when(zeroAdminTenantReader.findTenantsWithActiveAdminDefiningHolders())
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
    when(zeroAdminTenantReader.findTenantsWithAnAdminDefiningRole())
        .thenReturn(List.of(tenantA, tenantB));
    when(zeroAdminTenantReader.findTenantsWithActiveAdminDefiningHolders())
        .thenReturn(List.of());

    var health = indicator().health();

    assertThat(health.getStatus()).isEqualTo(Status.DOWN);
    assertThat(health.getDetails()).containsEntry("affectedTenantCount", 2);
  }

  /**
   * FR-2's tenant-level, not role-level, question: a tenant with TWO admin-defining roles
   * where only one has holders is healthy — the driving set minus the holder set correctly
   * excludes it.
   */
  @Test
  void should_report_up_when_tenantHasOneHolderlessAdminDefiningRoleButAnotherWithAHolder() {
    UUID tenantId = UUID.randomUUID();
    when(zeroAdminTenantReader.findTenantsWithAnAdminDefiningRole())
        .thenReturn(List.of(tenantId));
    when(zeroAdminTenantReader.findTenantsWithActiveAdminDefiningHolders())
        .thenReturn(List.of(tenantId));

    var health = indicator().health();

    assertThat(health.getStatus()).isEqualTo(Status.UP);
  }

  @Test
  void should_report_unknown_not_throw_when_the_driving_set_query_fails() {
    when(zeroAdminTenantReader.findTenantsWithAnAdminDefiningRole())
        .thenThrow(new QueryTimeoutException("db unavailable"));

    var indicator = indicator();

    assertThatCode(indicator::health).doesNotThrowAnyException();
    assertThat(indicator.health().getStatus()).isEqualTo(Status.UNKNOWN);
  }

  @Test
  void should_report_unknown_not_throw_when_the_holder_set_query_fails() {
    when(zeroAdminTenantReader.findTenantsWithAnAdminDefiningRole())
        .thenReturn(List.of(UUID.randomUUID()));
    when(zeroAdminTenantReader.findTenantsWithActiveAdminDefiningHolders())
        .thenThrow(new QueryTimeoutException("db unavailable"));

    var indicator = indicator();

    assertThatCode(indicator::health).doesNotThrowAnyException();
    assertThat(indicator.health().getStatus()).isEqualTo(Status.UNKNOWN);
  }

  /** Row 15: the indicator takes no names, so a name can never decide who is an administrator. */
  @Test
  void should_askTheReaderWithoutAnyArguments_when_checking() {
    when(zeroAdminTenantReader.findTenantsWithAnAdminDefiningRole()).thenReturn(List.of());
    when(zeroAdminTenantReader.findTenantsWithActiveAdminDefiningHolders()).thenReturn(List.of());

    indicator().health();

    org.mockito.Mockito.verify(zeroAdminTenantReader).findTenantsWithAnAdminDefiningRole();
    org.mockito.Mockito.verify(zeroAdminTenantReader).findTenantsWithActiveAdminDefiningHolders();
    org.mockito.Mockito.verify(zeroAdminTenantReader).countActiveAssignmentsOnDeletedRolesInAnyTenant();
    org.mockito.Mockito.verifyNoMoreInteractions(zeroAdminTenantReader);
  }

  // -- US-018 T-026 / RC-36.4: the soft-delete invariant detector ------------------------------

  @Test
  void should_report_up_withAZeroDetail_when_noActiveAssignmentReferencesADeletedRole() {
    when(zeroAdminTenantReader.findTenantsWithAnAdminDefiningRole()).thenReturn(List.of());
    when(zeroAdminTenantReader.findTenantsWithActiveAdminDefiningHolders()).thenReturn(List.of());
    when(zeroAdminTenantReader.countActiveAssignmentsOnDeletedRolesInAnyTenant()).thenReturn(0L);

    var health = indicator().health();

    assertThat(health.getStatus()).isEqualTo(Status.UP);
    assertThat(health.getDetails()).containsEntry("deletedRoleActiveAssignments", 0L);
  }

  @Test
  void should_report_down_withCountOnly_when_anActiveAssignmentReferencesADeletedRole() {
    when(zeroAdminTenantReader.findTenantsWithAnAdminDefiningRole()).thenReturn(List.of());
    when(zeroAdminTenantReader.findTenantsWithActiveAdminDefiningHolders()).thenReturn(List.of());
    when(zeroAdminTenantReader.countActiveAssignmentsOnDeletedRolesInAnyTenant()).thenReturn(2L);

    var health = indicator().health();

    assertThat(health.getStatus()).isEqualTo(Status.DOWN);
    assertThat(health.getDetails()).containsEntry("deletedRoleActiveAssignments", 2L);
    assertThat(health.getDetails()).containsEntry("affectedTenantCount", 0);
    assertThat(health.getDetails().keySet())
        .as("count only: no role, user or tenant ids")
        .containsExactlyInAnyOrder("affectedTenantCount", "deletedRoleActiveAssignments", "issue");
  }

  @Test
  void should_report_unknown_not_throw_when_the_deleted_role_detector_query_fails() {
    when(zeroAdminTenantReader.findTenantsWithAnAdminDefiningRole()).thenReturn(List.of());
    when(zeroAdminTenantReader.findTenantsWithActiveAdminDefiningHolders()).thenReturn(List.of());
    when(zeroAdminTenantReader.countActiveAssignmentsOnDeletedRolesInAnyTenant())
        .thenThrow(new QueryTimeoutException("timeout"));

    assertThat(indicator().health().getStatus()).isEqualTo(Status.UNKNOWN);
  }

  /** A holder in another tenant does not rescue a tenant that has none. */
  @Test
  void should_report_down_when_onlyAnotherTenantHasAnActiveAdminDefiningHolder() {
    UUID emptyTenant = UUID.randomUUID();
    UUID healthyTenant = UUID.randomUUID();
    when(zeroAdminTenantReader.findTenantsWithAnAdminDefiningRole())
        .thenReturn(List.of(emptyTenant, healthyTenant));
    when(zeroAdminTenantReader.findTenantsWithActiveAdminDefiningHolders())
        .thenReturn(List.of(healthyTenant));

    var health = indicator().health();

    assertThat(health.getStatus()).isEqualTo(Status.DOWN);
    assertThat(health.getDetails()).containsEntry("affectedTenantCount", 1);
  }
}
