package com.example.nexus.rbac.infrastructure.health;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.mockito.Mockito.when;

import com.example.nexus.rbac.domain.RbacRoleNames;
import com.example.nexus.rbac.infrastructure.persistence.JpaUserRoleRepository;
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
 * Unit coverage for the T-015 / T-D4 zero-active-admins detection control, in isolation from a
 * real database (Mockito {@link JpaUserRoleRepository}; no Spring context).
 */
@ExtendWith(MockitoExtension.class)
@Tag("UnitTest")
class RbacZeroActiveAdminsHealthIndicatorTest {

  @Mock private JpaUserRoleRepository userRoleRepository;

  private RbacZeroActiveAdminsHealthIndicator indicator() {
    return new RbacZeroActiveAdminsHealthIndicator(userRoleRepository);
  }

  @Test
  void should_report_up_when_every_tenant_has_at_least_one_active_admin() {
    when(userRoleRepository.findTenantsWithZeroActiveAssignmentsForRole(
            RbacRoleNames.TENANT_ADMIN))
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
    when(userRoleRepository.findTenantsWithZeroActiveAssignmentsForRole(
            RbacRoleNames.TENANT_ADMIN))
        .thenReturn(List.of(lockedOutTenantId));

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
    when(userRoleRepository.findTenantsWithZeroActiveAssignmentsForRole(
            RbacRoleNames.TENANT_ADMIN))
        .thenReturn(List.of(tenantA, tenantB));

    var health = indicator().health();

    assertThat(health.getStatus()).isEqualTo(Status.DOWN);
    assertThat(health.getDetails()).containsEntry("affectedTenantCount", 2);
  }

  @Test
  void should_report_unknown_not_throw_when_the_query_itself_fails() {
    when(userRoleRepository.findTenantsWithZeroActiveAssignmentsForRole(
            RbacRoleNames.TENANT_ADMIN))
        .thenThrow(new QueryTimeoutException("db unavailable"));

    var indicator = indicator();

    assertThatCode(indicator::health).doesNotThrowAnyException();
    assertThat(indicator.health().getStatus()).isEqualTo(Status.UNKNOWN);
  }
}
