package com.example.nexus.rbac.application;

import com.example.nexus.rbac.application.port.out.UserRoleAssignmentPort;
import com.example.nexus.rbac.application.port.out.UserRoleQueryPort;
import com.example.nexus.rbac.domain.RoleChangeActor;
import com.example.nexus.rbac.domain.RoleRef;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import java.util.List;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * US-019 B4 (03-design.md §6): the signed-in caller's own live roles, permissions and
 * administrator status.
 *
 * <p>The reads share one read-only transaction, so they see one REPEATABLE READ snapshot and
 * cannot disagree. Every answer comes from the database: never the permission cache, never the
 * token's claims (T-S13), so a revocation shows the moment it commits. {@code isAdministrator}
 * comes from {@link RoleAssignmentService#isCallerAdministrator}, the one predicate (per role,
 * never the union; ADR-0021 D3), reused rather than copied.
 *
 * <p>No audit row (a read of own data, AS8), no cache and no throttle (design §6.2).
 */
@Service
@Transactional(readOnly = true)
public class CallerAuthorizationService {

  private static final Logger log = LoggerFactory.getLogger(CallerAuthorizationService.class);

  private static final String COUNTER_READS = "nexus.rbac.caller_authorization.reads";

  private final UserRoleQueryPort userRoleQueryPort;
  private final UserRoleAssignmentPort userRoleAssignmentPort;
  private final MeterRegistry meterRegistry;

  public CallerAuthorizationService(
      UserRoleQueryPort userRoleQueryPort,
      UserRoleAssignmentPort userRoleAssignmentPort,
      MeterRegistry meterRegistry) {
    this.userRoleQueryPort = userRoleQueryPort;
    this.userRoleAssignmentPort = userRoleAssignmentPort;
    this.meterRegistry = meterRegistry;
  }

  /**
   * The caller's live roles (ordered by name, then id), the distinct permission names they grant
   * (sorted), and whether one of those roles is admin-defining.
   */
  public CallerAuthorization read(RoleChangeActor actor) {
    List<RoleRef> roles = userRoleQueryPort.findActiveRoles(actor.userId(), actor.tenantId());
    List<String> permissions =
        userRoleQueryPort.findActivePermissionNames(actor.userId(), actor.tenantId()).stream()
            .distinct()
            .sorted()
            .toList();
    boolean administrator =
        RoleAssignmentService.isCallerAdministrator(userRoleAssignmentPort, actor);

    log.atDebug()
        .addKeyValue("event", "RBAC_CALLER_AUTHORIZATION_READ")
        .addKeyValue("actorUserId", actor.userId())
        .addKeyValue("roleCount", roles.size())
        .addKeyValue("isAdministrator", administrator)
        .log("Caller authorization read");
    Counter.builder(COUNTER_READS)
        .tag("isAdministrator", Boolean.toString(administrator))
        .register(meterRegistry)
        .increment();
    return new CallerAuthorization(roles, permissions, administrator);
  }

  /** The caller's authorization profile, as read live in one snapshot. */
  public record CallerAuthorization(
      List<RoleRef> roles, List<String> permissions, boolean isAdministrator) {

    public CallerAuthorization {
      roles = List.copyOf(roles);
      permissions = List.copyOf(permissions);
    }
  }
}
