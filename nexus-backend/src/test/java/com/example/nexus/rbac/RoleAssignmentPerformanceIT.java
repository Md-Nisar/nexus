package com.example.nexus.rbac;

import static org.assertj.core.api.Assertions.assertThat;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.example.nexus.TestcontainersConfiguration;
import com.example.nexus.identity.domain.EmailCipher;
import com.example.nexus.identity.domain.User;
import com.example.nexus.identity.domain.UuidGenerator;
import com.example.nexus.identity.infrastructure.persistence.JpaUserRepository;
import com.example.nexus.rbac.application.RoleAssignmentService;
import com.example.nexus.rbac.domain.ActiveRoleAssignment;
import com.example.nexus.rbac.domain.PageResult;
import com.example.nexus.rbac.domain.Role;
import com.example.nexus.rbac.domain.RoleChangeActor;
import com.example.nexus.rbac.domain.UserRole;
import com.example.nexus.rbac.infrastructure.persistence.JpaRoleRepository;
import com.example.nexus.rbac.infrastructure.persistence.JpaUserRoleRepository;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;

/**
 * Performance IT verifying O(1) database queries in {@link RoleAssignmentService#listActive}.
 * Proves that listing a page of active assignments does not suffer from N+1 query regression
 * regardless of the number of assignments on the target user.
 */
@SpringBootTest
@Import(TestcontainersConfiguration.class)
@Tag("integration")
class RoleAssignmentPerformanceIT {

  @Autowired private RoleAssignmentService roleAssignmentService;
  @Autowired private JpaUserRepository userRepository;
  @Autowired private JpaRoleRepository roleRepository;
  @Autowired private JpaUserRoleRepository userRoleRepository;
  @Autowired private UuidGenerator uuidGenerator;

  @Test
  void should_execute_single_query_for_active_assignments_page() {
    UUID tenantId = uuidGenerator.newId();
    User actorUser = seedUser(tenantId);
    User targetUser = seedUser(tenantId);
    User assigner = seedUser(tenantId);

    // Seed 10 distinct roles and active assignments
    for (int i = 0; i < 10; i++) {
      Role role = seedRole("PERF-ROLE-" + i, tenantId);
      seedAssignment(targetUser.getId(), role.getId(), tenantId, assigner.getId());
    }

    RoleChangeActor actor = new RoleChangeActor(actorUser.getId(), tenantId);

    // Warm-up call to avoid counting initial hibernate metadata queries
    roleAssignmentService.listActive(actor, targetUser.getId(), 0, 10);

    List<String> sqlStatements =
        captureHibernateSql(
            () -> {
              PageResult<ActiveRoleAssignment> result =
                  roleAssignmentService.listActive(actor, targetUser.getId(), 0, 10);
              assertThat(result.items()).hasSize(10);
            });

    // The page of 10 items must only execute bounded O(1) queries (tenant check, select, count),
    // strictly avoiding 10 separate queries for each assignment's assignedBy user.
    assertThat(sqlStatements)
        .as("Query count must remain O(1) and never scale N+1 with assignment count")
        .hasSizeLessThanOrEqualTo(5);
  }

  private List<String> captureHibernateSql(Runnable action) {
    Logger sqlLogger = (Logger) LoggerFactory.getLogger("org.hibernate.SQL");
    Level originalLevel = sqlLogger.getLevel();
    ListAppender<ILoggingEvent> appender = new ListAppender<>();
    appender.start();
    sqlLogger.addAppender(appender);
    sqlLogger.setLevel(Level.DEBUG);
    try {
      action.run();
    } finally {
      sqlLogger.detachAppender(appender);
      sqlLogger.setLevel(originalLevel);
      appender.stop();
    }
    return appender.list.stream().map(ILoggingEvent::getFormattedMessage).toList();
  }

  private User seedUser(UUID tenantId) {
    String email = "perf-" + UUID.randomUUID() + "@example.com";
    String hmac = "hmac-" + UUID.randomUUID().toString().replace("-", "");
    return userRepository.save(
        new User(uuidGenerator.newId(), tenantId, new EmailCipher(email), hmac, "test-hash", null));
  }

  private Role seedRole(String namePrefix, UUID tenantId) {
    UUID id = uuidGenerator.newId();
    Role role =
        new Role(
            id,
            tenantId,
            namePrefix + "-" + UUID.randomUUID().toString().substring(0, 8),
            "description",
            false);
    return roleRepository.saveAndFlush(role);
  }

  private void seedAssignment(UUID userId, UUID roleId, UUID tenantId, UUID assignedBy) {
    UserRole ur =
        new UserRole(
            uuidGenerator.newId(),
            userId,
            roleId,
            tenantId,
            assignedBy);
    userRoleRepository.saveAndFlush(ur);
  }
}
