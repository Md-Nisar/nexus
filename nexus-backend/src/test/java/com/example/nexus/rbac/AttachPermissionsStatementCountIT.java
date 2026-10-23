package com.example.nexus.rbac;

import static org.assertj.core.api.Assertions.assertThat;

import com.example.nexus.TestcontainersConfiguration;
import com.example.nexus.identity.domain.UuidGenerator;
import com.example.nexus.rbac.application.port.out.RoleManagementPort;
import com.example.nexus.rbac.domain.Role;
import com.example.nexus.rbac.infrastructure.persistence.JpaRoleRepository;
import jakarta.persistence.EntityManagerFactory;
import java.nio.ByteBuffer;
import java.util.List;
import java.util.UUID;
import org.hibernate.SessionFactory;
import org.hibernate.stat.Statistics;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.ActiveProfiles;

/**
 * US-019 P-22: {@code attachPermissions} inserts the join rows without a per-id existence
 * {@code SELECT} (a merge of a detached-looking entity), so the statement count never exceeds the
 * number of ids.
 */
@SpringBootTest(properties = "spring.jpa.properties.hibernate.generate_statistics=true")
@ActiveProfiles("test")
@Import(TestcontainersConfiguration.class)
@Tag("IT")
class AttachPermissionsStatementCountIT {

  @Autowired private RoleManagementPort port;
  @Autowired private JpaRoleRepository roleRepository;
  @Autowired private UuidGenerator uuidGenerator;
  @Autowired private JdbcTemplate jdbc;
  @Autowired private EntityManagerFactory entityManagerFactory;

  @Test
  void should_issueNoPerIdSelect_when_attachingPermissions() {
    Role role =
        roleRepository.save(
            new Role(uuidGenerator.newId(), uuidGenerator.newId(), "AP-" + UUID.randomUUID(), "ap", false));
    List<UUID> permissionIds =
        jdbc.query("SELECT id FROM permissions", (rs, i) -> fromBytes(rs.getBytes(1)));
    assertThat(permissionIds.size()).isGreaterThan(2);
    Statistics statistics = entityManagerFactory.unwrap(SessionFactory.class).getStatistics();
    statistics.clear();

    port.attachPermissions(role.getId(), permissionIds);

    assertThat(statistics.getPrepareStatementCount()).isLessThanOrEqualTo(permissionIds.size());
    assertThat(port.findPermissionsForRole(role.getId())).hasSameSizeAs(permissionIds);
  }

  private static UUID fromBytes(byte[] bytes) {
    ByteBuffer buf = ByteBuffer.wrap(bytes);
    return new UUID(buf.getLong(), buf.getLong());
  }
}
