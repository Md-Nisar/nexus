package com.example.nexus.rbac;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.example.nexus.TestcontainersConfiguration;
import com.example.nexus.identity.domain.UuidGenerator;
import java.nio.ByteBuffer;
import java.util.UUID;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.dao.DataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;

/**
 * US-009 T-09-05 (AC5; Scenarios 2, 3): tenant isolation on {@code roles} via {@code
 * uq_roles_tenant_name}. Depends only on T-09-01 (schema), not the JPA entities, so fixtures are
 * inserted directly via raw {@code JdbcTemplate} -- mirrors {@code AuthEventsAppendOnlyIT}'s
 * raw-SQL style rather than going through {@code JpaRoleRepository}.
 *
 * <p>All fixture roles here pass {@code is_system_role=FALSE} explicitly, keeping {@code
 * RbacSchemaMigrationIT}'s scoped seed-role count stable regardless of test execution order (see
 * that class's Javadoc).
 */
@SpringBootTest
@Import(TestcontainersConfiguration.class)
@Tag("IT")
class RoleUniquenessIT {

  @Autowired private JdbcTemplate jdbc;
  @Autowired private UuidGenerator uuidGenerator;

  private void insertRole(UUID id, UUID tenantId, String name) {
    jdbc.update(
        "INSERT INTO roles (id, tenant_id, name, is_system_role) VALUES (?, ?, ?, FALSE)",
        toBytes(id),
        toBytes(tenantId),
        name);
  }

  @Test
  void should_rejectDuplicateName_when_sameTenant() {
    UUID tenantId = uuidGenerator.newId();
    String name = "DUP-" + UUID.randomUUID();
    insertRole(uuidGenerator.newId(), tenantId, name);

    assertThatThrownBy(() -> insertRole(uuidGenerator.newId(), tenantId, name))
        .isInstanceOf(DataAccessException.class);
  }

  @Test
  void should_allowSameName_when_differentTenants() {
    UUID tenantA = uuidGenerator.newId();
    UUID tenantB = uuidGenerator.newId();
    String name = "SHARED-" + UUID.randomUUID();

    insertRole(uuidGenerator.newId(), tenantA, name);
    insertRole(uuidGenerator.newId(), tenantB, name);

    Integer count =
        jdbc.queryForObject("SELECT COUNT(*) FROM roles WHERE name = ?", Integer.class, name);
    assertThat(count).as("both rows must persist -- uniqueness is per-tenant, not global").isEqualTo(2);
  }

  private static byte[] toBytes(UUID uuid) {
    ByteBuffer buf = ByteBuffer.allocate(16);
    buf.putLong(uuid.getMostSignificantBits());
    buf.putLong(uuid.getLeastSignificantBits());
    return buf.array();
  }
}
