package com.example.nexus.identity.infrastructure.persistence;

import com.example.nexus.identity.domain.User;
import com.example.nexus.identity.domain.UserStatus;
import com.example.nexus.rbac.application.port.out.DirectoryUser;
import com.example.nexus.rbac.application.port.out.DirectoryUserStatus;
import com.example.nexus.rbac.application.port.out.UserDirectoryPort;
import java.nio.ByteBuffer;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import org.springframework.stereotype.Component;

/**
 * {@code identity.infrastructure} implementation of {@link UserDirectoryPort}, delegating to the
 * existing {@link JpaUserRepository}. This is the one permitted {@code identity} &rarr; {@code
 * rbac} dependency direction: {@code identity.infrastructure} depends only on {@code
 * rbac.application.port.out.UserDirectoryPort}; {@code rbac} never imports {@code identity}
 * (03-design.md §5.1/§7.4, ArchUnit-enforced).
 */
@Component
public class JpaUserDirectoryAdapter implements UserDirectoryPort {

  private final JpaUserRepository userRepository;

  public JpaUserDirectoryAdapter(JpaUserRepository userRepository) {
    this.userRepository = userRepository;
  }

  @Override
  public Optional<UUID> findTenantId(UUID userId) {
    return userRepository.findById(userId).map(User::getTenantId);
  }

  @Override
  public Optional<DirectoryUser> findUser(UUID userId) {
    return userRepository
        .findById(userId)
        .map(user -> new DirectoryUser(user.getTenantId(), user.getStatus() == UserStatus.ACTIVE));
  }

  @Override
  public Map<UUID, DirectoryUserStatus> lockUserStatuses(UUID tenantId, Collection<UUID> userIds) {
    List<byte[]> idBytes = userIds.stream().map(JpaUserDirectoryAdapter::toBytes).toList();
    Map<UUID, DirectoryUserStatus> statuses = new HashMap<>();
    for (JpaUserRepository.UserStatusRow row :
        userRepository.lockStatusesByIds(idBytes, toBytes(tenantId))) {
      // Through identity's own enum first, so an unknown status fails loudly here.
      statuses.put(
          toUuid(row.getId()),
          DirectoryUserStatus.valueOf(UserStatus.valueOf(row.getStatus()).name()));
    }
    return statuses;
  }

  private static byte[] toBytes(UUID uuid) {
    return ByteBuffer.allocate(16)
        .putLong(uuid.getMostSignificantBits())
        .putLong(uuid.getLeastSignificantBits())
        .array();
  }

  private static UUID toUuid(byte[] bytes) {
    ByteBuffer buffer = ByteBuffer.wrap(bytes);
    return new UUID(buffer.getLong(), buffer.getLong());
  }
}
