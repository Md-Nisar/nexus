package com.example.nexus.identity.infrastructure.persistence;

import com.example.nexus.identity.application.port.out.UserDirectoryQueryPort;
import com.example.nexus.identity.domain.DirectoryPage;
import com.example.nexus.identity.domain.DirectoryUserView;
import com.example.nexus.identity.domain.User;
import com.example.nexus.identity.domain.UserStatus;
import java.util.Collection;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

/**
 * {@link UserDirectoryQueryPort} over {@link JpaUserRepository} (US-019 B1, design §4.1). The
 * email is decrypted by {@link AttributeEncryptor} as the entity loads, so a tampered cipher fails
 * the whole read rather than returning a partial page. Only the five directory fields are mapped:
 * the blind index, password hash, counters and lock expiry never leave this class.
 *
 * <p>Every method is one read-only transaction that ends when it returns, so the caller holds no
 * connection while it writes its audit row (review R2-1, {@code UserDirectoryService}).
 *
 * <p>The only caller of the unscoped {@link JpaUserRepository#countByIdIn} (RC-61.2, ArchUnit).
 */
@Component
@Transactional(readOnly = true)
public class JpaUserDirectoryQueryAdapter implements UserDirectoryQueryPort {

  private static final Sort BY_ID = Sort.by("id");

  private final JpaUserRepository userRepository;

  public JpaUserDirectoryQueryAdapter(JpaUserRepository userRepository) {
    this.userRepository = userRepository;
  }

  @Override
  public DirectoryPage<DirectoryUserView> findPageByTenant(
      UUID tenantId, UserStatus status, int page, int size) {
    PageRequest request = PageRequest.of(page, size, BY_ID);
    Page<User> users =
        status == null
            ? userRepository.findByTenantId(tenantId, request)
            : userRepository.findByTenantIdAndStatus(tenantId, status, request);
    return new DirectoryPage<>(
        users.getContent().stream().map(JpaUserDirectoryQueryAdapter::toView).toList(),
        users.getTotalElements(),
        page,
        size);
  }

  @Override
  public List<DirectoryUserView> findByTenantAndIds(UUID tenantId, Collection<UUID> ids) {
    return userRepository.findByTenantIdAndIdIn(tenantId, ids, BY_ID).stream()
        .map(JpaUserDirectoryQueryAdapter::toView)
        .toList();
  }

  @Override
  public Optional<DirectoryUserView> findByTenantAndId(UUID tenantId, UUID userId) {
    return userRepository.findByTenantIdAndId(tenantId, userId).map(JpaUserDirectoryQueryAdapter::toView);
  }

  @Override
  public Optional<DirectoryUserView> findByTenantAndEmailHmac(UUID tenantId, String emailHmac) {
    return userRepository
        .findByTenantIdAndEmailHmac(tenantId, emailHmac)
        .map(JpaUserDirectoryQueryAdapter::toView);
  }

  @Override
  public boolean existsById(UUID userId) {
    return userRepository.existsById(userId);
  }

  @Override
  public long countByIdIn(Collection<UUID> ids) {
    return userRepository.countByIdIn(ids);
  }

  private static DirectoryUserView toView(User user) {
    return new DirectoryUserView(
        user.getId(),
        user.getEmailCipher().value(),
        user.getStatus(),
        user.getEmailVerifiedAt(),
        user.getCreatedAt());
  }
}
