package com.example.nexus.identity.infrastructure.persistence;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.example.nexus.TestcontainersConfiguration;
import com.example.nexus.identity.application.EmailBlindIndexService;
import com.example.nexus.identity.domain.EmailCipher;
import com.example.nexus.identity.domain.User;
import com.example.nexus.identity.domain.UuidGenerator;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.transaction.annotation.Transactional;

@SpringBootTest
@Import(TestcontainersConfiguration.class)
@Transactional
class UserUniquenessIT {

  @Autowired private JpaUserRepository userRepository;
  @Autowired private EmailBlindIndexService blindIndexService;
  @Autowired private UuidGenerator uuidGenerator;

  @Test
  void should_saveUser_when_emailHmacIsUniquePerTenant() {
    UUID tenantId = uuidGenerator.newId();
    String email = "alice@example.com";
    String hmac = blindIndexService.blindIndex(email);

    User user = new User(uuidGenerator.newId(), tenantId, new EmailCipher(email), hmac);
    User saved = userRepository.save(user);
    userRepository.flush();

    Optional<User> found = userRepository.findByTenantIdAndEmailHmac(tenantId, hmac);
    assertThat(found).isPresent();
    assertThat(found.get().getId()).isEqualTo(saved.getId());
  }

  @Test
  void should_rejectDuplicate_when_sameEmailSameTenant() {
    UUID tenantId = uuidGenerator.newId();
    String email = "bob@example.com";
    String hmac = blindIndexService.blindIndex(email);

    User first = new User(uuidGenerator.newId(), tenantId, new EmailCipher(email), hmac);
    userRepository.saveAndFlush(first);

    User duplicate = new User(uuidGenerator.newId(), tenantId, new EmailCipher(email), hmac);

    assertThatThrownBy(() -> userRepository.saveAndFlush(duplicate))
        .isInstanceOf(DataIntegrityViolationException.class);
  }

  @Test
  void should_allowSameEmail_when_differentTenants() {
    UUID tenant1 = uuidGenerator.newId();
    UUID tenant2 = uuidGenerator.newId();
    String email = "carol@example.com";
    String hmac = blindIndexService.blindIndex(email);

    User u1 = new User(uuidGenerator.newId(), tenant1, new EmailCipher(email), hmac);
    User u2 = new User(uuidGenerator.newId(), tenant2, new EmailCipher(email), hmac);

    userRepository.saveAndFlush(u1);
    userRepository.saveAndFlush(u2); // must not throw

    assertThat(userRepository.findByTenantIdAndEmailHmac(tenant1, hmac)).isPresent();
    assertThat(userRepository.findByTenantIdAndEmailHmac(tenant2, hmac)).isPresent();
  }

  @Test
  void should_normaliseEmail_when_lookingUpByHmac() {
    UUID tenantId = uuidGenerator.newId();
    String storedEmail = "dave@example.com";
    String hmac = blindIndexService.blindIndex(storedEmail);

    User user = new User(uuidGenerator.newId(), tenantId, new EmailCipher(storedEmail), hmac);
    userRepository.saveAndFlush(user);

    // Lookup with differently-cased email must produce the same HMAC and find the user
    String lookedUpHmac = blindIndexService.blindIndex("  DAVE@EXAMPLE.COM  ");
    assertThat(lookedUpHmac).isEqualTo(hmac);
    assertThat(userRepository.findByTenantIdAndEmailHmac(tenantId, lookedUpHmac)).isPresent();
  }
}
