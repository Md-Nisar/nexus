package com.example.nexus.identity.infrastructure.persistence;

import static org.assertj.core.api.Assertions.assertThat;

import com.example.nexus.TestcontainersConfiguration;
import com.example.nexus.common.domain.RequestContext;
import com.example.nexus.identity.application.EmailBlindIndexService;
import com.example.nexus.identity.application.RegisterUserUseCase;
import com.example.nexus.identity.application.port.out.AuthTokenPort;
import com.example.nexus.identity.application.port.out.UserRegistrationPort;
import com.example.nexus.identity.domain.AuthTokenType;
import com.example.nexus.identity.domain.User;
import com.example.nexus.identity.domain.UserStatus;
import java.time.Instant;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;

/**
 * Integration tests for {@link RegisterUserUseCase} exercising the full call chain
 * through persistence against a real MySQL container.
 */
@SpringBootTest
@Import(TestcontainersConfiguration.class)
class RegistrationIT {

  @Autowired private RegisterUserUseCase registerUserUseCase;
  @Autowired private UserRegistrationPort userRegistrationPort;
  @Autowired private EmailBlindIndexService emailBlindIndexService;
  @Autowired private AuthTokenPort authTokenPort;

  private static final UUID TENANT_ID =
      UUID.fromString("00000000-0000-7000-8000-000000000001");
  private static final String STRONG_PASS = "ValidPassphrase_99!"; // EXAMPLE

  @Test
  void register_newUser_createsPendingUserAndVerificationToken() {
    String email = "reg-new-" + UUID.randomUUID() + "@example.com";

    registerUserUseCase.register(TENANT_ID, email, STRONG_PASS, RequestContext.UNKNOWN);

    String hmac = emailBlindIndexService.blindIndex(email);
    User user = userRegistrationPort.findByTenantAndEmailHmac(TENANT_ID, hmac).orElseThrow();

    assertThat(user.getStatus()).isEqualTo(UserStatus.PENDING);
    assertThat(user.getEmailVerifiedAt()).isNull();

    int tokenCount = authTokenPort.countByUserIdAndTypeAndCreatedAtAfter(
        user.getId(), AuthTokenType.VERIFICATION, Instant.now().minusSeconds(3600));
    assertThat(tokenCount).isEqualTo(1);
  }

  @Test
  void register_duplicateEmail_silentlyAcknowledgesWithoutNewUser() {
    String email = "reg-dup-" + UUID.randomUUID() + "@example.com";

    registerUserUseCase.register(TENANT_ID, email, STRONG_PASS, RequestContext.UNKNOWN);
    registerUserUseCase.register(TENANT_ID, email, STRONG_PASS, RequestContext.UNKNOWN); // must not throw

    String hmac = emailBlindIndexService.blindIndex(email);
    User user = userRegistrationPort.findByTenantAndEmailHmac(TENANT_ID, hmac).orElseThrow();

    // Only one token from the original registration
    int tokenCount = authTokenPort.countByUserIdAndTypeAndCreatedAtAfter(
        user.getId(), AuthTokenType.VERIFICATION, Instant.now().minusSeconds(3600));
    assertThat(tokenCount).isEqualTo(1);
  }
}
