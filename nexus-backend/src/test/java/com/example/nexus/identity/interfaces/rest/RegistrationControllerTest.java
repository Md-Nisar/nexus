package com.example.nexus.identity.interfaces.rest;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;

import com.example.nexus.common.domain.RequestContext;
import com.example.nexus.identity.application.RegisterUserUseCase;
import com.example.nexus.identity.application.ResendVerificationUseCase;
import com.example.nexus.identity.application.VerifyEmailUseCase;
import com.example.nexus.identity.interfaces.rest.dto.RegisterRequest;
import com.example.nexus.identity.interfaces.rest.dto.RegisterResponse;
import com.example.nexus.identity.interfaces.rest.dto.ResendVerificationRequest;
import com.example.nexus.identity.interfaces.rest.dto.VerifyEmailRequest;
import jakarta.servlet.http.HttpServletRequest;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

/**
 * Unit tests for {@link RegistrationController}. Integration-level HTTP contract
 * verification (status codes, validation, security) is covered in RegistrationControllerIT.
 */
@ExtendWith(MockitoExtension.class)
class RegistrationControllerTest {

  @Mock private RegisterUserUseCase registerUseCase;
  @Mock private VerifyEmailUseCase verifyEmailUseCase;
  @Mock private ResendVerificationUseCase resendVerificationUseCase;
  @Mock private HttpServletRequest httpRequest;

  private static final UUID DEFAULT_TENANT = UUID.fromString("00000000-0000-0000-0000-000000000001");

  private RegistrationController controller;

  @BeforeEach
  void setUp() {
    controller = new RegistrationController(
        registerUseCase, verifyEmailUseCase, resendVerificationUseCase, DEFAULT_TENANT);
  }

  @Test
  void register_delegates_to_use_case_with_normalized_email() {
    var request = new RegisterRequest("  USER@Example.COM  ", "pass", true);

    RegisterResponse response = controller.register(request, httpRequest);

    verify(registerUseCase).register(
        eq(DEFAULT_TENANT), eq("user@example.com"), eq("pass"), any(RequestContext.class));
    assertThat(response.message()).isNotBlank();
  }

  @Test
  void verifyEmail_delegates_to_use_case() {
    var token = "a".repeat(64);
    var request = new VerifyEmailRequest(token);

    var response = controller.verifyEmail(request, httpRequest);

    verify(verifyEmailUseCase).verify(eq(token), any(RequestContext.class));
    assertThat(response.message()).isNotBlank();
  }

  @Test
  void resendVerification_delegates_to_use_case_with_normalized_email() {
    var request = new ResendVerificationRequest("  USER@Example.COM  ");

    var response = controller.resendVerification(request, httpRequest);

    verify(resendVerificationUseCase).resend(
        eq(DEFAULT_TENANT), eq("user@example.com"), any(RequestContext.class));
    assertThat(response.message()).isNotBlank();
  }
}
