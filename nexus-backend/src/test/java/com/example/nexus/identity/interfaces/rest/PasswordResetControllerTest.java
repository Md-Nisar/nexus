package com.example.nexus.identity.interfaces.rest;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.example.nexus.common.domain.RequestContext;
import com.example.nexus.common.web.GlobalExceptionHandler;
import com.example.nexus.identity.application.ForgotPasswordUseCase;
import com.example.nexus.identity.application.ResetPasswordUseCase;
import com.example.nexus.identity.interfaces.rest.dto.ForgotPasswordRequest;
import com.example.nexus.identity.interfaces.rest.dto.ResetPasswordRequest;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import jakarta.servlet.http.HttpServletRequest;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

@ExtendWith(MockitoExtension.class)
class PasswordResetControllerTest {

  @Mock private ForgotPasswordUseCase forgotPasswordUseCase;
  @Mock private ResetPasswordUseCase resetPasswordUseCase;
  @Mock private HttpServletRequest httpRequest;

  private static final UUID DEFAULT_TENANT = UUID.fromString("00000000-0000-0000-0000-000000000001");
  private static final String RAW_TOKEN = "a".repeat(64);

  private PasswordResetController controller;
  private MockMvc mockMvc;

  @BeforeEach
  void setUp() {
    forgotPasswordUseCase = mock(ForgotPasswordUseCase.class);
    resetPasswordUseCase = mock(ResetPasswordUseCase.class);
    controller = new PasswordResetController(forgotPasswordUseCase, resetPasswordUseCase, DEFAULT_TENANT);
    mockMvc = MockMvcBuilders.standaloneSetup(controller)
        .setControllerAdvice(new GlobalExceptionHandler(new SimpleMeterRegistry()))
        .build();
  }

  // --- Direct controller delegation tests (email normalisation, delegation) ---

  @Test
  void forgotPassword_delegates_to_use_case_with_normalized_email() {
    var request = new ForgotPasswordRequest("  USER@Example.COM  ");

    var response = controller.forgotPassword(request, httpRequest);

    verify(forgotPasswordUseCase).execute(
        eq(DEFAULT_TENANT), eq("user@example.com"), any(RequestContext.class));
    assertThat(response.message()).isNotBlank();
  }

  @Test
  void should_captureUserAgentHeader_when_forgotPasswordRequestIncludesUserAgent() {
    when(httpRequest.getHeader("User-Agent")).thenReturn("Mozilla/5.0 TestAgent");
    var request = new ForgotPasswordRequest("user@example.com");

    controller.forgotPassword(request, httpRequest);

    ArgumentCaptor<RequestContext> captor = ArgumentCaptor.forClass(RequestContext.class);
    verify(forgotPasswordUseCase).execute(
        eq(DEFAULT_TENANT), eq("user@example.com"), captor.capture());
    assertThat(captor.getValue().userAgent()).isEqualTo("Mozilla/5.0 TestAgent");
  }

  @Test
  void should_captureNullUserAgent_when_forgotPasswordRequestOmitsUserAgentHeader() {
    when(httpRequest.getHeader("User-Agent")).thenReturn(null);
    var request = new ForgotPasswordRequest("user@example.com");

    controller.forgotPassword(request, httpRequest);

    ArgumentCaptor<RequestContext> captor = ArgumentCaptor.forClass(RequestContext.class);
    verify(forgotPasswordUseCase).execute(
        eq(DEFAULT_TENANT), eq("user@example.com"), captor.capture());
    assertThat(captor.getValue().userAgent()).isNull();
  }

  @Test
  void resetPassword_delegates_to_use_case_with_token_and_password() {
    var request = new ResetPasswordRequest(RAW_TOKEN, "MyStr0ngP@ss!");

    var response = controller.resetPassword(request, httpRequest);

    verify(resetPasswordUseCase).execute(
        eq(RAW_TOKEN), eq("MyStr0ngP@ss!"), any(RequestContext.class));
    assertThat(response.message()).isNotBlank();
  }

  // --- HTTP boundary tests via MockMvc (verifies @Valid, status codes, error shape) ---

  @Test
  void forgotPassword_validEmail_returns202() throws Exception {
    mockMvc.perform(post("/api/v1/auth/password/forgot")
            .contentType(MediaType.APPLICATION_JSON)
            .content("{\"email\":\"user@example.com\"}"))
        .andExpect(status().isAccepted())
        .andExpect(jsonPath("$.message").isNotEmpty());
  }

  @Test
  void forgotPassword_blankEmail_returns400WithValidationCode() throws Exception {
    mockMvc.perform(post("/api/v1/auth/password/forgot")
            .contentType(MediaType.APPLICATION_JSON)
            .content("{\"email\":\"\"}"))
        .andExpect(status().isBadRequest())
        .andExpect(jsonPath("$.code").value("VALIDATION_FAILED"));
  }

  @Test
  void forgotPassword_malformedEmail_returns400WithValidationCode() throws Exception {
    mockMvc.perform(post("/api/v1/auth/password/forgot")
            .contentType(MediaType.APPLICATION_JSON)
            .content("{\"email\":\"not-an-email\"}"))
        .andExpect(status().isBadRequest())
        .andExpect(jsonPath("$.code").value("VALIDATION_FAILED"));
  }

  @Test
  void resetPassword_blankToken_returns400() throws Exception {
    mockMvc.perform(post("/api/v1/auth/password/reset")
            .contentType(MediaType.APPLICATION_JSON)
            .content("{\"token\":\"\",\"newPassword\":\"ValidP@ss12!\"}"))
        .andExpect(status().isBadRequest())
        .andExpect(jsonPath("$.code").value("VALIDATION_FAILED"));
  }

  @Test
  void resetPassword_validRequest_returns200() throws Exception {
    mockMvc.perform(post("/api/v1/auth/password/reset")
            .contentType(MediaType.APPLICATION_JSON)
            .content("{\"token\":\"" + RAW_TOKEN + "\",\"newPassword\":\"ValidP@ss12!\"}"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.message").isNotEmpty());
  }
}
