package com.example.nexus.identity.interfaces.rest;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.example.nexus.common.domain.AuthenticationException;
import com.example.nexus.common.domain.RequestContext;
import com.example.nexus.common.web.GlobalExceptionHandler;
import com.example.nexus.identity.application.service.LoginUseCase;
import com.example.nexus.identity.application.service.LogoutUseCase;
import com.example.nexus.identity.application.service.RefreshTokenUseCase;
import com.example.nexus.identity.domain.LoginResult;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

@Tag("UnitTest")
class LoginControllerTest {

  private LoginUseCase loginUseCase;
  private RefreshTokenUseCase refreshTokenUseCase;
  private LogoutUseCase logoutUseCase;
  private MockMvc mockMvc;

  private static final UUID TENANT_ID = UUID.fromString("00000000-0000-7000-8000-000000000001");
  private static final String RAW_REFRESH = "a".repeat(64);
  private static final LoginResult LOGIN_RESULT =
      new LoginResult("access.jwt.token", 900L, "user-uuid-1", RAW_REFRESH);

  @BeforeEach
  void setUp() {
    loginUseCase = mock(LoginUseCase.class);
    refreshTokenUseCase = mock(RefreshTokenUseCase.class);
    logoutUseCase = mock(LogoutUseCase.class);

    LoginController controller = new LoginController(
        loginUseCase, refreshTokenUseCase, logoutUseCase, TENANT_ID);
    mockMvc = MockMvcBuilders.standaloneSetup(controller)
        .setControllerAdvice(new GlobalExceptionHandler(new SimpleMeterRegistry()))
        .build();
  }

  @Test
  void login_happyPath_returns200_withAccessToken_andSetCookie() throws Exception {
    when(loginUseCase.execute(eq(TENANT_ID), eq("user@example.com"), eq("secret"), any(RequestContext.class)))
        .thenReturn(LOGIN_RESULT);

    MvcResult result = mockMvc.perform(post("/api/v1/auth/login")
            .contentType(MediaType.APPLICATION_JSON)
            .content("{\"email\":\"user@example.com\",\"password\":\"secret\"}"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.accessToken").value("access.jwt.token"))
        .andExpect(jsonPath("$.tokenType").value("Bearer"))
        .andExpect(jsonPath("$.expiresIn").value(900))
        .andExpect(jsonPath("$.userId").value("user-uuid-1"))
        .andExpect(header().string(HttpHeaders.SET_COOKIE, containsString("refresh_token=")))
        .andExpect(header().string(HttpHeaders.SET_COOKIE, containsString("HttpOnly")))
        .andExpect(header().string(HttpHeaders.SET_COOKIE, containsString("SameSite=Strict")))
        .andExpect(header().string(HttpHeaders.SET_COOKIE, containsString("Path=/api/v1/auth")))
        .andReturn();

    // raw refresh token must NOT appear in the response body
    assertThat(result.getResponse().getContentAsString()).doesNotContain(RAW_REFRESH);
  }

  @Test
  void should_captureUserAgentHeader_when_loginRequestIncludesUserAgent() throws Exception {
    when(loginUseCase.execute(eq(TENANT_ID), eq("user@example.com"), eq("secret"), any(RequestContext.class)))
        .thenReturn(LOGIN_RESULT);

    mockMvc.perform(post("/api/v1/auth/login")
            .header("User-Agent", "Mozilla/5.0 TestAgent")
            .contentType(MediaType.APPLICATION_JSON)
            .content("{\"email\":\"user@example.com\",\"password\":\"secret\"}"))
        .andExpect(status().isOk());

    ArgumentCaptor<RequestContext> captor = ArgumentCaptor.forClass(RequestContext.class);
    verify(loginUseCase).execute(eq(TENANT_ID), eq("user@example.com"), eq("secret"), captor.capture());
    assertThat(captor.getValue().userAgent()).isEqualTo("Mozilla/5.0 TestAgent");
  }

  @Test
  void should_captureNullUserAgent_when_loginRequestOmitsUserAgentHeader() throws Exception {
    when(loginUseCase.execute(eq(TENANT_ID), eq("user@example.com"), eq("secret"), any(RequestContext.class)))
        .thenReturn(LOGIN_RESULT);

    mockMvc.perform(post("/api/v1/auth/login")
            .contentType(MediaType.APPLICATION_JSON)
            .content("{\"email\":\"user@example.com\",\"password\":\"secret\"}"))
        .andExpect(status().isOk());

    ArgumentCaptor<RequestContext> captor = ArgumentCaptor.forClass(RequestContext.class);
    verify(loginUseCase).execute(eq(TENANT_ID), eq("user@example.com"), eq("secret"), captor.capture());
    assertThat(captor.getValue().userAgent()).isNull();
  }

  @Test
  void login_validationFail_emailMissing_returns400() throws Exception {
    mockMvc.perform(post("/api/v1/auth/login")
            .contentType(MediaType.APPLICATION_JSON)
            .content("{\"email\":\"\",\"password\":\"secret\"}"))
        .andExpect(status().isBadRequest());
  }

  @Test
  void refresh_happyPath_returns200_withRotatedCookie() throws Exception {
    when(refreshTokenUseCase.execute(eq(RAW_REFRESH), any()))
        .thenReturn(new LoginResult("new.access.jwt", 900L, "user-uuid-1", "new-raw-refresh"));

    mockMvc.perform(post("/api/v1/auth/refresh")
            .cookie(new jakarta.servlet.http.Cookie("refresh_token", RAW_REFRESH)))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.accessToken").value("new.access.jwt"))
        .andExpect(header().string(HttpHeaders.SET_COOKIE, containsString("refresh_token=")))
        .andExpect(header().string(HttpHeaders.SET_COOKIE, containsString("HttpOnly")));
  }

  @Test
  void refresh_missingCookie_returns401() throws Exception {
    mockMvc.perform(post("/api/v1/auth/refresh"))
        .andExpect(status().isUnauthorized());
  }

  @Test
  void logout_returns204_withClearedCookie_andRevokesTokens() throws Exception {
    mockMvc.perform(post("/api/v1/auth/logout"))
        .andExpect(status().isNoContent())
        .andExpect(header().string(HttpHeaders.SET_COOKIE, containsString("Max-Age=0")))
        .andExpect(header().string(HttpHeaders.SET_COOKIE, containsString("refresh_token=")));

    // No authenticated user in MockMvc → userId is null; no cookie → rawRefreshToken is null
    verify(logoutUseCase).execute(isNull(), isNull(), any());
  }
}
