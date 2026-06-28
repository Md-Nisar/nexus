package com.example.nexus.identity.application.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import com.example.nexus.identity.application.TokenHasher;
import com.example.nexus.identity.application.port.out.AuthEventPort;
import com.example.nexus.identity.application.port.out.RefreshTokenPort;
import com.example.nexus.identity.domain.AuthEvent;
import com.example.nexus.identity.domain.RefreshToken;
import com.example.nexus.identity.domain.UuidGenerator;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

class LogoutUseCaseTest {

  private RefreshTokenPort refreshTokenPort;
  private AuthEventPort authEventPort;
  private TokenHasher tokenHasher;
  private UuidGenerator uuidGenerator;

  private LogoutUseCase useCase;

  private static final Instant FIXED_INSTANT = Instant.parse("2026-06-29T10:00:00Z");
  private static final Clock FIXED_CLOCK = Clock.fixed(FIXED_INSTANT, ZoneOffset.UTC);
  private static final String CLIENT_IP = "203.0.113.7";

  @BeforeEach
  void setUp() {
    refreshTokenPort = mock(RefreshTokenPort.class);
    authEventPort = mock(AuthEventPort.class);
    tokenHasher = mock(TokenHasher.class);
    uuidGenerator = mock(UuidGenerator.class);

    when(uuidGenerator.newId()).thenReturn(UUID.randomUUID());

    useCase = new LogoutUseCase(
        refreshTokenPort, authEventPort, tokenHasher, uuidGenerator, FIXED_CLOCK);
  }

  @Test
  void bearer_path_revokes_by_userId_without_touching_cookie() {
    UUID userId = UUID.randomUUID();

    useCase.execute(userId, null, CLIENT_IP);

    verify(refreshTokenPort).revokeByUserId(userId, FIXED_INSTANT);
    verifyNoInteractions(tokenHasher);

    ArgumentCaptor<AuthEvent> captor = ArgumentCaptor.forClass(AuthEvent.class);
    verify(authEventPort, times(1)).record(captor.capture());
    AuthEvent event = captor.getValue();
    assertThat(event.getEventType()).isEqualTo("LOGOUT");
    assertThat(event.getOutcome()).isEqualTo("SUCCESS");
    assertThat(event.getUserId()).isEqualTo(userId);
    assertThat(event.getIpAddress()).isEqualTo(CLIENT_IP);
  }

  @Test
  void cookie_only_path_resolves_userId_then_revokes() {
    UUID resolvedUserId = UUID.randomUUID();
    String rawToken = "deadbeef";
    String tokenHash = "HASH";

    RefreshToken storedToken = new RefreshToken(
        UUID.randomUUID(), resolvedUserId, tokenHash, UUID.randomUUID(),
        FIXED_INSTANT.plusSeconds(3600));

    when(tokenHasher.hash(rawToken)).thenReturn(tokenHash);
    when(refreshTokenPort.findByTokenHash(tokenHash)).thenReturn(Optional.of(storedToken));

    useCase.execute(null, rawToken, CLIENT_IP);

    verify(tokenHasher).hash(rawToken);
    verify(refreshTokenPort).findByTokenHash(tokenHash);
    verify(refreshTokenPort).revokeByUserId(resolvedUserId, FIXED_INSTANT);

    ArgumentCaptor<AuthEvent> captor = ArgumentCaptor.forClass(AuthEvent.class);
    verify(authEventPort, times(1)).record(captor.capture());
    assertThat(captor.getValue().getUserId()).isEqualTo(resolvedUserId);
  }

  @Test
  void malformed_cookie_degrades_to_audit_only() {
    String rawToken = "not-hex";
    when(tokenHasher.hash(rawToken)).thenThrow(new IllegalArgumentException("bad hex"));

    useCase.execute(null, rawToken, CLIENT_IP);

    verify(refreshTokenPort, never()).revokeByUserId(any(), any());

    ArgumentCaptor<AuthEvent> captor = ArgumentCaptor.forClass(AuthEvent.class);
    verify(authEventPort, times(1)).record(captor.capture());
    AuthEvent event = captor.getValue();
    assertThat(event.getEventType()).isEqualTo("LOGOUT");
    assertThat(event.getOutcome()).isEqualTo("SUCCESS");
    assertThat(event.getUserId()).isNull();
  }

  @Test
  void unknown_cookie_degrades_to_audit_only() {
    String rawToken = "abcd1234";
    when(tokenHasher.hash(rawToken)).thenReturn("HASH");
    when(refreshTokenPort.findByTokenHash("HASH")).thenReturn(Optional.empty());

    useCase.execute(null, rawToken, CLIENT_IP);

    verify(refreshTokenPort, never()).revokeByUserId(any(), any());

    ArgumentCaptor<AuthEvent> captor = ArgumentCaptor.forClass(AuthEvent.class);
    verify(authEventPort, times(1)).record(captor.capture());
    assertThat(captor.getValue().getUserId()).isNull();
  }
}
