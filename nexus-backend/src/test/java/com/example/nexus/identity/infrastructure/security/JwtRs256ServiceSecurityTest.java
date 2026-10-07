package com.example.nexus.identity.infrastructure.security;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.example.nexus.common.domain.AuthenticationException;
import com.example.nexus.identity.domain.AccessTokenResult;
import com.example.nexus.identity.domain.JwtClaims;
import com.example.nexus.identity.domain.User;
import com.example.nexus.identity.domain.UserStatus;
import com.example.nexus.rbac.application.PermissionFreshnessService;
import com.example.nexus.rbac.application.RoleResolutionService;
import com.example.nexus.rbac.domain.ResolvedPermissions;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.SignatureAlgorithm;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.Locale;
import java.util.UUID;
import javax.crypto.spec.SecretKeySpec;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;
import org.springframework.core.env.Environment;

/**
 * Security-focused unit tests for {@link JwtRs256Service} (IMPL-13 / T-3.x).
 *
 * <p>Covers attack vectors not addressed by the basic round-trip tests in
 * {@link JwtRs256ServiceTest}: alg=none injection, HS256 key-confusion, foreign-key forgery,
 * payload tampering, and clock-skew boundary verification.
 *
 * <p>No Spring context — pure JUnit 5 + JJWT.
 */
@Tag("UnitTest")
class JwtRs256ServiceSecurityTest {

  private static RsaKeyConfig rsaKeyConfig;

  private final SimpleMeterRegistry meterRegistry = new SimpleMeterRegistry();

  @BeforeAll
  static void setUpKeyConfig() throws Exception {
    Environment devEnv = mock(Environment.class);
    when(devEnv.getActiveProfiles()).thenReturn(new String[]{"dev"});
    rsaKeyConfig = new RsaKeyConfig(devEnv);
    rsaKeyConfig.init();
  }

  private JwtRs256Service service(Clock clock) {
    RoleResolutionService roleResolutionService = mock(RoleResolutionService.class);
    when(roleResolutionService.resolve(
            org.mockito.ArgumentMatchers.any(), org.mockito.ArgumentMatchers.any()))
        .thenReturn(new ResolvedPermissions(List.of("USER"), List.of("read:only")));
    return new JwtRs256Service(
        rsaKeyConfig, UUID::randomUUID, clock, 900L, roleResolutionService,
        mock(PermissionFreshnessService.class), meterRegistry);
  }

  private User activeUser() {
    User user = mock(User.class);
    when(user.getId()).thenReturn(UUID.randomUUID());
    when(user.getTenantId()).thenReturn(UUID.randomUUID());
    when(user.getStatus()).thenReturn(UserStatus.ACTIVE);
    when(user.getTokenVersion()).thenReturn(0);
    return user;
  }

  // -----------------------------------------------------------------------
  // T-3.1: alg=none injection
  // -----------------------------------------------------------------------

  /**
   * T-3.1: A token crafted with {@code "alg":"none"} and an empty signature must be rejected.
   * JJWT's {@code parseSignedClaims} rejects unsigned JWTs outright; the service must surface
   * this as {@code AuthenticationException} with code {@code AUTH_003}.
   */
  @Test
  void should_rejectToken_when_algIsNone() {
    Base64.Encoder enc = Base64.getUrlEncoder().withoutPadding();

    String header = enc.encodeToString(
        "{\"alg\":\"none\",\"typ\":\"JWT\"}".getBytes(StandardCharsets.UTF_8));

    long now = Instant.now().getEpochSecond();
    String payloadJson = "{\"sub\":\"user-x\",\"tenant_id\":\"t-1\",\"roles\":[\"USER\"],"
        + "\"iat\":" + now + ",\"exp\":" + (now + 900) + ",\"jti\":\"jti-none\","
        + "\"token_version\":0}";
    String payload = enc.encodeToString(payloadJson.getBytes(StandardCharsets.UTF_8));

    // "alg=none" token has an empty signature segment
    String noneJwt = header + "." + payload + ".";

    JwtRs256Service svc = service(Clock.systemUTC());

    assertThatThrownBy(() -> svc.verify(noneJwt))
        .isInstanceOf(AuthenticationException.class)
        .satisfies(e -> assertThat(((AuthenticationException) e).code()).isEqualTo("AUTH_003"));
  }

  // -----------------------------------------------------------------------
  // T-3.2: HS256 key-confusion attack
  // -----------------------------------------------------------------------

  /**
   * T-3.2: An attacker who knows the public key signs a token with HS256 using the raw
   * public-key bytes as the HMAC secret. The service must reject this token because the
   * explicit algorithm assertion ({@code alg != "RS256"}) fires before any payload is trusted.
   */
  @Test
  void should_rejectToken_when_hs256ConfusionAttack() {
    byte[] publicKeyBytes = rsaKeyConfig.getKeyPair().getPublic().getEncoded();
    SecretKeySpec hmacKey = new SecretKeySpec(publicKeyBytes, "HmacSHA256");

    long now = Instant.now().getEpochSecond();
    String confusionJwt = Jwts.builder()
        .subject("attacker")
        .claim("tenant_id", "t-1")
        .claim("roles", List.of("ADMIN"))
        .claim("token_version", 0)
        .issuedAt(new Date(now * 1000))
        .expiration(new Date((now + 900) * 1000))
        .id(UUID.randomUUID().toString())
        .signWith(hmacKey, Jwts.SIG.HS256)
        .compact();

    JwtRs256Service svc = service(Clock.systemUTC());

    assertThatThrownBy(() -> svc.verify(confusionJwt))
        .isInstanceOf(AuthenticationException.class)
        .satisfies(e -> assertThat(((AuthenticationException) e).code()).isEqualTo("AUTH_003"));
  }

  // -----------------------------------------------------------------------
  // T-3.3: Token signed by a foreign RSA key
  // -----------------------------------------------------------------------

  /**
   * T-3.3: A token issued by a completely different RSA key pair must be rejected with
   * {@code AUTH_003}. The service's public key will not validate the foreign signature.
   */
  @Test
  void should_rejectToken_when_signedByForeignRsaKey() throws Exception {
    KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
    kpg.initialize(2048);
    KeyPair foreignPair = kpg.generateKeyPair();

    long now = Instant.now().getEpochSecond();
    String foreignJwt = Jwts.builder()
        .header()
            .add("kid", "foreignkid")
            .add("typ", "JWT")
            .and()
        .subject(UUID.randomUUID().toString())
        .claim("tenant_id", UUID.randomUUID().toString())
        .claim("roles", List.of("USER"))
        .claim("email_verified", true)
        .claim("token_version", 0)
        .issuedAt(new Date(now * 1000))
        .expiration(new Date((now + 900) * 1000))
        .id(UUID.randomUUID().toString())
        .signWith(foreignPair.getPrivate(), Jwts.SIG.RS256)
        .compact();

    JwtRs256Service svc = service(Clock.systemUTC());

    assertThatThrownBy(() -> svc.verify(foreignJwt))
        .isInstanceOf(AuthenticationException.class)
        .satisfies(e -> assertThat(((AuthenticationException) e).code()).isEqualTo("AUTH_003"));
  }

  // -----------------------------------------------------------------------
  // T-3.4: Payload tampering — tenant_id
  // -----------------------------------------------------------------------

  /**
   * T-3.4a: Replacing the {@code tenant_id} claim in the payload while keeping the original
   * RS256 signature must invalidate the token.
   */
  @Test
  void should_rejectToken_when_tenantIdTampered() throws Exception {
    Instant issuedAt = Instant.parse("2026-06-01T00:00:00Z");
    JwtRs256Service svc = service(Clock.fixed(issuedAt, ZoneOffset.UTC));
    User user = activeUser();

    AccessTokenResult result = svc.issue(user);
    String tamperedJwt = tamperPayload(result.token(), "\"tenant_id\":\"" + user.getTenantId() + "\"",
        "\"tenant_id\":\"00000000-0000-0000-0000-000000000099\"");

    assertThatThrownBy(() -> svc.verify(tamperedJwt))
        .isInstanceOf(AuthenticationException.class)
        .satisfies(e -> assertThat(((AuthenticationException) e).code()).isEqualTo("AUTH_003"));
  }

  // -----------------------------------------------------------------------
  // T-3.4: Payload tampering — roles
  // -----------------------------------------------------------------------

  /**
   * T-3.4b: Replacing the {@code roles} claim to escalate privileges while keeping the original
   * signature must invalidate the token.
   */
  @Test
  void should_rejectToken_when_rolesTampered() throws Exception {
    Instant issuedAt = Instant.parse("2026-06-01T00:00:00Z");
    JwtRs256Service svc = service(Clock.fixed(issuedAt, ZoneOffset.UTC));
    User user = activeUser();

    AccessTokenResult result = svc.issue(user);
    String tamperedJwt = tamperPayload(result.token(),
        "[\"USER\"]", "[\"ADMIN\"]");

    assertThatThrownBy(() -> svc.verify(tamperedJwt))
        .isInstanceOf(AuthenticationException.class)
        .satisfies(e -> assertThat(((AuthenticationException) e).code()).isEqualTo("AUTH_003"));
  }

  // -----------------------------------------------------------------------
  // T-3.5: Clock-skew boundary — verifier slightly behind issuer
  // -----------------------------------------------------------------------

  /**
   * T-3.5: A token issued 25 seconds ago (i.e. the issuer's clock was 25 seconds behind the
   * verifier) must still be accepted, because the parser's 30-second {@code clockSkewSeconds}
   * window covers the drift. Also acts as a smoke-test confirming that the full issue → verify
   * round-trip succeeds for a valid RS256 token.
   *
   * <p>JJWT's parser validates {@code exp} and {@code iat} against the JVM's real system clock,
   * not against the {@link java.time.Clock} injected into the service (which is only used by
   * {@link JwtRs256Service#issue}). Therefore the token's {@code exp} must be in the future
   * from the JVM's perspective. We set {@code issueTime = Instant.now() - 25s} so the token
   * was "issued 25 seconds ago": {@code iat} is 25s in the past, {@code exp} is {@code iat + 900s}
   * (~875s from now), which is well within the validity window and demonstrates that the
   * 30-second skew allowance does not interfere with normal acceptance.
   */
  @Test
  void should_acceptToken_when_verifierClock25sBehindIssuer() {
    // Issue 25 seconds in the past so iat < now and exp is still ~875s away.
    Instant issueTime = Instant.now().minusSeconds(25);
    JwtRs256Service issuer = service(Clock.fixed(issueTime, ZoneOffset.UTC));

    // Verifier uses the real system clock (JJWT parser always does), but a fixed service
    // clock matching issue time is sufficient — verify() never reads this.clock.
    JwtRs256Service verifier = service(Clock.fixed(issueTime, ZoneOffset.UTC));

    User user = activeUser();
    AccessTokenResult result = issuer.issue(user);
    JwtClaims claims = verifier.verify(result.token());

    assertThat(claims.sub()).isEqualTo(user.getId().toString());
    assertThat(claims.roles()).containsExactly("USER");
  }

  // -----------------------------------------------------------------------
  // US-018 T-005 / T-S10 (RC-40.1): sub must be a canonical UUID — 401, never a downstream 500
  // -----------------------------------------------------------------------

  @Test
  void should_rejectWithSubReason_when_subIsNotAUuid() {
    String token = signedToken("not-a-uuid-subject", rsaKeyConfig.getKeyPair().getPrivate(),
        Jwts.SIG.RS256);

    assertRejectedWithReason(token, "sub");
  }

  @Test
  void should_rejectWithSubReason_when_subIsNonCanonicalUuid() {
    // UUID.fromString("1-1-1-1-1") succeeds; a lenient check would let this alias a real user id.
    String token = signedToken("1-1-1-1-1", rsaKeyConfig.getKeyPair().getPrivate(),
        Jwts.SIG.RS256);

    assertRejectedWithReason(token, "sub");
  }

  @Test
  void should_rejectWithSubReason_when_subIsUppercaseUuid() {
    // issue() only ever mints UUID.toString() (lowercase); any other spelling is not ours.
    String token = signedToken(UUID.randomUUID().toString().toUpperCase(Locale.ROOT),
        rsaKeyConfig.getKeyPair().getPrivate(), Jwts.SIG.RS256);

    assertRejectedWithReason(token, "sub");
  }

  // -----------------------------------------------------------------------
  // US-018 T-005: cryptographic rejections are tagged reason=signature
  // -----------------------------------------------------------------------

  @Test
  void should_rejectWithSignatureReason_when_signedByForeignRsaKey() throws Exception {
    KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
    kpg.initialize(2048);
    String token = signedToken(UUID.randomUUID().toString(),
        kpg.generateKeyPair().getPrivate(), Jwts.SIG.RS256);

    assertRejectedWithReason(token, "signature");
  }

  /**
   * T-3.2 at unit level: RS384 under the app's own key passes JJWT's signature check, so only the
   * explicit {@code alg} assertion rejects it — and that rejection must still be counted.
   */
  @Test
  void should_rejectWithSignatureReason_when_algorithmIsRs384() {
    String token = signedToken(UUID.randomUUID().toString(),
        rsaKeyConfig.getKeyPair().getPrivate(), Jwts.SIG.RS384);

    assertRejectedWithReason(token, "signature");
  }

  @Test
  void should_rejectWithSignatureReason_when_algIsNone() {
    Base64.Encoder enc = Base64.getUrlEncoder().withoutPadding();
    String header = enc.encodeToString(
        "{\"alg\":\"none\",\"typ\":\"JWT\"}".getBytes(StandardCharsets.UTF_8));
    String payload = enc.encodeToString(
        ("{\"sub\":\"" + UUID.randomUUID() + "\"}").getBytes(StandardCharsets.UTF_8));

    assertRejectedWithReason(header + "." + payload + ".", "signature");
  }

  /** Rejections log at DEBUG only (M7 rollout log-flood risk) and never echo token material. */
  @Test
  void should_logRejectionAtDebugOnly_when_tokenRejected() {
    String subject = "not-a-uuid-subject";
    String token = signedToken(subject, rsaKeyConfig.getKeyPair().getPrivate(), Jwts.SIG.RS256);
    Logger logger = (Logger) LoggerFactory.getLogger(JwtRs256Service.class);
    Level originalLevel = logger.getLevel();
    ListAppender<ILoggingEvent> appender = new ListAppender<>();
    appender.start();
    logger.addAppender(appender);
    logger.setLevel(Level.TRACE);
    try {
      JwtRs256Service svc = service(Clock.systemUTC());
      assertThatThrownBy(() -> svc.verify(token)).isInstanceOf(AuthenticationException.class);
    } finally {
      logger.detachAppender(appender);
      logger.setLevel(originalLevel);
      appender.stop();
    }

    assertThat(appender.list)
        .isNotEmpty()
        .allSatisfy(event -> {
          assertThat(event.getLevel()).isEqualTo(Level.DEBUG);
          assertThat(event.getFormattedMessage()).doesNotContain(token).doesNotContain(subject);
          assertThat(String.valueOf(event.getKeyValuePairs()))
              .doesNotContain(token)
              .doesNotContain(subject);
        });
  }

  // -----------------------------------------------------------------------
  // Helpers
  // -----------------------------------------------------------------------

  /** A token carrying every valid v2 claim, with the given {@code sub}, key and algorithm. */
  private static String signedToken(
      String subject, PrivateKey signingKey, SignatureAlgorithm algorithm) {
    Instant now = Instant.now();
    return Jwts.builder()
        .subject(subject)
        .claim("tenant_id", UUID.randomUUID().toString())
        .claim("email_verified", true)
        .claim("roles", List.of("USER"))
        .claim("permissions", List.of("read:only"))
        .issuedAt(Date.from(now))
        .expiration(Date.from(now.plusSeconds(900)))
        .id(UUID.randomUUID().toString())
        .claim("token_version", 0)
        .claim("schema_version", JwtClaims.CURRENT_VERSION)
        .signWith(signingKey, algorithm)
        .compact();
  }

  /** The token is rejected with 401 AUTH_003, counted exactly once under {@code reason}. */
  private void assertRejectedWithReason(String token, String reason) {
    JwtRs256Service svc = service(Clock.systemUTC());

    assertThatThrownBy(() -> svc.verify(token))
        .isInstanceOf(AuthenticationException.class)
        .satisfies(e -> assertThat(((AuthenticationException) e).code()).isEqualTo("AUTH_003"));
    Counter counter =
        meterRegistry.find("nexus.auth.token_rejected").tag("reason", reason).counter();
    assertThat(counter).as("token_rejected{reason=%s}", reason).isNotNull();
    assertThat(counter.count()).isEqualTo(1.0);
  }

  /**
   * Replaces {@code oldFragment} with {@code newFragment} in the base64url-decoded payload
   * segment of a JWT, then reassembles the token with the original header and signature.
   * The resulting token has an invalid signature for the modified payload.
   */
  private static String tamperPayload(String jwt, String oldFragment, String newFragment) {
    String[] parts = jwt.split("\\.", -1);
    if (parts.length != 3) {
      throw new IllegalArgumentException("Expected 3-part JWT, got " + parts.length);
    }
    Base64.Decoder dec = Base64.getUrlDecoder();
    Base64.Encoder enc = Base64.getUrlEncoder().withoutPadding();

    String decodedPayload = new String(dec.decode(parts[1]), StandardCharsets.UTF_8);
    String tamperedPayload = decodedPayload.replace(oldFragment, newFragment);
    String reEncodedPayload = enc.encodeToString(tamperedPayload.getBytes(StandardCharsets.UTF_8));

    // Keep original header and signature — signature no longer matches modified payload
    return parts[0] + "." + reEncodedPayload + "." + parts[2];
  }
}
