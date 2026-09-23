package com.example.nexus.identity.infrastructure.security;

import static org.assertj.core.api.Assertions.assertThat;

import com.example.nexus.TestcontainersConfiguration;
import com.example.nexus.identity.domain.JwtClaims;
import com.example.nexus.support.web.GuardedTestControllerConfig;
import io.jsonwebtoken.Jwts;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.context.annotation.Import;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.web.client.DefaultResponseErrorHandler;
import org.springframework.web.client.RestTemplate;

/**
 * US-011/T-3.2 regression: {@link JwtRs256Service#verify(String)}'s explicit {@code alg !=
 * "RS256"} assertion is the only thing rejecting a token that is otherwise cryptographically
 * valid under the app's own RSA key but signed with a different RSA-family algorithm (RS384).
 *
 * <p>JJWT's {@code Jwts.parser().verifyWith(publicKey)} accepts any algorithm compatible with the
 * supplied key — not RS256 specifically — so an RS384-signed token verifies successfully at the
 * JJWT layer before ever reaching the service's manual {@code alg} check. This is a distinct
 * attack surface from the HS256 key-confusion case covered by {@code
 * JwtRs256ServiceSecurityTest#should_rejectToken_when_hs256ConfusionAttack}: that HS256 token is
 * rejected earlier, by JJWT's own signature verification (RSA public key cannot verify an HMAC
 * signature), so the manual {@code alg} check is never reached and its "algorithm mismatch" branch
 * was previously exercised 0% by the suite.
 *
 * <p>End-to-end through the real embedded server and the app's actual {@link RsaKeyConfig}-issued
 * key pair (mirrors {@code CrossTenantPermissionIT}'s harness), rather than a unit test against a
 * standalone {@code JwtRs256Service}, so the forged token also proves out the real {@code
 * JwtAuthenticationFilter} → {@code JwtRs256Service} → HTTP response integration path.
 */
@SpringBootTest(
    webEnvironment = WebEnvironment.RANDOM_PORT,
    properties = {
        "nexus.identity.encryption.password=test-enc-password-32-chars-long!!",
        "nexus.identity.encryption.salt=cafebabecafebabecafebabecafebabe",
        "nexus.identity.hmac-key=test-not-a-secret-hmac-key-min-32-bytes!!",
        "nexus.identity.default-tenant-id=00000000-0000-7000-8000-000000000001"
    })
@Import({TestcontainersConfiguration.class, GuardedTestControllerConfig.class})
@ActiveProfiles("test")
@Tag("IT")
class JwtAlgorithmDowngradeIT {

  @Value("${local.server.port}")
  private int port;

  @Autowired private RsaKeyConfig rsaKeyConfig;

  /**
   * Forges a token carrying every claim a real {@code issue()}d token would have — including
   * {@code permissions=[tenant:write]}, the exact permission {@code
   * GuardedTestController#guarded()} requires — signed with the app's real private key but under
   * RS384 instead of RS256. If the manual {@code alg} guard were ever removed or weakened, this
   * request would succeed (200); it must instead be rejected at authentication (401 AUTH_003)
   * before permission evaluation ever runs.
   */
  @Test
  void should_return401Auth003_when_tokenCryptographicallyValidButSignedWithRs384NotRs256() {
    long nowSeconds = System.currentTimeMillis() / 1000;
    String forgedJwt = Jwts.builder()
        .header()
            .add("kid", rsaKeyConfig.getKid())
            .add("typ", "JWT")
            .and()
        .subject(UUID.randomUUID().toString())
        .claim("tenant_id", "00000000-0000-7000-8000-000000000001")
        .claim("email_verified", true)
        .claim("roles", List.of("ADMIN"))
        .claim("permissions", List.of("tenant:write"))
        .issuedAt(new Date(nowSeconds * 1000))
        .expiration(new Date((nowSeconds + 900) * 1000))
        .id(UUID.randomUUID().toString())
        .claim("token_version", 0)
        .claim("schema_version", JwtClaims.CURRENT_VERSION)
        .signWith(rsaKeyConfig.getKeyPair().getPrivate(), Jwts.SIG.RS384)
        .compact();

    ResponseEntity<Map> resp = getGuarded(forgedJwt);

    assertThat(resp.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
    assertThat(resp.getBody()).containsEntry("code", "AUTH_003");
  }

  // ── HTTP helper ──────────────────────────────────────────────────────

  @SuppressWarnings("rawtypes")
  private ResponseEntity<Map> getGuarded(String bearerToken) {
    RestTemplate restTemplate = new RestTemplate();
    // Suppress RestTemplate's default behaviour of throwing on 4xx/5xx so we can assert the
    // status directly (mirrors CrossTenantPermissionIT / RegistrationControllerIT).
    restTemplate.setErrorHandler(new DefaultResponseErrorHandler() {
      @Override
      public boolean hasError(ClientHttpResponse response) {
        return false;
      }
    });
    HttpHeaders headers = new HttpHeaders();
    headers.setBearerAuth(bearerToken);
    return restTemplate.exchange(
        "http://localhost:" + port + "/internal-test/guarded",
        HttpMethod.GET,
        new HttpEntity<>(headers),
        Map.class);
  }
}
