package com.example.nexus.identity.infrastructure.security;

import com.example.nexus.common.domain.AuthenticationException;
import com.example.nexus.identity.application.port.out.JwtPort;
import com.example.nexus.identity.domain.AccessTokenResult;
import com.example.nexus.identity.domain.JwtClaims;
import com.example.nexus.identity.domain.User;
import com.example.nexus.identity.domain.UserStatus;
import com.example.nexus.identity.domain.UuidGenerator;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import java.security.KeyPair;
import java.time.Clock;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

/**
 * RS256 JWT issuance and verification (ADR-0007). Explicit algorithm assertion in {@link
 * #verify(String)} guards against alg=none and HS256-confusion attacks (T-3.1, T-3.2).
 */
@Component
public class JwtRs256Service implements JwtPort {

  private static final String AUTH_003 = "AUTH_003";
  private static final String MSG_INVALID = "Token invalid or expired";

  private final KeyPair keyPair;
  private final String kid;
  private final UuidGenerator uuidGenerator;
  private final Clock clock;
  private final long accessTokenTtlSeconds;

  public JwtRs256Service(
      RsaKeyConfig rsaKeyConfig,
      UuidGenerator uuidGenerator,
      Clock clock,
      @Value("${nexus.jwt.access-token-ttl-seconds}") long accessTokenTtlSeconds) {
    this.keyPair = rsaKeyConfig.getKeyPair();
    this.kid = rsaKeyConfig.getKid();
    this.uuidGenerator = uuidGenerator;
    this.clock = clock;
    this.accessTokenTtlSeconds = accessTokenTtlSeconds;
  }

  @Override
  public AccessTokenResult issue(User user) {
    Instant now = clock.instant();
    String jti = uuidGenerator.newId().toString();

    String jwt = Jwts.builder()
        .header()
            .add("kid", kid)
            .add("typ", "JWT")
            .and()
        .subject(user.getId().toString())
        .claim("tenant_id", user.getTenantId().toString())
        .claim("email_verified", user.getStatus() == UserStatus.ACTIVE)
        .claim("roles", List.of("USER"))
        .issuedAt(Date.from(now))
        .expiration(Date.from(now.plusSeconds(accessTokenTtlSeconds)))
        .id(jti)
        .claim("token_version", user.getTokenVersion())
        .signWith(keyPair.getPrivate(), Jwts.SIG.RS256)
        .compact();

    return new AccessTokenResult(jwt, accessTokenTtlSeconds, jti);
  }

  @Override
  public JwtClaims verify(String rawJwt) {
    try {
      Jws<Claims> jws = Jwts.parser()
          .verifyWith(keyPair.getPublic())
          .clockSkewSeconds(30)
          .build()
          .parseSignedClaims(rawJwt);

      // T-3.2: explicit algorithm assertion — never trust JJWT's internal binding alone
      String alg = jws.getHeader().getAlgorithm();
      if (!"RS256".equals(alg)) {
        throw new AuthenticationException(AUTH_003, MSG_INVALID);
      }

      Claims payload = jws.getPayload();
      Date iatDate = payload.getIssuedAt();
      Date expDate = payload.getExpiration();
      String sub = payload.getSubject();
      String jti = payload.getId();
      if (iatDate == null || expDate == null || sub == null || jti == null) {
        throw new AuthenticationException(AUTH_003, MSG_INVALID);
      }

      @SuppressWarnings("unchecked")
      List<String> roles = (List<String>) payload.get("roles");
      Integer tokenVersion = payload.get("token_version", Integer.class);
      if (roles == null || tokenVersion == null) {
        throw new AuthenticationException(AUTH_003, MSG_INVALID);
      }

      return new JwtClaims(
          sub,
          payload.get("tenant_id", String.class),
          Boolean.TRUE.equals(payload.get("email_verified", Boolean.class)),
          roles,
          iatDate.toInstant().getEpochSecond(),
          expDate.toInstant().getEpochSecond(),
          jti,
          tokenVersion);

    } catch (AuthenticationException e) {
      throw e;
    } catch (JwtException | IllegalArgumentException | ClassCastException e) {
      // Never expose the original exception message — information leak risk
      throw new AuthenticationException(AUTH_003, MSG_INVALID);
    }
  }
}
