package com.example.nexus.identity.infrastructure.security;

import com.example.nexus.common.domain.AuthenticationException;
import com.example.nexus.identity.application.port.out.JwtPort;
import com.example.nexus.identity.domain.AccessTokenResult;
import com.example.nexus.identity.domain.AuthConstants;
import com.example.nexus.identity.domain.JwtClaims;
import com.example.nexus.identity.domain.User;
import com.example.nexus.identity.domain.UserStatus;
import com.example.nexus.identity.domain.UuidGenerator;
import com.example.nexus.rbac.application.PermissionFreshnessService;
import com.example.nexus.rbac.application.RoleResolutionService;
import com.example.nexus.rbac.domain.ResolvedPermissions;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.RequiredTypeException;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import java.security.KeyPair;
import java.time.Clock;
import java.time.Instant;
import java.util.Date;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

/**
 * RS256 JWT issuance and verification (ADR-0007). Explicit algorithm assertion in {@link
 * #verify(String)} guards against alg=none and HS256-confusion attacks (T-3.1, T-3.2).
 */
@Component
@SuppressWarnings("java:S2143")
public class JwtRs256Service implements JwtPort {

  private static final Logger log = LoggerFactory.getLogger(JwtRs256Service.class);

  private static final String AUTH_003 = "AUTH_003";
  private static final String MSG_INVALID = "Token invalid or expired";
  private static final String METRIC_TOKEN_REJECTED = "nexus.auth.token_rejected";
  private static final String CLAIM_SCHEMA_VERSION = "schema_version";
  private static final String CLAIM_TENANT_ID = "tenant_id";
  private static final String CLAIM_PERM_EPOCH = "perm_epoch";
  private static final int SCHEMA_VERSION_WITH_PERM_EPOCH = 3;

  private final KeyPair keyPair;
  private final String kid;
  private final UuidGenerator uuidGenerator;
  private final Clock clock;
  private final long accessTokenTtlSeconds;
  private final RoleResolutionService roleResolutionService;
  private final PermissionFreshnessService permissionFreshnessService;
  private final Map<RejectionReason, Counter> rejectionCounters;

  public JwtRs256Service(
      RsaKeyConfig rsaKeyConfig,
      UuidGenerator uuidGenerator,
      Clock clock,
      @Value("${nexus.jwt.access-token-ttl-seconds}") long accessTokenTtlSeconds,
      RoleResolutionService roleResolutionService,
      PermissionFreshnessService permissionFreshnessService,
      MeterRegistry meterRegistry) {
    this.keyPair = rsaKeyConfig.getKeyPair();
    this.kid = rsaKeyConfig.getKid();
    this.uuidGenerator = uuidGenerator;
    this.clock = clock;
    this.accessTokenTtlSeconds = accessTokenTtlSeconds;
    this.roleResolutionService = roleResolutionService;
    this.permissionFreshnessService = permissionFreshnessService;
    this.rejectionCounters = registerRejectionCounters(meterRegistry);
  }

  /**
   * Registers one {@code nexus.auth.token_rejected} counter per reason up front, so every reason
   * reports 0 from startup (the M6 baseline) instead of appearing only after its first rejection.
   */
  private static Map<RejectionReason, Counter> registerRejectionCounters(
      MeterRegistry meterRegistry) {
    Map<RejectionReason, Counter> counters = new EnumMap<>(RejectionReason.class);
    for (RejectionReason reason : RejectionReason.values()) {
      counters.put(reason, Counter.builder(METRIC_TOKEN_REJECTED)
          .description("Access tokens rejected by verify(), by reason")
          .tag("reason", reason.tag)
          .register(meterRegistry));
    }
    return counters;
  }

  /**
   * Issues a new RS256 JWT access token for the authenticated user.
   * The token includes {@code sub} (user ID), {@code tenant_id}, {@code email_verified},
   * {@code roles}, {@code permissions}, {@code token_version}, {@code schema_version}, {@code
   * perm_epoch}, and standard claims ({@code iat}, {@code exp}, {@code jti}).
   *
   * <p><b>MC-7a:</b> the permission epoch is read <i>before</i> the permissions are resolved. A
   * revocation landing between the two reads then yields "old epoch, new permissions", which the
   * next request rejects once (safe); the reverse order would yield "new epoch, old permissions",
   * which would be accepted (US-018 design §9.3). The permissions are resolved, and cached, under
   * that same epoch (Decision 17), so a set cached before a detach is never read after its bump.
   *
   * <p>{@code roles}/{@code permissions} are resolved via {@link RoleResolutionService} using
   * {@code user.getTenantId()} exclusively — never a default/bootstrap tenant (US-010 AC9).
   *
   * @param user the user for whom to issue the token
   * @return the JWT string, TTL in seconds, and unique JWT ID
   */
  @Override
  @SuppressWarnings("java:S2143")
  public AccessTokenResult issue(User user) {
    Instant now = clock.instant();
    String jti = uuidGenerator.newId().toString();
    long permEpoch = permissionFreshnessService.epochForMint(user.getTenantId(), user.getId());
    ResolvedPermissions resolved =
        roleResolutionService.resolve(user.getId(), user.getTenantId(), permEpoch);

    String jwt = Jwts.builder()
        .header()
            .add("kid", kid)
            .add("typ", "JWT")
            .and()
        .subject(user.getId().toString())
        .claim("tenant_id", user.getTenantId().toString())
        .claim("email_verified", user.getStatus() == UserStatus.ACTIVE)
        .claim("roles", resolved.roles())
        .claim("permissions", resolved.permissions())
        .issuedAt(Date.from(now))
        .expiration(Date.from(now.plusSeconds(accessTokenTtlSeconds)))
        .id(jti)
        .claim("token_version", user.getTokenVersion())
        .claim("schema_version", JwtClaims.CURRENT_VERSION)
        .claim(CLAIM_PERM_EPOCH, permEpoch)
        .signWith(keyPair.getPrivate(), Jwts.SIG.RS256)
        .compact();

    return new AccessTokenResult(jwt, accessTokenTtlSeconds, jti);
  }

  /**
   * Verifies and parses an RS256 JWT, extracting and validating all required claims.
   * Enforces algorithm RS256 (no alg=none or HS256 confusion — T-3.1, T-3.2), then validates the
   * claims (US-018 A11, ADR-0022 D7): {@code schema_version} in {@link
   * JwtClaims#ACCEPTED_VERSIONS}; iat, exp, jti, roles, permissions and token_version present;
   * {@code sub} and {@code tenant_id} canonical UUIDs; and, for v3 only, {@code perm_epoch} a
   * non-negative long. A v2 token has no {@code perm_epoch} and is returned with epoch 0, so a
   * user with a recent revocation gets the v2 token rejected (design §9.6).
   *
   * <p>Every rejection is the same 401 {@code AUTH_003}, counted as {@code
   * nexus.auth.token_rejected{reason}} and logged at DEBUG only, so an M7 rolling deploy cannot
   * flood the logs.
   *
   * @param rawJwt the signed JWT string
   * @return extracted and validated claims
   * @throws AuthenticationException if the token is invalid, expired, or claims are missing or
   *     malformed (AUTH_003)
   */
  @Override
  public JwtClaims verify(String rawJwt) {
    Jws<Claims> jws;
    try {
      jws = Jwts.parser()
          .verifyWith(keyPair.getPublic())
          .clockSkewSeconds(AuthConstants.AUTH_CLOCK_SKEW_SECONDS)
          .build()
          .parseSignedClaims(rawJwt);

      // T-3.2: explicit algorithm assertion — never trust JJWT's internal binding alone
      String alg = jws.getHeader().getAlgorithm();
      if (!"RS256".equals(alg)) {
        throw new AuthenticationException(AUTH_003, MSG_INVALID);
      }
    } catch (AuthenticationException e) {
      // Only the algorithm assertion above throws this inside the try.
      recordRejection(RejectionReason.SIGNATURE);
      throw e;
    } catch (ExpiredJwtException e) {
      throw reject(RejectionReason.EXPIRED);
    } catch (JwtException | IllegalArgumentException e) {
      // Never expose the original exception message — information leak risk
      throw reject(RejectionReason.SIGNATURE);
    }
    return validatedClaims(jws.getPayload());
  }

  /**
   * Validates the claims of a token whose signature and algorithm are already verified. The
   * version is checked first because the shape of a version outside the accepted set is
   * undefined.
   */
  private JwtClaims validatedClaims(Claims payload) {
    if (!(payload.get(CLAIM_SCHEMA_VERSION) instanceof Integer schemaVersion)
        || !JwtClaims.ACCEPTED_VERSIONS.contains(schemaVersion)) {
      throw reject(RejectionReason.SCHEMA_VERSION);
    }

    try {
      Date iatDate = payload.getIssuedAt();
      Date expDate = payload.getExpiration();
      String jti = payload.getId();
      List<String> roles = stringList(payload.get("roles"));
      List<String> permissions = stringList(payload.get("permissions"));
      Integer tokenVersion = payload.get("token_version", Integer.class);
      if (iatDate == null || expDate == null || jti == null
          || roles == null || permissions == null || tokenVersion == null) {
        throw reject(RejectionReason.CLAIMS_MISSING);
      }

      String sub = payload.getSubject();
      if (!isCanonicalUuid(sub)) {
        throw reject(RejectionReason.SUB);
      }
      if (!(payload.get(CLAIM_TENANT_ID) instanceof String tenantId)
          || !isCanonicalUuid(tenantId)) {
        throw reject(RejectionReason.TENANT_ID);
      }
      // v3 is frozen as v2 + perm_epoch (ADR-0022 D7). A v2 token is epoch 0 (design §9.6).
      long permEpoch = 0L;
      if (schemaVersion == SCHEMA_VERSION_WITH_PERM_EPOCH) {
        Object rawPermEpoch = payload.get(CLAIM_PERM_EPOCH);
        if (!isNonNegativeLong(rawPermEpoch)) {
          throw reject(RejectionReason.PERM_EPOCH);
        }
        permEpoch = ((Number) rawPermEpoch).longValue();
      }

      return new JwtClaims(
          sub,
          tenantId,
          Boolean.TRUE.equals(payload.get("email_verified", Boolean.class)),
          roles,
          permissions,
          iatDate.toInstant().getEpochSecond(),
          expDate.toInstant().getEpochSecond(),
          jti,
          tokenVersion,
          schemaVersion,
          permEpoch);
    } catch (ClassCastException | RequiredTypeException e) {
      // A required claim is present with the wrong JSON type.
      throw reject(RejectionReason.CLAIMS_MISSING);
    }
  }

  /**
   * Casts to {@code List<String>}, rejecting a non-null, non-String element. A missing claim
   * (non-{@link List} value, including {@code null}) returns {@code null} for the caller's
   * existing missing-claims check; a wrong element type throws {@link ClassCastException},
   * caught by {@link #validatedClaims(Claims)} as {@code CLAIMS_MISSING} instead of surfacing as
   * a 500 downstream (e.g. in {@code List.copyOf} or a {@code "ROLE_" + r} mapping).
   */
  private static List<String> stringList(Object value) {
    if (!(value instanceof List<?> list)) {
      return null;
    }
    for (Object element : list) {
      if (!(element instanceof String)) {
        throw new ClassCastException("list element is not a String");
      }
    }
    @SuppressWarnings("unchecked")
    List<String> stringElements = (List<String>) list;
    return stringElements;
  }

  /**
   * True only for the exact {@link UUID#toString()} form {@link #issue(User)} mints. {@link
   * UUID#fromString} alone is lenient (it parses {@code "1-1-1-1-1"}), which would let a
   * non-canonical spelling alias a real id downstream.
   */
  private static boolean isCanonicalUuid(String value) {
    if (value == null) {
      return false;
    }
    try {
      return UUID.fromString(value).toString().equals(value);
    } catch (IllegalArgumentException e) {
      return false;
    }
  }

  /** JSON integers deserialize as Integer or Long by size; anything else is not a long. */
  private static boolean isNonNegativeLong(Object value) {
    return (value instanceof Integer i && i >= 0) || (value instanceof Long l && l >= 0);
  }

  private AuthenticationException reject(RejectionReason reason) {
    recordRejection(reason);
    return new AuthenticationException(AUTH_003, MSG_INVALID);
  }

  /** Counts and DEBUG-logs a rejection. Never logs the token or any claim value. */
  private void recordRejection(RejectionReason reason) {
    rejectionCounters.get(reason).increment();
    log.atDebug().addKeyValue("reason", reason.tag).log("access token rejected");
  }

  /** Closed set of {@code nexus.auth.token_rejected} reason tags (US-018 design §8). */
  private enum RejectionReason {
    SIGNATURE("signature"),
    EXPIRED("expired"),
    CLAIMS_MISSING("claims_missing"),
    SCHEMA_VERSION("schema_version"),
    TENANT_ID("tenant_id"),
    SUB("sub"),
    PERM_EPOCH("perm_epoch");

    private final String tag;

    RejectionReason(String tag) {
      this.tag = tag;
    }
  }
}
