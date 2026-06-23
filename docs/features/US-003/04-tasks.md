# US-003 Task Breakdown — Authenticate users via login issuing JWT access and refresh tokens

Status: GATE 3 APPROVED — READY FOR IMPLEMENTATION  
Sources: `03-design.md` (approved) · `03b-threat-model.md` (approved, all 8 required changes folded in)  
Date: 2026-06-21

> **AI-implementation note:** Consolidated from 36 granular tasks to 15 implementation sessions. Each IMPL groups tasks that share a compilation boundary or package context. Original T-IDs are preserved in parentheses for threat-model traceability.

---

## Pre-implementation notes

**No schema migration required.** `refresh_tokens` (V2) and `auth_events` (V2) are fully defined. `ddl-auto=validate` will pass. V4 slot (`idx_refresh_tokens_expires_at`) reserved but not created this sprint.

**Existing code reused without modification:** `TokenGenerator`, `TokenHasher`, `EmailBlindIndexService`, `UuidV7Generator`, `UuidGenerator`, `AuthEventPort`, `AuthEvent`, `RateLimitException`, `PasswordEncoderConfig` (`Argon2PasswordEncoder` bean), `UserRegistrationPort`, `JpaUserRepository`, `JpaAuthTokenAdapter` (email-verification tokens — separate from refresh tokens).

**Controller sub-package:** `identity/interfaces/rest` (matches existing `RegistrationController`).  
**New infra sub-package:** `identity/infrastructure/web` (for filters; does not exist yet).

---

## Dependency graph

```
IMPL-01 (config) ──────────────────────────────────────────────────────────────────┐
IMPL-02 (domain + ports) ──────────────────────────────────────────────────────────┼──→ IMPL-07
                          ──────────────────────────────────────────────────────────┼──→ IMPL-08
IMPL-03 (RsaKeyConfig + PwVerifier) ← IMPL-01, IMPL-02
IMPL-04 (JwtRs256Service) ← IMPL-01, IMPL-02, IMPL-03
IMPL-05 (RateLimitStore)  ← IMPL-02
IMPL-06 (JpaRefreshToken) ← IMPL-02

IMPL-07 (LoginUseCase)    ← IMPL-02, IMPL-03, IMPL-04, IMPL-05, IMPL-06
IMPL-08 (RefreshUseCase)  ← IMPL-02, IMPL-04, IMPL-06
IMPL-09 (Filters + SecurityConfig + GlobalExceptionHandler) ← IMPL-02, IMPL-04, IMPL-05
IMPL-10 (Controllers + DTOs) ← IMPL-07, IMPL-08, IMPL-09

Frontend (parallel track after IMPL-01):
IMPL-11 (AuthStore + AuthService + Interceptor + Guard)
IMPL-12 (LoginFormComponent + route) ← IMPL-11

Tests (after implementation):
IMPL-13 (security unit tests)  ← IMPL-04, IMPL-07
IMPL-14 (integration tests)    ← IMPL-07, IMPL-08, IMPL-10
IMPL-15 (SecurityConfig IT + contract + docs) ← IMPL-09, IMPL-10
```

**Verification gate after each IMPL (backend):** `./mvnw verify -DskipITs` must be green before moving to the next.  
**After IMPL-09:** `./mvnw verify` (full, with Testcontainers) to confirm existing IT suite still green.

---

## Critical-risk tasks

| IMPL | Risk |
|------|------|
| **IMPL-07** | Anti-enumeration ordering must be exact; dummy-hash must use runtime Argon2 params; status gate must be allowlist. Highest security sensitivity. |
| **IMPL-09** | Blast-radius: every existing IT that touches a protected endpoint re-validates here. |
| **IMPL-04** | Algorithm-confusion defence (alg=none, HS256 confusion) must be explicitly asserted at parse time, not implicitly handled by JJWT defaults. |

---

## IMPL-01 — Dependencies + Configuration (T-001, T-002)

**What gets built:** pom.xml JJWT additions + application.yml/dev/test JWT and feature-flag properties.

**Files modified:**
- `nexus-backend/pom.xml`
- `nexus-backend/src/main/resources/application.yml`
- `nexus-backend/src/main/resources/application-dev.yml`
- `nexus-backend/src/main/resources/application-test.yml`

### pom.xml changes

Add to `<properties>`:
```xml
<jjwt.version>0.12.6</jjwt.version>
```

Add to `<dependencies>`:
```xml
<dependency>
  <groupId>io.jsonwebtoken</groupId>
  <artifactId>jjwt-api</artifactId>
  <version>${jjwt.version}</version>
</dependency>
<dependency>
  <groupId>io.jsonwebtoken</groupId>
  <artifactId>jjwt-impl</artifactId>
  <version>${jjwt.version}</version>
  <scope>runtime</scope>
</dependency>
<dependency>
  <groupId>io.jsonwebtoken</groupId>
  <artifactId>jjwt-jackson</artifactId>
  <version>${jjwt.version}</version>
  <scope>runtime</scope>
</dependency>
```

Do NOT add `spring-boot-starter-data-redis` or `spring-boot-starter-oauth2-resource-server`.

### application.yml additions
```yaml
nexus:
  jwt:
    private-key-pem: ${NEXUS_JWT_PRIVATE_KEY_PEM:}
    public-key-pem: ${NEXUS_JWT_PUBLIC_KEY_PEM:}
    access-token-ttl-seconds: 900
  security:
    rate-limit:
      store-type: memory
      max-attempts: 5
      window-seconds: 300
feature:
  nexus-us003-auth-login:
    enabled: false
```

### application-dev.yml additions
```yaml
feature:
  nexus-us003-auth-login:
    enabled: true
```

### application-test.yml additions
```yaml
feature:
  nexus-us003-auth-login:
    enabled: true
nexus:
  security:
    rate-limit:
      max-attempts: 3
      window-seconds: 10
```

**Testing:** `./mvnw verify -DskipITs` compiles and passes.  
**Definition of Done:** JJWT artifacts at 0.12.6 in dependency tree. No PEM values in source. No Redis or OAuth2-resource-server dependencies added.

---

## IMPL-02 — Domain Layer + Port Interfaces (T-003 through T-008)

**What gets built:** All domain exceptions, value records, entity changes, AuthConstants update, and 5 port interfaces. These are all pure-Java files with no Spring or JJWT imports — they form the inner-layer compilation unit.

**Files created:**
- `nexus-backend/src/main/java/com/example/nexus/common/domain/AuthenticationException.java`
- `nexus-backend/src/main/java/com/example/nexus/common/domain/AccountNotVerifiedException.java`
- `nexus-backend/src/main/java/com/example/nexus/identity/domain/AccessTokenResult.java`
- `nexus-backend/src/main/java/com/example/nexus/identity/domain/JwtClaims.java`
- `nexus-backend/src/main/java/com/example/nexus/identity/domain/LoginResult.java`
- `nexus-backend/src/main/java/com/example/nexus/identity/application/port/out/JwtPort.java`
- `nexus-backend/src/main/java/com/example/nexus/identity/application/port/out/JwkSetPort.java`
- `nexus-backend/src/main/java/com/example/nexus/identity/application/port/out/PasswordVerifierPort.java`
- `nexus-backend/src/main/java/com/example/nexus/identity/application/port/out/RefreshTokenPort.java`
- `nexus-backend/src/main/java/com/example/nexus/identity/application/port/out/RateLimitStore.java`
- `nexus-backend/src/main/java/com/example/nexus/identity/application/port/out/RateLimitResult.java`

**Files modified:**
- `nexus-backend/src/main/java/com/example/nexus/identity/domain/RefreshToken.java`
- `nexus-backend/src/main/java/com/example/nexus/identity/domain/AuthConstants.java`

### Domain exceptions (common/domain)

```java
// AuthenticationException.java — maps to HTTP 401
public class AuthenticationException extends DomainException {
  public AuthenticationException(String code, String message) { super(code, message); }
}

// AccountNotVerifiedException.java — maps to HTTP 403
public class AccountNotVerifiedException extends DomainException {
  public AccountNotVerifiedException(String code, String message) { super(code, message); }
}
```

Standard usage: `AUTH_001` (bad credentials/unknown email/non-ACTIVE status) and `AUTH_003` (invalid JWT) and `AUTH_004` (invalid refresh token) → `AuthenticationException`. `AUTH_002` (PENDING account, after credential check) → `AccountNotVerifiedException`.

### Domain value objects (identity/domain)

```java
// AccessTokenResult.java
public record AccessTokenResult(String token, long expiresInSeconds, String jti) {}

// JwtClaims.java
public record JwtClaims(
    String sub, String tenantId, boolean emailVerified,
    java.util.List<String> roles, long iat, long exp, String jti, int tokenVersion) {}

// LoginResult.java
public record LoginResult(String accessToken, long expiresInSeconds, String userId, String rawRefreshToken) {}
```

### RefreshToken.revoke() domain method

Add to the existing `RefreshToken` entity (after the constructor):
```java
/** Marks this token as revoked. Follows the User.verify() pattern — intention-revealing domain method. */
public void revoke(Instant revokedAt) {
  this.revokedAt = revokedAt;
}
```
No public setter. `revokedAt` field is already present in the entity.

### AuthConstants update

Change `AUTH_REFRESH_TOKEN_TTL_DAYS` from `7` → `14` (Gate-1 Q1). Add new constant:
```java
public static final int AUTH_REFRESH_TOKEN_TTL_DAYS = 14;  // was 7
public static final int AUTH_ACCESS_TOKEN_TTL_SECONDS = 900;
```

### Port interfaces (identity/application/port/out)

```java
// JwtPort.java
public interface JwtPort {
  AccessTokenResult issue(User user);
  JwtClaims verify(String rawJwt); // throws AuthenticationException("AUTH_003") on any failure
}

// JwkSetPort.java
public interface JwkSetPort {
  Map<String, Object> getPublicKeySet(); // RFC 7517 JSON-serialisable map — no Jackson/Nimbus types
}

// PasswordVerifierPort.java  (separate from existing PasswordHasherPort which only hashes)
public interface PasswordVerifierPort {
  boolean matches(String rawPassword, String encodedHash);
}

// RefreshTokenPort.java  (separate from AuthTokenPort which handles email-verification tokens)
public interface RefreshTokenPort {
  void save(RefreshToken token);
  Optional<RefreshToken> findByTokenHash(String tokenHash);
  void revokeFamily(UUID familyId, Instant revokedAt);
  void revokeByUserId(UUID userId, Instant revokedAt); // for US-005 reuse
}

// RateLimitResult.java
public record RateLimitResult(boolean allowed, long retryAfterSeconds) {
  public static RateLimitResult allowed() { return new RateLimitResult(true, 0); }
  public static RateLimitResult rejected(long retryAfterSeconds) {
    return new RateLimitResult(false, retryAfterSeconds);
  }
}

// RateLimitStore.java
public interface RateLimitStore {
  /** Key format: "IP:{ip}" or "USER:{emailHmac}" or "REFRESH_IP:{ip}". */
  RateLimitResult tryConsume(String key, int windowSeconds, int maxAttempts);
}
```

**Testing:** Unit tests for `AuthenticationException`/`AccountNotVerifiedException` (code + message), `RefreshToken.revoke()` (revokedAt set; calling twice is idempotent), `AuthConstants.AUTH_REFRESH_TOKEN_TTL_DAYS == 14`.  
**Definition of Done:** All 11 new files + 2 modified files compile. No Spring or infrastructure imports in any port interface or domain class.

---

## IMPL-03 — RsaKeyConfig + PasswordVerifierAdapter (T-010, T-012)

**What gets built:** RSA key loading/generation config bean and Argon2 verification adapter.

**Files created:**
- `nexus-backend/src/main/java/com/example/nexus/identity/infrastructure/security/RsaKeyConfig.java`
- `nexus-backend/src/main/java/com/example/nexus/identity/infrastructure/security/PasswordVerifierAdapter.java`

### RsaKeyConfig

`@Configuration @ConfigurationProperties(prefix="nexus.jwt")`. Fields: `String privateKeyPem`, `String publicKeyPem`.

`@PostConstruct init()` behaviour:
1. If both PEM strings are non-blank: parse via `KeyFactory.getInstance("RSA")` → PKCS8 private + X509 public. Validate `((RSAKey) keyPair.getPrivate()).getModulus().bitLength() >= 2048` — throw `IllegalArgumentException` if shorter. Cache as `KeyPair`.
2. If blank AND active profile is `prod` (check `Environment.acceptsProfiles(Profiles.of("prod"))`): throw `IllegalStateException("JWT RSA key not configured — startup blocked in prod profile")`.
3. If blank AND NOT prod: generate ephemeral `KeyPairGenerator.getInstance("RSA")` at 2048 bits. Log WARN "Using ephemeral RSA-2048 key — NOT for production".

`String getKid()`: first 8 hex chars of SHA-256 of `keyPair.getPublic().getEncoded()`.

`@Override public String toString()`: return `"RsaKeyConfig{kid='" + getKid() + "'}"` — never expose PEM content.

Add `privateKeyPem` to the sanitize list so it is hidden in `/actuator/configprops` and `/actuator/env`. Reference the existing `IdentityActuatorSanitizer` in `identity/infrastructure/crypto/` — extend it or apply the same `@SanitizableData` pattern already used there.

### PasswordVerifierAdapter

```java
@Component
public class PasswordVerifierAdapter implements PasswordVerifierPort {
  private final Argon2PasswordEncoder encoder;
  public PasswordVerifierAdapter(Argon2PasswordEncoder encoder) { this.encoder = encoder; }

  @Override
  public boolean matches(String rawPassword, String encodedHash) {
    return encoder.matches(rawPassword, encodedHash);
  }
}
```

**Testing:** Unit tests for `RsaKeyConfig`: (a) blank PEM + prod profile → `IllegalStateException`; (b) blank PEM + dev → key generated with modulus ≥ 2048 bit; (c) PEM with 1024-bit key → `IllegalArgumentException`; (d) `toString()` does not contain "BEGIN"; (e) `getKid()` is exactly 8 hex chars.  
Unit test for `PasswordVerifierAdapter`: `matches("correct", encoder.encode("correct"))` → true; `matches("wrong", ...)` → false.  
**Definition of Done:** All unit tests pass. `IdentityActuatorSanitizer` (or equivalent) prevents `privateKeyPem` from appearing in actuator responses.

---

## IMPL-04 — JwtRs256Service + JwkSetAdapter (T-011)

**What gets built:** JWT issuance, verification, and JWKS publishing — the most security-sensitive infrastructure classes.

**Files created:**
- `nexus-backend/src/main/java/com/example/nexus/identity/infrastructure/security/JwtRs256Service.java`
- `nexus-backend/src/main/java/com/example/nexus/identity/infrastructure/security/JwkSetAdapter.java`

### JwtRs256Service implements JwtPort

Constructor-inject: `RsaKeyConfig rsaKeyConfig`, `UuidGenerator uuidGenerator`, `Clock clock`, `@Value("${nexus.jwt.access-token-ttl-seconds}") long accessTokenTtlSeconds`.

**`issue(User user)`:**
- `Instant now = clock.instant()`.
- Claims: `sub`=user.id().toString(), `tenant_id`=user.tenantId().toString(), `email_verified`=(user.status()==UserStatus.ACTIVE), `roles`=List.of("USER"), `iat`=now, `exp`=now+900s, `jti`=uuidGenerator.generate().toString(), `token_version`=user.tokenVersion().
- Sign: `Jwts.builder().header().add("kid", rsaKeyConfig.getKid()).add("typ","JWT").and().<claim calls>.signWith(rsaKeyConfig.getKeyPair().getPrivate(), Jwts.SIG.RS256).compact()`.
- Return `new AccessTokenResult(jwt, accessTokenTtlSeconds, jti)`.

**`verify(String rawJwt)`:**
- Parse: `Jwts.parser().verifyWith(rsaKeyConfig.getKeyPair().getPublic()).clockSkewSeconds(30).build().parseSignedClaims(rawJwt)`.
- **Explicit alg assertion (T-3.2 — algorithm confusion defence):** After parsing, assert `claims.getHeader().getAlgorithm().equals("RS256")`. If not RS256 → throw `AuthenticationException("AUTH_003", "Token invalid or expired")`. This prevents HS256 confusion even if JJWT's internal binding is bypassed.
- Map payload to `JwtClaims` record. Cast `roles` claim to `List<String>`, `token_version` to `Integer`.
- Catch ALL of: `JwtException`, `IllegalArgumentException`, `ClassCastException` → rethrow as `new AuthenticationException("AUTH_003", "Token invalid or expired")`. **Never propagate the original exception message** (information leak).

### JwkSetAdapter implements JwkSetPort

```java
@Component
public class JwkSetAdapter implements JwkSetPort {
  private final RsaKeyConfig rsaKeyConfig;
  public JwkSetAdapter(RsaKeyConfig rsaKeyConfig) { this.rsaKeyConfig = rsaKeyConfig; }

  @Override
  public Map<String, Object> getPublicKeySet() {
    RSAPublicKey pub = (RSAPublicKey) rsaKeyConfig.getKeyPair().getPublic();
    String n = Base64.getUrlEncoder().withoutPadding()
        .encodeToString(pub.getModulus().toByteArray());
    String e = Base64.getUrlEncoder().withoutPadding()
        .encodeToString(pub.getPublicExponent().toByteArray());
    Map<String, Object> key = new LinkedHashMap<>();
    key.put("kty", "RSA");
    key.put("use", "sig");
    key.put("alg", "RS256");
    key.put("kid", rsaKeyConfig.getKid());
    key.put("n", n);
    key.put("e", e);
    // Assert: never include d, p, q (private key fields)
    return Map.of("keys", List.of(key));
  }
}
```

**Testing (T-028 subset — written here, full suite in IMPL-13):**
- Round-trip: `verify(issue(user).token())` → claims match user fields exactly.
- Expired token (clock 30min past) → `AuthenticationException`.
- `getPublicKeySet()` map contains no `d`/`p`/`q` keys.

**Definition of Done:** Round-trip test passes. Algorithm assertion present in `verify()`. Private key fields absent from JWKS output.

---

## IMPL-05 — InMemoryRateLimitStore (T-014)

**What gets built:** Thread-safe sliding-window rate limiter with bounded memory (T-6.2 mitigation).

**Files created:**
- `nexus-backend/src/main/java/com/example/nexus/identity/infrastructure/security/InMemoryRateLimitStore.java`

```java
@ConditionalOnProperty(name = "nexus.security.rate-limit.store-type",
    havingValue = "memory", matchIfMissing = true)
@Component
public class InMemoryRateLimitStore implements RateLimitStore {
  private final ConcurrentHashMap<String, Deque<Instant>> store = new ConcurrentHashMap<>();
  private final Clock clock;
  public InMemoryRateLimitStore(Clock clock) { this.clock = clock; }

  @Override
  public RateLimitResult tryConsume(String key, int windowSeconds, int maxAttempts) {
    Instant now = clock.instant();
    Instant windowStart = now.minusSeconds(windowSeconds);
    boolean[] rejected = {false};

    store.compute(key, (k, deque) -> {
      if (deque == null) deque = new ArrayDeque<>();
      deque.removeIf(t -> t.isBefore(windowStart));  // prune expired
      if (deque.size() >= maxAttempts) {
        rejected[0] = true;
      } else {
        deque.addLast(now);
      }
      return deque.isEmpty() ? null : deque;  // evict empty key (T-6.2 bounding)
    });

    return rejected[0]
        ? RateLimitResult.rejected(windowSeconds)
        : RateLimitResult.allowed();
  }
}
```

**No `synchronized` blocks.** Thread-safety via `ConcurrentHashMap.compute()` (one atomic critical section per key). Injects `Clock` — never calls `Instant.now()` directly.

**Known limitations (T-6.1/T-6.3, documented):** Per-JVM counters only; not shared across replicas; reset on restart. Single-replica deployment constraint until Redis store is enabled via `nexus.security.rate-limit.store-type=redis`.

**Testing:**
1. First `maxAttempts-1` calls in window → all `allowed()`.
2. `maxAttempts`-th call → `rejected()` with `retryAfterSeconds == windowSeconds`.
3. After window expires (advance Clock) → counter resets; next call `allowed()`.
4. Flood with 5000 distinct keys → all Deques pruned to empty → `store.size() == 0` (key eviction working).
5. 50 concurrent threads calling `tryConsume` on the same key → no NPE, no data corruption, count does not exceed `maxAttempts`.

**Definition of Done:** All 5 unit tests pass. No `synchronized`. `@ConditionalOnProperty(matchIfMissing=true)` present.

---

## IMPL-06 — JpaRefreshTokenRepository + JpaRefreshTokenAdapter (T-013)

**What gets built:** JPA persistence layer for the `refresh_tokens` table. `AuthTokenPort`/`JpaAuthTokenAdapter` (email-verification tokens) are untouched.

**Files created:**
- `nexus-backend/src/main/java/com/example/nexus/identity/infrastructure/persistence/JpaRefreshTokenRepository.java`
- `nexus-backend/src/main/java/com/example/nexus/identity/infrastructure/persistence/JpaRefreshTokenAdapter.java`

### JpaRefreshTokenRepository

```java
public interface JpaRefreshTokenRepository extends JpaRepository<RefreshToken, UUID> {

  Optional<RefreshToken> findByTokenHash(String tokenHash);

  @Modifying
  @Query("UPDATE RefreshToken r SET r.revokedAt = :revokedAt " +
         "WHERE r.familyId = :familyId AND r.revokedAt IS NULL")
  void revokeByFamilyId(@Param("familyId") UUID familyId, @Param("revokedAt") Instant revokedAt);

  @Modifying
  @Query("UPDATE RefreshToken r SET r.revokedAt = :revokedAt " +
         "WHERE r.userId = :userId AND r.revokedAt IS NULL")
  void revokeByUserId(@Param("userId") UUID userId, @Param("revokedAt") Instant revokedAt);
}
```

### JpaRefreshTokenAdapter

```java
@Component
public class JpaRefreshTokenAdapter implements RefreshTokenPort {
  private final JpaRefreshTokenRepository repo;
  public JpaRefreshTokenAdapter(JpaRefreshTokenRepository repo) { this.repo = repo; }

  @Override public void save(RefreshToken token) { repo.save(token); }
  @Override public Optional<RefreshToken> findByTokenHash(String hash) { return repo.findByTokenHash(hash); }
  @Override public void revokeFamily(UUID familyId, Instant revokedAt) { repo.revokeByFamilyId(familyId, revokedAt); }
  @Override public void revokeByUserId(UUID userId, Instant revokedAt) { repo.revokeByUserId(userId, revokedAt); }
}
```

`UuidV7Converter` (existing) handles `BINARY(16)` mapping automatically via `@Column(columnDefinition = "BINARY(16)")` already present on `RefreshToken`.

**Testing:** `*IT` (Testcontainers MySQL): save token → `findByTokenHash` returns it; `revokeFamily` sets `revokedAt` on matching rows; `revokeByUserId` same; calling revoke on already-revoked rows is idempotent (no error, `revokedAt` unchanged).  
**Definition of Done:** IT tests pass. `@Modifying` queries do not touch rows where `revokedAt IS NOT NULL`.

---

## IMPL-07 — LoginUseCase (T-015)

**What gets built:** The primary login application service. Highest security sensitivity — anti-enumeration ordering, ACTIVE allowlist, dummy-hash timing must be exact.

**Files created:**
- `nexus-backend/src/main/java/com/example/nexus/identity/application/service/LoginUseCase.java`

**Annotation:** `@Service @Transactional`

**Constructor injection:** `EmailBlindIndexService`, `UserRegistrationPort`, `PasswordVerifierPort`, `PasswordHasherPort` (for dummy-hash init), `RefreshTokenPort`, `JwtPort`, `AuthEventPort`, `RateLimitStore`, `TokenGenerator`, `TokenHasher`, `UuidGenerator`, `Clock`, `RequestContext` (for tenant resolution), `@Value("${nexus.security.rate-limit.max-attempts}") int maxAttempts`, `@Value("${nexus.security.rate-limit.window-seconds}") int windowSeconds`.

**`@PostConstruct init()`:** Pre-compute dummy hash using the runtime Argon2 params:
```java
private String dummyHash;

@PostConstruct
void init() {
  this.dummyHash = passwordHasher.hash("__nexus_dummy_timing_constant__");
}
```
This runs Argon2 encode at startup with the **runtime profile's parameters** (not hardcoded). Field is immutable after init.

**`execute(String email, String rawPassword, String clientIp) → LoginResult`**

Steps — ORDER IS SECURITY-CRITICAL, do not reorder:

```
1. Rate-limit check (BEFORE any DB or Argon2 work):
   emailHmac = emailBlindIndexService.blindIndex(email)
   ipResult = rateLimitStore.tryConsume("IP:" + clientIp, windowSeconds, maxAttempts)
   userResult = rateLimitStore.tryConsume("USER:" + emailHmac, windowSeconds, maxAttempts)
   if (!ipResult.allowed() || !userResult.allowed())
     → throw new RateLimitException("RATE_001", "Too many login attempts",
                                    Math.max(ipResult.retryAfterSeconds(), userResult.retryAfterSeconds()))

2. Look up user (assign found flag — DO NOT BRANCH YET):
   UUID tenantId = RequestContext.currentTenantId()  // from request scope, never from request body
   Optional<User> userOpt = userRegistrationPort.findByTenantAndEmailHmac(tenantId, emailHmac)
   boolean found = userOpt.isPresent()

3. Argon2 verify — ALWAYS RUNS regardless of found (anti-enumeration T-2.2):
   boolean passwordMatch = found
       ? passwordVerifier.matches(rawPassword, userOpt.get().passwordHash())
       : passwordVerifier.matches(rawPassword, dummyHash)  // same CPU cost

4. If !found OR !passwordMatch (SAME code path for both, IDENTICAL response):
   authEventPort.record(new AuthEvent(uuidGenerator.generate(), "LOGIN_FAILURE", "FAILURE")
       .withIpAddress(clientIp))
   throw new AuthenticationException("AUTH_001", "Invalid email or password")

5. Status gate — ACTIVE allowlist (T-2.5 — allowlist, not denylist):
   User user = userOpt.get()
   if (user.status() == UserStatus.PENDING):
     authEventPort.record(new AuthEvent(uuidGenerator.generate(), "LOGIN_PENDING_ACCOUNT", "FAILURE")
         .withUserId(user.id()).withIpAddress(clientIp))
     throw new AccountNotVerifiedException("AUTH_002", "Account not verified. Please check your email.")
   if (user.status() != UserStatus.ACTIVE):
     // LOCKED, DISABLED, or any future status — NEVER fall through to token issuance
     authEventPort.record(new AuthEvent(uuidGenerator.generate(), "LOGIN_FAILURE", "FAILURE")
         .withUserId(user.id()).withIpAddress(clientIp))
     throw new AuthenticationException("AUTH_001", "Invalid email or password")

6. Issue access JWT:
   AccessTokenResult accessResult = jwtPort.issue(user)

7. Generate refresh token:
   String rawRefreshToken = tokenGenerator.generate()  // 32-byte random hex
   String tokenHash = tokenHasher.hash(rawRefreshToken)  // SHA-256
   UUID familyId = uuidGenerator.generate()
   UUID tokenId = uuidGenerator.generate()
   Instant expiresAt = clock.instant().plus(AuthConstants.AUTH_REFRESH_TOKEN_TTL_DAYS, ChronoUnit.DAYS)

8. Persist refresh token:
   refreshTokenPort.save(new RefreshToken(tokenId, user.id(), tokenHash, familyId, expiresAt))

9. Record LOGIN_SUCCESS and return:
   authEventPort.record(new AuthEvent(uuidGenerator.generate(), "LOGIN_SUCCESS", "SUCCESS")
       .withUserId(user.id()).withIpAddress(clientIp))
   return new LoginResult(accessResult.token(), accessResult.expiresInSeconds(),
                          user.id().toString(), rawRefreshToken)
   // rawRefreshToken exits here ONLY — never logged, never in JSON body
```

**`RequestContext` usage:** Check `com/example/nexus/common/domain/RequestContext.java` (existing) for how `currentTenantId()` is resolved from the request scope. If tenant comes from a header/path variable on the HTTP layer, it must be injected here via the existing mechanism, not from the email.

**Testing (full suite in IMPL-13 — minimum here):** Happy path produces `LoginResult` with non-null `accessToken`. Wrong password → `AUTH_001`. Argon2 still called when `!found` (verify mock invocation count).  
**Definition of Done:** `@Transactional` on class. No `if (found)` branch before step 3. `DUMMY_ARGON2_HASH` initialised at startup via `@PostConstruct`. All unit tests pass.

---

## IMPL-08 — RefreshTokenUseCase (T-016)

**What gets built:** Refresh token rotation with theft detection and concurrent-rotation safety.

**Files created:**
- `nexus-backend/src/main/java/com/example/nexus/identity/application/service/RefreshTokenUseCase.java`

**Annotation:** `@Service @Transactional`

**Constructor injection:** `RefreshTokenPort`, `UserRegistrationPort`, `JwtPort`, `AuthEventPort`, `UuidGenerator`, `TokenGenerator`, `TokenHasher`, `Clock`.

**`execute(String tokenCookieValue, String clientIp) → LoginResult`**

```
1. Hash incoming value:
   String hash = tokenHasher.hash(tokenCookieValue)

2. Look up by hash (unknown token = theft signal):
   RefreshToken token = refreshTokenPort.findByTokenHash(hash)
       .orElseThrow(() → {
           record("TOKEN_REFRESH_FAILURE")
           throw new AuthenticationException("AUTH_004", "Refresh token invalid")
       })

3. Theft detection — MUST fire family revocation before throwing:
   if (token.getRevokedAt() != null):
     refreshTokenPort.revokeFamily(token.getFamilyId(), clock.instant())
     record("REFRESH_FAMILY_REVOKED", withUserId=token.getUserId())
     throw new AuthenticationException("AUTH_004", "Refresh token invalid")

4. Expiry check:
   if (token.getExpiresAt().isBefore(clock.instant())):
     record("TOKEN_REFRESH_FAILURE")
     throw new AuthenticationException("AUTH_004", "Refresh token invalid")

5. Revoke old token (one-time use):
   token.revoke(clock.instant())
   try:
     refreshTokenPort.save(token)
   catch (OptimisticLockingFailureException):
     record("TOKEN_REFRESH_FAILURE")
     throw new AuthenticationException("AUTH_004", "Refresh token invalid")

6. Re-fetch user:
   User user = userRegistrationPort.findById(token.getUserId())
       .orElseThrow(() → new AuthenticationException("AUTH_004", "Refresh token invalid"))

7. Re-check status (must re-validate — status may have changed):
   if (user.status() != UserStatus.ACTIVE):
     throw new AuthenticationException("AUTH_004", "Refresh token invalid")

8. Issue new access JWT:
   AccessTokenResult accessResult = jwtPort.issue(user)

9. Create new refresh token (same familyId — rotation chain):
   String newRaw = tokenGenerator.generate()
   RefreshToken newToken = new RefreshToken(
       uuidGenerator.generate(), user.id(), tokenHasher.hash(newRaw),
       token.getFamilyId(),  // SAME family
       clock.instant().plus(AuthConstants.AUTH_REFRESH_TOKEN_TTL_DAYS, ChronoUnit.DAYS))
   refreshTokenPort.save(newToken)

10. Record and return:
    record("TOKEN_REFRESH_SUCCESS", withUserId=user.id())
    return new LoginResult(accessResult.token(), accessResult.expiresInSeconds(),
                           user.id().toString(), newRaw)
```

**Testing (full in IMPL-14 — minimum here):** Happy path produces new `LoginResult`. Revoked token → family revocation fires + `AUTH_004`.  
**Definition of Done:** `@Transactional` on class. `OptimisticLockingFailureException` caught and converted to `AUTH_004`. Family revocation emits `REFRESH_FAMILY_REVOKED` audit event.

---

## IMPL-09 — Filters + SecurityConfig overhaul + GlobalExceptionHandler (T-017, T-018, T-019)

**What gets built:** Two new filters, full SecurityConfig overhaul (remove HTTP Basic, add JWT filter, update permit-all + CORS), and two new exception handlers. High blast-radius — existing IT tests re-validate here.

**Files created:**
- `nexus-backend/src/main/java/com/example/nexus/identity/infrastructure/web/LoginRateLimitFilter.java`
- `nexus-backend/src/main/java/com/example/nexus/identity/infrastructure/web/JwtAuthenticationFilter.java`

**Files modified:**
- `nexus-backend/src/main/java/com/example/nexus/config/SecurityConfig.java`
- `nexus-backend/src/main/java/com/example/nexus/common/web/GlobalExceptionHandler.java`

### LoginRateLimitFilter

`extends OncePerRequestFilter`. Matches `POST /api/v1/auth/login` (Argon2 cost, 5/5-min) and `POST /api/v1/auth/refresh` (DB cost, 30/5-min per IP).

**Client IP — always `request.getRemoteAddr()` only (T-1.3). Never `X-Forwarded-For`.**

For `/auth/login`: wrap request with `ContentCachingRequestWrapper`, parse body JSON to extract `email`, compute `emailHmac = emailBlindIndexService.blindIndex(email)`, check both IP and USER keys.

For `/auth/refresh`: check only IP key (`"REFRESH_IP:" + ip`) with limit 30, same `windowSeconds`.

On exceeded: write 429 RFC 7807 directly to response (before `@ControllerAdvice` is reached):
```json
{"status":429,"title":"Too Many Requests","code":"RATE_001","retryAfterSeconds":<n>,"traceId":"<MDC>"}
```
Set `Content-Type: application/problem+json` and `Retry-After: <n>` header. Return without calling `filterChain.doFilter`.

Constructor-inject: `RateLimitStore`, `EmailBlindIndexService`, `ObjectMapper`, `@Value("${nexus.security.rate-limit.max-attempts}") int maxAttempts`, `@Value("${nexus.security.rate-limit.window-seconds}") int windowSeconds`.

### JwtAuthenticationFilter

`extends OncePerRequestFilter`.

```java
@Override
protected void doFilterInternal(HttpServletRequest req, HttpServletResponse res, FilterChain chain) {
  String header = req.getHeader("Authorization");
  if (header == null || !header.startsWith("Bearer ")) {
    chain.doFilter(req, res);  // no-op; default-deny handles unauthenticated access
    return;
  }
  String rawJwt = header.substring(7);
  try {
    JwtClaims claims = jwtPort.verify(rawJwt);
    List<GrantedAuthority> authorities = claims.roles().stream()
        .map(r -> new SimpleGrantedAuthority("ROLE_" + r)).toList();
    UsernamePasswordAuthenticationToken auth =
        new UsernamePasswordAuthenticationToken(claims.sub(), null, authorities);
    // stash all extra claims as details (T-3.7 — downstream paths read from SecurityContext)
    auth.setDetails(Map.of(
        "tenantId", claims.tenantId(),
        "emailVerified", claims.emailVerified(),
        "tokenVersion", claims.tokenVersion()
    ));
    SecurityContextHolder.getContext().setAuthentication(auth);
    MDC.put("userId", claims.sub());
    MDC.put("tenantId", claims.tenantId());
  } catch (AuthenticationException e) {
    SecurityContextHolder.clearContext();
    authenticationEntryPoint.commence(req, res,
        new org.springframework.security.core.AuthenticationException(e.getMessage(), e) {});
    return;
  }
  chain.doFilter(req, res);
}
```

Constructor-inject: `JwtPort`, `AuthenticationEntryPoint` (will be wired by SecurityConfig below).

### SecurityConfig overhaul

Changes to existing `SecurityConfig.java`:

1. **Remove** `.httpBasic(Customizer.withDefaults())`.
2. **Add** `JwtAuthenticationFilter` and `AuthenticationEntryPoint` as constructor args.
3. **Add** `.addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)` — unconditional (feature-flag-independent; harmless no-op when no token is issued).
4. **Extend** permit-all list:
```java
.requestMatchers(
    "/actuator/health/**", "/actuator/info",
    "/v3/api-docs/**", "/swagger-ui/**", "/swagger-ui.html",
    "/api/v1/auth/register", "/api/v1/auth/verify-email", "/api/v1/auth/resend-verification",
    "/api/v1/auth/login", "/api/v1/auth/refresh", "/api/v1/auth/logout",
    "/.well-known/jwks.json").permitAll()
```
5. **Add** `.exceptionHandling(e -> e.authenticationEntryPoint(jwtAuthenticationEntryPoint()).accessDeniedHandler(accessDeniedHandler()))`.
6. **Define** `AuthenticationEntryPoint` bean returning 401 RFC 7807 `AUTH_003` (writes problem-document JSON directly, no redirect).
7. **Update CORS:** Add `/.well-known/**` to `UrlBasedCorsConfigurationSource`; set `cfg.setAllowCredentials(true)`; add `Set-Cookie` to `exposedHeaders`.

### GlobalExceptionHandler additions

Add BEFORE the `DomainException` catch-all (handler precedence):
```java
@ExceptionHandler(AuthenticationException.class)
ResponseEntity<ProblemDetail> handleAuthentication(AuthenticationException e) {
  return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
      .body(problem(HttpStatus.UNAUTHORIZED, e.code(), e.getMessage()));
}

@ExceptionHandler(AccountNotVerifiedException.class)
ProblemDetail handleAccountNotVerified(AccountNotVerifiedException e) {
  return problem(HttpStatus.FORBIDDEN, e.code(), e.getMessage());
}
```

**Testing:** After this task run `./mvnw verify` (full, with Testcontainers). All existing registration IT tests must still pass. 401 response must NOT contain `WWW-Authenticate: Basic`.  
**Definition of Done:** HTTP Basic removed from chain. `JwtAuthenticationFilter` registered unconditionally. `AuthenticationException` → 401 (not 422). `AccountNotVerifiedException` → 403 (not 422). CORS `allowCredentials(true)` + `Set-Cookie` exposed.

---

## IMPL-10 — Controllers + DTOs (T-020, T-021)

**What gets built:** Three controllers (login/refresh/logout, JWKS, /users/me) and five DTOs. All gated by `@ConditionalOnProperty("feature.nexus-us003-auth-login.enabled")`.

**Files created:**
- `nexus-backend/src/main/java/com/example/nexus/identity/interfaces/rest/LoginController.java`
- `nexus-backend/src/main/java/com/example/nexus/identity/interfaces/rest/JwksController.java`
- `nexus-backend/src/main/java/com/example/nexus/identity/interfaces/rest/UserProfileController.java`
- `nexus-backend/src/main/java/com/example/nexus/identity/interfaces/rest/dto/LoginRequest.java`
- `nexus-backend/src/main/java/com/example/nexus/identity/interfaces/rest/dto/LoginResponse.java`
- `nexus-backend/src/main/java/com/example/nexus/identity/interfaces/rest/dto/MeResponse.java`

### DTOs

```java
// LoginRequest.java
public record LoginRequest(
    @Email @NotBlank @Size(max = 254) String email,
    @NotBlank @Size(max = 256) String password
) {}

// LoginResponse.java
public record LoginResponse(String accessToken, String tokenType, long expiresIn, String userId) {}

// MeResponse.java
public record MeResponse(String userId, boolean emailVerified, String tenantId,
                         List<String> roles, int tokenVersion) {}
```

### LoginController

`@RestController @RequestMapping("/api/v1/auth") @ConditionalOnProperty("feature.nexus-us003-auth-login.enabled")`

Constructor-inject: `LoginUseCase`, `RefreshTokenUseCase`, `AuthEventPort`, `UuidGenerator`.

```java
@PostMapping("/login")
ResponseEntity<LoginResponse> login(@Valid @RequestBody LoginRequest req, HttpServletRequest request) {
  LoginResult result = loginUseCase.execute(req.email(), req.password(), request.getRemoteAddr());
  return ResponseEntity.ok()
      .header(HttpHeaders.SET_COOKIE, buildRefreshCookie(result.rawRefreshToken(), 1_209_600L).toString())
      .body(new LoginResponse(result.accessToken(), "Bearer", result.expiresInSeconds(), result.userId()));
}

@PostMapping("/refresh")
ResponseEntity<LoginResponse> refresh(
    @CookieValue(value = "refresh_token", required = false) String cookieValue,
    HttpServletRequest request) {
  if (cookieValue == null) throw new AuthenticationException("AUTH_004", "Refresh token invalid");
  LoginResult result = refreshTokenUseCase.execute(cookieValue, request.getRemoteAddr());
  return ResponseEntity.ok()
      .header(HttpHeaders.SET_COOKIE, buildRefreshCookie(result.rawRefreshToken(), 1_209_600L).toString())
      .body(new LoginResponse(result.accessToken(), "Bearer", result.expiresInSeconds(), result.userId()));
}

@PostMapping("/logout")
ResponseEntity<Void> logout(HttpServletRequest request) {
  Authentication auth = SecurityContextHolder.getContext().getAuthentication();
  UUID userId = (auth != null && auth.isAuthenticated() && auth.getPrincipal() instanceof String s)
      ? UUID.fromString(s) : null;
  authEventPort.record(new AuthEvent(uuidGenerator.generate(), "LOGOUT", "SUCCESS")
      .withUserId(userId).withIpAddress(request.getRemoteAddr()));
  ResponseCookie clear = ResponseCookie.from("refresh_token", "")
      .httpOnly(true).secure(true).sameSite("Strict").path("/api/v1/auth").maxAge(0).build();
  return ResponseEntity.noContent().header(HttpHeaders.SET_COOKIE, clear.toString()).build();
}

private ResponseCookie buildRefreshCookie(String raw, long maxAge) {
  return ResponseCookie.from("refresh_token", raw)
      .httpOnly(true).secure(true).sameSite("Strict").path("/api/v1/auth").maxAge(maxAge).build();
}
```

**Cookie path:** `/api/v1/auth` — the browser only sends the cookie to requests under this path.

### JwksController

```java
@RestController
@ConditionalOnProperty("feature.nexus-us003-auth-login.enabled")
public class JwksController {
  @GetMapping(value = "/.well-known/jwks.json", produces = MediaType.APPLICATION_JSON_VALUE)
  ResponseEntity<Map<String, Object>> jwks() {
    return ResponseEntity.ok()
        .cacheControl(CacheControl.maxAge(3600, TimeUnit.SECONDS))
        .body(jwkSetPort.getPublicKeySet());
  }
}
```

### UserProfileController

```java
@RestController @RequestMapping("/api/v1/users")
@ConditionalOnProperty("feature.nexus-us003-auth-login.enabled")
public class UserProfileController {
  @GetMapping("/me")
  MeResponse me(Authentication authentication) {
    Map<?, ?> details = (Map<?, ?>) authentication.getDetails();
    return new MeResponse(
        (String) authentication.getPrincipal(),
        (Boolean) details.getOrDefault("emailVerified", false),
        (String) details.get("tenantId"),
        authentication.getAuthorities().stream()
            .map(a -> a.getAuthority().replace("ROLE_", "")).toList(),
        ((Number) details.getOrDefault("tokenVersion", 0)).intValue()
    );
  }
}
```

All values read from JWT claims stashed in `authentication.getDetails()` by `JwtAuthenticationFilter` — no DB call this sprint.

**Testing:** MockMvc: login happy path → 200 + access token + `Set-Cookie`; refresh → 200 + rotated cookie; logout → 204 + `Max-Age=0`; missing cookie on refresh → 401; `/users/me` without token → 401; JWKS JSON contains `kty/use/alg/kid/n/e` only.  
**Definition of Done:** Raw refresh token never in response body. LOGOUT audit event recorded. All three controllers gated by feature flag.

---

## IMPL-11 — Frontend Core Auth (T-022 through T-025)

**What gets built:** `AuthStore` (signal-based in-memory state), `AuthService` additions (login/refresh/logout), `AuthInterceptor` (Bearer + 401 retry), `AuthGuard` (functional).

**Files created:**
- `nexus-frontend/src/app/core/auth/auth.store.ts`
- `nexus-frontend/src/app/core/auth/auth.store.spec.ts`
- `nexus-frontend/src/app/core/auth/auth.guard.ts`
- `nexus-frontend/src/app/core/auth/auth.guard.spec.ts`
- `nexus-frontend/src/app/core/http/auth.interceptor.ts`
- `nexus-frontend/src/app/core/http/auth.interceptor.spec.ts`

**Files modified:**
- `nexus-frontend/src/app/features/auth/auth.service.ts`
- `nexus-frontend/src/app/features/auth/auth.service.spec.ts`
- `nexus-frontend/src/app/app.config.ts`

### AuthStore (auth.store.ts)

```typescript
@Injectable({ providedIn: 'root' })
export class AuthStore {
  private readonly _accessToken = signal<string | null>(null);
  private readonly _userId = signal<string | null>(null);
  private readonly _expiresAt = signal<number | null>(null);

  readonly accessToken = this._accessToken.asReadonly();
  readonly userId = this._userId.asReadonly();
  readonly isAuthenticated = computed(() => {
    const token = this._accessToken();
    const exp = this._expiresAt();
    return token !== null && exp !== null && exp > Math.floor(Date.now() / 1000);
  });

  setTokens(accessToken: string, expiresIn: number, userId: string): void {
    this._accessToken.set(accessToken);
    this._userId.set(userId);
    this._expiresAt.set(Math.floor(Date.now() / 1000) + expiresIn);
  }

  clear(): void {
    this._accessToken.set(null);
    this._userId.set(null);
    this._expiresAt.set(null);
  }
}
```

**NEVER** use `localStorage`, `sessionStorage`, or `document.cookie`. In-memory only.

### AuthService additions

Add `LoginResponse` interface and three methods. Inject `AuthStore`:

```typescript
interface LoginResponse { accessToken: string; tokenType: string; expiresIn: number; userId: string; }

login(email: string, password: string): Observable<void> {
  return this.http.post<LoginResponse>(`${this.base}/login`, { email, password },
    { withCredentials: true }
  ).pipe(tap(r => this.authStore.setTokens(r.accessToken, r.expiresIn, r.userId)), map(() => undefined));
}

refresh(): Observable<void> {
  return this.http.post<LoginResponse>(`${this.base}/refresh`, {}, { withCredentials: true })
    .pipe(tap(r => this.authStore.setTokens(r.accessToken, r.expiresIn, r.userId)), map(() => undefined));
}

logout(): Observable<void> {
  return this.http.post<void>(`${this.base}/logout`, {}, { withCredentials: true })
    .pipe(tap(() => this.authStore.clear()), map(() => undefined));
}
```

### AuthInterceptor (auth.interceptor.ts)

Module-level singleton for in-flight refresh guard (no thundering herd):
```typescript
let refreshInFlight$: Observable<void> | null = null;
```

```typescript
export const authInterceptor: HttpInterceptorFn = (req, next) => {
  const authStore = inject(AuthStore);
  const authService = inject(AuthService);
  const router = inject(Router);

  const token = authStore.accessToken();
  const isApiCall = req.url.includes('/api/v1/');
  const isAuthEndpoint = req.url.includes('/api/v1/auth/');

  const outgoing = (token && isApiCall && !isAuthEndpoint)
    ? req.clone({ setHeaders: { Authorization: `Bearer ${token}` } })
    : req;

  return next(outgoing).pipe(
    catchError((err: HttpErrorResponse) => {
      if (err.status === 401 && isApiCall && !isAuthEndpoint) {
        if (!refreshInFlight$) {
          refreshInFlight$ = authService.refresh().pipe(
            share(),
            finalize(() => { refreshInFlight$ = null; })
          );
        }
        return refreshInFlight$.pipe(
          switchMap(() => {
            const newToken = authStore.accessToken();
            const retried = newToken
              ? req.clone({ setHeaders: { Authorization: `Bearer ${newToken}` } })
              : req;
            return next(retried);
          }),
          catchError(() => {
            authService.logout().subscribe();
            router.navigate(['/auth/login']);
            return throwError(() => err);
          })
        );
      }
      return throwError(() => err);
    })
  );
};
```

Register in `app.config.ts`: `withInterceptors([correlationIdInterceptor, authInterceptor, apiErrorInterceptor])` — auth interceptor AFTER correlation-id, BEFORE api-error.

### AuthGuard (auth.guard.ts)

```typescript
export const authGuard: CanActivateFn = () => {
  const authStore = inject(AuthStore);
  const router = inject(Router);
  return authStore.isAuthenticated() ? true : router.createUrlTree(['/auth/login']);
};
```

**Testing:**  
- `AuthStore`: `isAuthenticated` false on init; `setTokens` + future exp → true; past exp → false; `clear()` → false.  
- `AuthService`: `login` → `setTokens` called; `logout` → `clear()` called.  
- `AuthInterceptor`: valid token → `Authorization` header attached; 401 → refresh once; refresh fails → logout + redirect; concurrent 401s → one refresh call (no thundering herd).  
- `AuthGuard`: authenticated → `true`; not authenticated → `UrlTree('/auth/login')`.

**Definition of Done:** All unit tests pass. No `localStorage`/`sessionStorage` references. Auth endpoints excluded from bearer header attachment. `refreshInFlight$` reset via `finalize`.

---

## IMPL-12 — LoginFormComponent + Route Wiring (T-026, T-027)

**What gets built:** Standalone `LoginFormComponent` (OnPush, signals, reactive form) and routing configuration.

**Files created:**
- `nexus-frontend/src/app/features/auth/login-form/login-form.component.ts`
- `nexus-frontend/src/app/features/auth/login-form/login-form.component.spec.ts`

**Files modified:**
- `nexus-frontend/src/app/features/auth/auth.routes.ts`

### LoginFormComponent

```typescript
@Component({
  selector: 'nx-login-form',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [ReactiveFormsModule, NxInput, NxButton, NxCard, RouterLink],
  template: `<!-- use NxCard wrapper, NxInput fields, NxButton submit, error display -->`
})
export class LoginFormComponent {
  private readonly authService = inject(AuthService);
  private readonly router = inject(Router);

  readonly loading = signal(false);
  readonly errorMessage = signal<string | null>(null);

  readonly form = new FormGroup({
    email: new FormControl('', [Validators.required, Validators.email, Validators.maxLength(254)]),
    password: new FormControl('', [Validators.required, Validators.maxLength(256)])
  });

  submit(): void {
    if (this.form.invalid || this.loading()) return;
    this.loading.set(true);
    this.errorMessage.set(null);
    const { email, password } = this.form.getRawValue();
    this.authService.login(email!, password!).subscribe({
      next: () => this.router.navigate(['/dashboard']),
      error: (err: AppError) => {
        this.loading.set(false);
        switch (err.code) {
          case 'AUTH_001': this.errorMessage.set('Invalid email or password.'); break;
          case 'AUTH_002': this.errorMessage.set('Please verify your email before logging in.'); break;
          case 'RATE_001': this.errorMessage.set('Too many attempts. Please try again later.'); break;
          default: this.errorMessage.set('An unexpected error occurred. Please try again.');
        }
      }
    });
  }
}
```

Error handler receives `AppError` (normalised by `apiErrorInterceptor`) — never `HttpErrorResponse`.

### auth.routes.ts addition

```typescript
{
  path: 'login',
  loadComponent: () =>
    import('./login-form/login-form.component').then(m => m.LoginFormComponent),
},
```

**Testing:** (1) valid submit → `authService.login()` called; (2) `AUTH_001` → correct message; (3) `AUTH_002` → resend prompt; (4) `RATE_001` → rate limit message; (5) `loading` true during submit, false after error.  
**Definition of Done:** Standalone, OnPush. No `HttpErrorResponse` reference. `npm run test:ci` + `npm run lint` green.

---

## IMPL-13 — Backend Security Unit Tests (T-028, T-029, T-034)

**What gets built:** Three test classes covering JWT algorithm attacks, anti-enumeration ordering, key security — no Spring context, pure unit tests.

**Files created:**
- `nexus-backend/src/test/java/com/example/nexus/identity/infrastructure/security/JwtRs256ServiceSecurityTest.java`
- `nexus-backend/src/test/java/com/example/nexus/identity/application/service/LoginUseCaseSecurityTest.java`
- `nexus-backend/src/test/java/com/example/nexus/identity/infrastructure/security/RsaKeyConfigSecurityTest.java`

### JwtRs256ServiceSecurityTest (T-028)

| Test | Threat | Expected |
|------|--------|----------|
| `alg_none_token_rejected` | T-3.1 | Manually craft `alg=none` token → `AuthenticationException(AUTH_003)` |
| `hs256_confusion_rejected` | T-3.2 | HMAC-sign with public-key bytes as secret → `AuthenticationException` |
| `foreign_rsa_key_rejected` | T-3.3 | Sign with a second generated RSA key → `AuthenticationException` |
| `tampered_tenant_id_rejected` | T-3.4 | Decode body, alter `tenant_id`, re-encode without re-signing → `AuthenticationException` |
| `tampered_roles_rejected` | T-3.4 | Same — alter `roles` |
| `expired_token_rejected` | T-3.5 | Clock 30min past (beyond 30s skew) → `AuthenticationException` |
| `within_skew_boundary_accepted` | T-3.5 | Clock 25s behind real-time → accepted |
| `jwks_contains_no_private_fields` | T-1.6 | `JwkSetAdapter.getPublicKeySet()` map has no `d`/`p`/`q` keys |
| `issue_verify_roundtrip` | — | `verify(issue(user).token())` → claims match |

### LoginUseCaseSecurityTest (T-029)

| Test | Threat | Expected |
|------|--------|----------|
| `unknown_email_returns_auth_001` | T-2.2 | Empty user → `AUTH_001` |
| `wrong_password_returns_auth_001` | T-2.2 | User found, mismatch → `AUTH_001` |
| `wrong_password_on_pending_returns_auth_001` | T-2.3 | PENDING user, mismatch → `AUTH_001` (NOT 403) |
| `correct_password_on_pending_returns_auth_002` | T-2.3 | PENDING user, match → `AccountNotVerifiedException(AUTH_002)` |
| `locked_account_returns_auth_001` | T-2.5 | LOCKED, correct pw → `AUTH_001` |
| `disabled_account_returns_auth_001` | T-2.5 | DISABLED, correct pw → `AUTH_001` |
| `active_account_succeeds` | — | ACTIVE, correct pw → `LoginResult` |
| `rate_limit_blocks_before_argon2` | T-1.7 | Rate limit rejected → `passwordVerifier.matches` NOT called (verify mock) |
| `argon2_called_on_unknown_email` | T-2.2 | `!found` → `passwordVerifier.matches(_, dummyHash)` called (verify mock invocation) |
| `oversized_password_validation_400` | T-2.1 | MockMvc: `password` of 257 chars → 400 with `details[]` before use-case is called |

### RsaKeyConfigSecurityTest (T-034)

| Test | Covers |
|------|--------|
| `prod_profile_blank_key_fails_fast` | T-5.1 → `IllegalStateException` |
| `key_below_2048_bit_rejected` | T-5.1 → `IllegalArgumentException` |
| `ephemeral_key_in_dev_profile` | T-5.4 → key generated, modulus ≥ 2048 bit |
| `toString_does_not_expose_pem` | T-5.2 → no "BEGIN" in `toString()` output |
| `private_key_not_in_actuator_env` | T-5.2 → actuator `/env` response has no `privateKeyPem` value |
| `rate_store_bounded_on_key_flood` | T-6.2 → flood 5000 keys; `store.size() == 0` after windows expire |

**Definition of Done:** All 25 unit tests pass. No Spring context required. Tests run in `./mvnw verify -DskipITs`.

---

## IMPL-14 — Integration Tests: Rate Limit + Rotation + Audit (T-030, T-031, T-035)

**What gets built:** Three IT test classes using Testcontainers MySQL.

**Files created:**
- `nexus-backend/src/test/java/com/example/nexus/identity/infrastructure/security/RateLimitIT.java`
- `nexus-backend/src/test/java/com/example/nexus/identity/application/service/RefreshTokenRotationIT.java`
- `nexus-backend/src/test/java/com/example/nexus/identity/application/service/AuthAuditIT.java`

### RateLimitIT (T-030)

| Test | Covers |
|------|--------|
| `login_rate_limit_by_ip` | 5 failed attempts same IP → 6th → 429 + `Retry-After` |
| `login_rate_limit_by_username` | 5 failed attempts same email, 5 IPs → 6th → 429 |
| `rate_limit_resets_after_window` | 5 attempts; advance test Clock past window; next → allowed |
| `spoof_xff_does_not_bypass_ip_limit` | `X-Forwarded-For` spoofed; counter still increments on `getRemoteAddr()` |
| `refresh_throttle_per_ip` | 30 refresh attempts → 31st → 429 |
| `different_ips_have_independent_counters` | IP-A attempts do not affect IP-B |
| `store_bounded_on_key_flood` | 5000 distinct IP logins; no OOM; `store.size()` bounded |

### RefreshTokenRotationIT (T-031)

| Test | Covers | Threat |
|------|--------|--------|
| `happy_path_rotation` | Login → refresh → new pair; old token rejected | T-4.1 |
| `reused_revoked_token_revokes_family` | Rotate; present first token again → `REFRESH_FAMILY_REVOKED` audit + `AUTH_004` | T-4.1 |
| `expired_token_rejected` | Token with past `expiresAt` → `AUTH_004` | T-4.1 |
| `concurrent_rotation_single_winner` | Two threads present same token simultaneously → exactly 1 succeeds; loser → `AUTH_004` | T-4.2 |
| `cross_tenant_isolation` | Tenant A user refresh → JWT has tenant A `tenant_id`; no bleed from tenant B | T-4.4 |

Concurrency test uses `CountDownLatch` + `ExecutorService`; both threads join before assertion.

### AuthAuditIT (T-035)

| Test | Covers | Threat |
|------|--------|--------|
| `login_success_emits_event` | `auth_events` row `LOGIN_SUCCESS` after login | T-7.1 |
| `login_failure_emits_event` | Bad creds → `LOGIN_FAILURE` row | T-7.1 |
| `login_pending_emits_event` | PENDING account → `LOGIN_PENDING_ACCOUNT` row | T-7.1 |
| `refresh_success_emits_event` | Rotation → `TOKEN_REFRESH_SUCCESS` | T-7.1 |
| `refresh_family_revoke_emits_event` | Reused token → `REFRESH_FAMILY_REVOKED` | T-7.1 |
| `logout_emits_event` | POST `/auth/logout` → `LOGOUT` row in `auth_events` | T-7.1 |
| `no_raw_token_in_logs` | Capture SLF4J output during login; assert no 64-char hex string and no full `email@domain` in WARN/INFO lines | T-7.4 |

**Definition of Done:** All 19 IT tests pass with Testcontainers MySQL. `./mvnw verify` (full) green.

---

## IMPL-15 — SecurityConfig IT + JWT Contract Test + Docs (T-032, T-033, T-036, T-037)

**What gets built:** SecurityConfig integration tests, the CI-enforced JWT claims contract test, load test plan document, and ADR-0007.

**Files created:**
- `nexus-backend/src/test/java/com/example/nexus/config/SecurityConfigIT.java`
- `nexus-backend/src/test/java/com/example/nexus/identity/infrastructure/security/JwtClaimsContractTest.java`
- `docs/features/US-003/load-test-plan.md`
- `docs/adr/0007-jwt-library-jjwt-not-resource-server.md`

### SecurityConfigIT (T-032)

| Test | Covers | Threat |
|------|--------|--------|
| `protected_endpoint_without_token_returns_401` | GET `/api/v1/users/me` → 401 body with `code=AUTH_003` (not 422) | T-3.8 |
| `arbitrary_protected_path_returns_401` | GET `/api/v1/unknown-path` → 401 (default-deny) | T-3.8 |
| `public_paths_not_blocked` | login/refresh/logout/jwks/register/verify-email → not 401 | — |
| `login_cookie_attributes` | Login success → `Set-Cookie` has `HttpOnly`, `Secure`, `SameSite=Strict`, `Path=/api/v1/auth`, `Max-Age=1209600` | T-1.4 |
| `logout_clears_cookie_max_age_0` | Logout → `Set-Cookie` `Max-Age=0` same attributes | T-1.4 |
| `cors_exposes_set_cookie` | CORS preflight on `/auth/login` → `Access-Control-Expose-Headers` includes `Set-Cookie` | T-1.5 |
| `cors_allows_credentials` | CORS preflight → `Access-Control-Allow-Credentials: true` | T-1.5 |
| `expired_jwt_returns_401_not_500` | Expired Bearer token → 401 `AUTH_003` | T-3.5 |
| `http_basic_removed` | 401 response has no `WWW-Authenticate: Basic` header | §6 |

### JwtClaimsContractTest (T-033) — CI freeze gate

```java
@Test
void issued_token_matches_frozen_contract() {
  AccessTokenResult result = jwtRs256Service.issue(testActiveUser);
  Claims claims = Jwts.parser().verifyWith(publicKey).build()
      .parseSignedClaims(result.token()).getPayload();

  // Exactly these 8 claims, no more, no less
  assertThat(claims.keySet()).containsExactlyInAnyOrder(
      "sub","tenant_id","email_verified","roles","iat","exp","jti","token_version");
  assertThat(claims).doesNotContainKeys("email","name","given_name"); // no PII (T-7.5)
  assertThat(claims.get("roles", List.class)).containsExactly("USER");
  assertThat(claims.get("email_verified", Boolean.class)).isTrue();
  assertThat(claims.get("token_version", Integer.class)).isEqualTo(0);

  long exp = claims.getExpiration().toInstant().getEpochSecond();
  long iat = claims.getIssuedAt().toInstant().getEpochSecond();
  assertThat(exp - iat).isEqualTo(900L);

  // Header shape is also frozen
  assertThat(claims.getHeader().getAlgorithm()).isEqualTo("RS256");
  assertThat(claims.getHeader().get("kid")).isNotNull();
  assertThat(claims.getHeader().get("typ")).isEqualTo("JWT");
}
```

Adding any new claim (e.g., `email`) causes this test to fail — that is the intended freeze-gate behaviour.

### ADR-0007 (T-037)

`docs/adr/0007-jwt-library-jjwt-not-resource-server.md`:
- **Status:** Accepted
- **Context:** US-003 needs JWT issuance + narrow verification within a custom `SecurityFilterChain` (RFC 7807 `AuthenticationEntryPoint`).
- **Decision:** JJWT 0.12.6 (`jjwt-api`/`impl`/`jackson`). NOT `spring-boot-starter-oauth2-resource-server`.
- **Rationale:** Resource-server starter autoconfigures `BearerTokenAuthenticationFilter` + `JwtDecoder` that collide with the hand-built chain. JJWT is issuance-first; surface smaller; algorithm allowlist explicit; zero bean conflicts.
- **Consequences:** Key rotation managed manually (no external JWKS fetch). Revisit if Nexus becomes a pure resource server behind an IdP.

### Load test plan (T-036)

`docs/features/US-003/load-test-plan.md`:
- Tool: k6 (preferred) or Gatling.
- Scenario: ramp to 100 RPS over 60s; sustain 10 min; target `POST /api/v1/auth/login` (pre-seeded ACTIVE users).
- Assertions: p95 < 300ms; p99 < 500ms.
- Config: set `max-attempts=10000` in load-test env to avoid rate-limiter interfering with the test; use distinct pre-hashed users.
- Note: Argon2 params MUST match production (not dev) for meaningful results.

**Definition of Done:** All 9 SecurityConfig IT tests pass. Contract test fails if a new claim is added to `issue()`. ADR and load-test-plan documents created following existing format.

---

## Task summary (consolidated)

| IMPL | Original T-IDs | Title | Complexity |
|------|----------------|-------|------------|
| IMPL-01 | T-001, T-002 | Dependencies + Configuration | S |
| IMPL-02 | T-003–T-008 | Domain layer + Port interfaces | M |
| IMPL-03 | T-010, T-012 | RsaKeyConfig + PasswordVerifierAdapter | M |
| IMPL-04 | T-011 | JwtRs256Service + JwkSetAdapter | M |
| IMPL-05 | T-014 | InMemoryRateLimitStore | M |
| IMPL-06 | T-013 | JpaRefreshTokenRepository + JpaRefreshTokenAdapter | M |
| IMPL-07 | T-015 | LoginUseCase ⚠ highest-risk | L |
| IMPL-08 | T-016 | RefreshTokenUseCase | M |
| IMPL-09 | T-017, T-018, T-019 | Filters + SecurityConfig + GlobalExceptionHandler ⚠ blast-radius | M |
| IMPL-10 | T-020, T-021 | All 3 controllers + 5 DTOs | M |
| IMPL-11 | T-022–T-025 | Frontend core (AuthStore + AuthService++ + AuthInterceptor + AuthGuard) | M |
| IMPL-12 | T-026, T-027 | LoginFormComponent + route wiring | M |
| IMPL-13 | T-028, T-029, T-034 | Backend security unit tests | M |
| IMPL-14 | T-030, T-031, T-035 | Integration tests (Testcontainers) | L |
| IMPL-15 | T-032, T-033, T-036, T-037 | SecurityConfig IT + contract test + docs | M |

**36 tasks → 15 implementation sessions.**

---

*Gate 3 APPROVED. Start with `/implement US-003 IMPL-01`.*
