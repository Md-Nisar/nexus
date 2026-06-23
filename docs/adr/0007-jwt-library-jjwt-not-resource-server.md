# ADR 0007 — JWT Library: JJWT 0.12.x Instead of spring-boot-starter-oauth2-resource-server

**Status:** Accepted
**Date:** 2026-06-22
**Author:** Engineering Team

## Context

US-003 introduces JWT-based stateless authentication. The backend must issue and verify RS256 JWTs,
expose a JWKS endpoint, and enforce a strict 8-claim contract with no PII. Two realistic options exist
for the Java/Spring Boot 4 implementation:

**Option A — `spring-boot-starter-oauth2-resource-server`**

Spring's OAuth2 resource-server starter provides `JwtDecoder`, auto-configured JWKS verification,
and tight Spring Security integration via `oauth2ResourceServer().jwt()`.

**Option B — JJWT 0.12.x (`io.jsonwebtoken:jjwt-*`)**

A battle-tested pure-Java JWT library. Requires implementing issuing (`JwtRs256Service`) and
verifying (`JwtPort`) manually, but gives explicit control over every header and claim.

## Options analysis

| Dimension | oauth2-resource-server | JJWT 0.12.x |
|-----------|----------------------|-------------|
| **Algorithm lock-in** | Auto-configures from JWKS; `alg` validated by the library but key-confusion requires explicit configuration care | `parserBuilder().verifyWith(publicKey)` rejects anything not signed by the exact key; explicit `alg=RS256` assertion in code enforces algorithm pinning (T-3.2) |
| **Claims contract** | Decodes all claims from the JWT; no out-of-box guard against unexpected PII claims being added silently | Claims freeze gate (`JwtClaimsContractTest`) fails the build if any claim is added — explicit enforcement |
| **JWKS endpoint** | Built-in `/oauth2/jwks` (path not customisable without override) | Custom `JwkSetAdapter` exposes `/.well-known/jwks.json`; private key fields (d, p, q…) excluded explicitly |
| **Issuing** | No built-in issuing support (resource-server only verifies) | `Jwts.builder()` issues directly; TTL, `kid`, `jti` all under our control |
| **Footprint** | Pulls in `spring-security-oauth2-resource-server`, `spring-security-oauth2-jose`, Nimbus JOSE JWT (~600 kB) | Three JJWT jars: `jjwt-api`, `jjwt-impl`, `jjwt-jackson` (~120 kB combined) |
| **External IdP / OIDC** | Natural fit — designed for trusting tokens from Keycloak, Auth0, etc. | Manual work if an external IdP is ever added |
| **Testability** | `JwtDecoder` can be mocked, but the auto-configuration makes it hard to assert exact claims without integration overhead | `JwtPort` interface + `JwtRs256Service` implementation — straightforward to unit-test with ephemeral RSA keys |
| **Complexity** | Low for standard OIDC; high if deviating from the happy path (custom claims, no-PII enforcement) | Higher boilerplate; low coupling |

## Decision

**Use JJWT 0.12.x** (`io.jsonwebtoken:jjwt-api:0.12.6`, `jjwt-impl`, `jjwt-jackson`).

Rationale:

1. **Nexus is an issuer, not just a verifier.** The resource-server starter provides no JWT-issuing
   support. JJWT covers both issuing and verifying from a single dependency set.

2. **No external IdP in scope.** The oauth2-resource-server starter's primary value is trusting tokens
   from a remote authorization server (Keycloak, Auth0). Nexus generates its own tokens; the starter
   adds Nimbus JOSE overhead with no corresponding benefit for this use case.

3. **Explicit algorithm pinning is simpler with JJWT.** `Jwts.parser().verifyWith(publicKey)` rejects
   any token not signed by the exact RSA key. The `alg=RS256` header assertion in `JwtRs256Service`
   provides defence-in-depth against algorithm-confusion attacks (T-3.2). Achieving the same level
   of explicit control with the resource-server requires non-trivial `JwtDecoder` customisation.

4. **Claims freeze gate requires a pure-parse path.** `JwtClaimsContractTest` inspects raw
   `Claims.keySet()` via `Jwts.parser()` — this test would require a full Spring context with the
   resource-server auto-configuration to achieve the equivalent. JJWT makes it a no-context unit test.

5. **PEM values are never in source.** Both approaches require key material. With JJWT, the
   ephemeral-key path (used in dev/smoke/test) generates a fresh RSA-2048 key pair at startup
   (`RsaKeyConfig`). Production supplies PEM via environment variables. No PEM appears in any
   checked-in file.

## Constraints adopted with this decision

- **No Redis / external token store.** JWTs are stateless; revocation is handled by short TTL (900 s)
  + refresh-token rotation (DB-backed, `jpa_refresh_tokens` table). If revocation SLA is tightened
  in future, a blocklist (Redis or DB) must be added — this ADR does not preclude it.
- **RS256 only.** HS256 and ES256 are excluded from the implementation. `JwtRs256Service` names
  the algorithm explicitly; adding another algorithm requires a new named service and a new ADR.
- **JJWT minor-version upgrades** must be reviewed for API changes before upgrading (JJWT 0.x
  is semver-sensitive at the minor level). The `<jjwt.version>` property in `pom.xml` pins the
  exact version.

## Consequences

- `JwtPort` interface (`identity.application.port.out`) abstracts the library — controllers and
  use-cases never import JJWT types.
- `JwkSetAdapter` explicitly strips private-key fields (`d`, `p`, `q`, `dp`, `dq`, `qi`) from the
  JWKS output before returning it (verified by `JwkSetAdapterTest`).
- `JwtClaimsContractTest` (`JwtClaimsContractTest.java`) fails the build if the 8-claim set changes,
  preventing silent PII leakage (T-7.5).
- If Nexus ever federates with an external OIDC provider, a second `JwtDecoder` bean using the
  resource-server starter may be introduced for that trust domain — this ADR governs only
  internally-issued tokens.
