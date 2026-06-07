# Coding Standards — Nexus

## Naming

### Java
- Classes: `UpperCamelCase` — `UserService`, `PasswordResetToken`
- Methods / variables: `lowerCamelCase` — `findByEmail`, `tokenHash`
- Constants: `UPPER_SNAKE_CASE`
- Packages: `lowercase.dots` — `com.nexus.auth.application`
- Test classes: `<Subject>Test` — `PasswordResetServiceTest`
- Test methods: `should_<expected>_when_<condition>` — `should_returnEmpty_when_tokenExpired`
- Exceptions: name the cause — `TokenExpiredException`, not `PasswordResetException`
- Interfaces for ports: noun of capability — `EmailPort`, `UserRepository`
- Implementations: `Jpa<X>`, `<Provider><X>` — `JpaUserRepository`, `SmtpEmailAdapter`

### TypeScript / Angular
- Components: `UpperCamelCase` class, `nx-kebab-case` selector
- Services: `UpperCamelCase` ending in `Service` — `AuthService`, `UserService`
- Interfaces / types: `UpperCamelCase` — `User`, `ApiError`
- Constants: `UPPER_SNAKE_CASE` for module-level, `lowerCamelCase` for local
- Files: `kebab-case.purpose.ts` — `user-card.component.ts`, `auth.service.ts`
- Specs: `*.spec.ts` in same directory as source

### Database
- Tables: `snake_case`, plural — `users`, `password_reset_tokens`
- Columns: `snake_case` — `created_at`, `token_hash`
- Indexes: `idx_<table>_<columns>` — `idx_users_email`
- Foreign keys: `fk_<from_table>_<to_table>` — `fk_orders_users`
- Primary keys: `id` (prefer CHAR(26) ULID for distributed contexts)

---

## Formatting

### Java
- Configured via Spotless in `pom.xml` (Google Java Format style, if configured).
- Else: 4-space indent, no tabs, 120-char line limit.
- Blank line between class members, after every logical section in a method.
- Run the format-and-lint hook or `./mvnw spotless:apply` before committing.

### TypeScript
- Prettier is configured in `package.json`: 100-char line width, single quotes, Angular HTML parser.
- Run `npm run format` (or Prettier on save in your IDE) — the hook calls it automatically after every write.
- Do not commit code with Prettier violations. CI enforces this.

---

## Comments

Good code needs few comments. Comments explain *why*, not *what*.

```java
// BAD: comment repeats the code
// Check if the token is expired
if (token.expiresAt().isBefore(Instant.now())) { ... }

// GOOD: comment explains the business intent
// Expired tokens must never transition to USED — prevents replay of a partially-consumed link
if (token.isExpired()) {
    throw new TokenExpiredException(token.id());
}
```

- Javadoc on public interfaces and port definitions — explain contracts, not implementations.
- No TODO/FIXME in committed code. Open a Jira ticket instead.
- No commented-out code — git history handles that.

---

## Error Handling

### Java
- Throw domain exceptions — `UserNotFoundException`, `TokenExpiredException`.
- Catch at the application layer or in `@RestControllerAdvice`. Never swallow silently.
- Every `catch(Exception e)` must either rethrow (with context) or log + rethrow.
- Include context in exceptions: `throw new TokenExpiredException("token=" + tokenId)`.

### TypeScript
- Services transform HTTP errors to typed `AppError` objects before returning to components.
- Components show user-friendly messages; they never inspect HTTP status codes directly.
- Use discriminated union state (`Loading | Success<T> | Failure`) — no `isLoading: boolean` + `error: string | null` pairs.

---

## Logging

- **Level discipline:**
  - `ERROR` — unexpected failures requiring investigation. Always includes exception.
  - `WARN` — expected but notable events (failed login, rate limit hit, deprecated call).
  - `INFO` — significant business events (user created, order placed, payment confirmed).
  - `DEBUG` — developer-useful internals (query params, intermediate state). Off in prod.
  - `TRACE` — granular execution path. Almost never in production.
- **Structured key=value:** `log.info("token issued userId={} expiry={}", userId, expiry)`.
- **Never log:** passwords, raw tokens, full credit cards, SSN, email bodies, full request bodies.
- **MDC fields:** `traceId`, `userId`, `tenantId` set in a filter at request entry. Clear in `finally`.
- **TypeScript:** use a logger service (wraps `console`) with the same level discipline. No bare `console.log` in committed code.

---

## Dependency Management

Before adding a new dependency, verify:
1. **License** is compatible (Apache 2.0, MIT, BSD are safe; GPL needs review).
2. **CVE status** — check with `./mvnw dependency:tree` + OWASP dependency-check, or `npm audit`.
3. **Maintenance** — last commit within 12 months, active issue tracker.
4. **Need** — can the existing stack do this? Don't reach for a library for one utility function.

Pin all dependency versions in `pom.xml` and `package.json`. Never use version ranges in production.

---

## Configuration

- All config in `nexus-backend/src/main/resources/application.yml` (or profile variants).
- Environment-specific values via `${ENV_VAR_NAME:defaultValue}` — never hardcoded credentials.
- No secrets in `application.yml` — use environment variables or Vault.
- New config keys must be documented with a comment in the YAML file.

---

## Concurrency

- Prefer stateless services. Avoid shared mutable state.
- Optimistic locking via `@Version` on entities subject to concurrent writes.
- Use `@Transactional(isolation = SERIALIZABLE)` sparingly — document the reason.
- Long-running tasks → async job (don't block request threads).
- Do not use `synchronized` in application code without explicit justification in a comment.

---

## Version Control

### Branch naming
```
feature/NEXUS-1234-short-description
bugfix/NEXUS-1235-what-was-broken
hotfix/NEXUS-1236-critical-thing
chore/NEXUS-1237-update-dependencies
```

### Commit format (Conventional Commits)
```
<type>(<scope>): <short summary>

[optional body]
[optional footer: NEXUS-1234]
```

Types: `feat`, `fix`, `docs`, `test`, `refactor`, `chore`, `perf`, `security`.

Examples:
```
feat(auth): add password reset via email

- 60-minute single-use tokens
- Account enumeration prevention

NEXUS-1234
```
```
fix(users): correct null check in profile update validator
```

### PR rules
- One feature / bugfix per PR. No "while I was in there" changes.
- PR description: what, why, how to test, screenshots if UI.
- All checks green before requesting review.
- At least one approval required to merge to `main`.
- Squash merges preferred for features; merge commits for release branches.

### Code review etiquette
Comments are labelled:
- `[blocker]` — must fix before merge
- `[suggestion]` — strong recommendation, needs discussion to override
- `[nit]` — minor style or preference, reviewer won't block on it
- `[praise]` — good decision worth calling out

Reviewers respond within one business day. Authors respond within one business day.

---

## Performance

- Instrument before optimizing. Measure, don't guess.
- Lazy-load JPA associations by default. Use explicit JPQL joins where needed.
- No N+1 queries. Run `spring.jpa.show-sql=true` + check the count in tests.
- For read-heavy endpoints, consider a `@Query` projection that returns only needed columns.
- Frontend: `OnPush` by default. Prefer `@defer` for below-the-fold content.
- Bundle size: `npm run build -- --stats-json` and review if a feature adds >50 KB.

---

## Forbidden Patterns

| Pattern | Why | Alternative |
|---------|-----|-------------|
| Field injection (`@Autowired` on field) | Non-testable, hides dependencies | Constructor injection |
| `System.out.println` | Bypasses log config | SLF4J |
| `new Date()` / `System.currentTimeMillis()` | Not testable | `Clock` injected via Spring |
| Returning JPA entities from REST | Leaks schema, lazy-load traps | Response DTO |
| `catch (Exception e) {}` (swallow) | Silent failure | Log and rethrow |
| `any` in TypeScript | Defeats type safety | `unknown` + narrow |
| `*ngIf` / `*ngFor` | Angular 21 deprecated | `@if` / `@for` |
| `localStorage` in Angular | No SSR compat, XSS risk | `StorageService` abstraction |
| Hardcoded credentials | Security | Env var / Vault |
| H2 in tests | Doesn't match MySQL semantics | Testcontainers MySQL |
