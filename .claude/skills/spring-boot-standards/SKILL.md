---
name: spring-boot-standards
description: Use when writing or reviewing Spring Boot 4 / Java 25 code in the Nexus backend. Covers package layout, dependency injection, persistence, validation, error handling, logging, transactions, and security conventions.
---

# Spring Boot 4 Standards for Nexus

## Package layout (hexagonal)

```
com.example.nexus.<bounded-context>
├── domain/              # Entities, value objects, domain services, domain exceptions
├── application/         # Use-case services, ports (interfaces), DTOs internal to use cases
├── infrastructure/      # JPA repositories, external clients, port implementations
└── interfaces/
    ├── rest/            # @RestController, request/response DTOs
    └── events/          # Event listeners / publishers
```

- DTOs never cross layers. Domain objects stay in `domain`.
- `application` defines ports; `infrastructure` provides adapters.
- `interfaces` is the only layer that knows about HTTP.

## Java 25 idioms

- **Records** for DTOs and value objects.
- **Sealed interfaces** for closed type hierarchies (e.g., `sealed interface Result permits Success, Failure`).
- **Pattern matching** in `switch` for type-based dispatch.
- **Text blocks** for multi-line strings.
- Avoid `var` for public API surfaces; use it locally where the type is obvious.

## Dependency injection

- **Constructor injection only.** No field `@Autowired`, no setter injection.
- Use `final` fields. Lombok `@RequiredArgsConstructor` is acceptable.
- A class with more than 4 dependencies is a smell — split it.

## Web layer

- `@RestController` with `ResponseEntity<T>` returns for explicit status codes.
- Request DTOs validated with `@Valid` and bean validation annotations.
- Path / query params validated with `@Validated` on the controller.
- Map domain → response DTO in the controller; do not return entities.

```java
@PostMapping("/users")
public ResponseEntity<UserResponse> create(@Valid @RequestBody CreateUserRequest req) {
    User user = userService.create(req.toCommand());
    return ResponseEntity.status(CREATED).body(UserResponse.from(user));
}
```

## Persistence (JPA)

- Repositories extend `JpaRepository<Entity, ID>`.
- **No business logic in repositories.** Custom queries via `@Query` only for read-only projection.
- Add an index (in the Flyway migration, not `@Table(indexes = ...)`) for any column used in WHERE / ORDER BY / JOIN.
- **Eager fetching is opt-in.** Default to lazy. Use explicit fetch joins where needed.
- Use `@Version` for optimistic locking on entities subject to concurrent writes.
- Schema management: **Flyway owns the schema** (`ddl-auto=validate`, see ADR 0003). Migrations live in `src/main/resources/db/migration` as `V<N>__<description>.sql` — append-only, never edit an applied migration.
- Non-additive changes (rename, drop, type change) require:
  1. Two-step deploy plan (expand → contract)
  2. Explicit review in the design phase

## Transactions

- `@Transactional` lives on application services, **not** controllers, **not** repositories.
- Default to `@Transactional(readOnly = true)` on classes; override at write methods.
- Be explicit about propagation when chaining services.
- No long transactions — extract external calls outside the transaction boundary.

## Validation

- Bean validation on DTOs: `@NotBlank`, `@Size`, `@Email`, `@Positive`, etc.
- Custom validators implement `ConstraintValidator<Annotation, Type>`.
- Method-level validation with `@Validated` on classes whose methods take constrained primitives.

## Error handling

- Throw **domain exceptions**, not generic `RuntimeException`.
- Mapping is centralised in `common/web/GlobalExceptionHandler` (`@RestControllerAdvice`). Add a handler there; do not create a new advice or error DTO. Every handler returns a Spring `ProblemDetail` (wrapped in `ResponseEntity` only when it must set a header such as `Retry-After`) built with the private `problem(status, code, message)` helper, which adds the `code` and `traceId` properties:

```java
@ExceptionHandler(ResourceNotFoundException.class)
ProblemDetail handleNotFound(ResourceNotFoundException e) {
    logHandledException(e, LEVEL_DEBUG, e.code());
    return problem(HttpStatus.NOT_FOUND, e.code(), e.getMessage());
}
```

- Prefer extending an existing domain exception base (`ResourceNotFoundException`, `ConflictException`, `DomainException`, …) so no new handler is needed.
- Error shape and field list: see the `api-design` skill → Error format.
- Never expose stack traces in production responses.

## Logging

- SLF4J via `@Slf4j` (Lombok) or `LoggerFactory.getLogger(Class.class)`.
- Structured: use key-value logging.
  ```java
  log.info("user created userId={} email={}", user.id(), maskEmail(user.email()));
  ```
- Log at boundaries: entry to use case, exit, errors.
- **Never log:** passwords, tokens, full PII, full request bodies, secrets.
- Mask emails, partial-mask IDs in logs.
- MDC for `correlationId`, `userId`, `tenantId` — set in a filter, cleared in a finally block. `CorrelationIdFilter` owns `correlationId` (from/to the `X-Correlation-Id` header); `traceId` is a deprecated alias of it — don't use it in new code.

## Security

- All endpoints have explicit auth. Default-deny config:
  ```java
  http.authorizeHttpRequests(auth -> auth.anyRequest().authenticated());
  ```
- Method-level permission checks use `@RequiresPermission("resource:action")` — not raw `@PreAuthorize` — see `SECURITY.md` §3.1 for the usage pattern, the `RBAC_001` response shape, and the **Spring AOP self-invocation caveat** (annotated methods called from within the same bean are silently unenforced).
- Object-level checks for IDOR — never trust the client-provided owner ID.
- Use `SecureRandom`, never `Math.random`, for any security-sensitive randomness.
- Bean validation is **not** a security boundary. Always validate again at the service layer for sensitive operations.

## Resilience (outbound calls)

Every call that leaves the JVM — MySQL, Redis, SMTP, any HTTP client — must be bounded:

- **Explicit timeouts** on connect and read, set in `application.yml`, never the library default (often infinite). Redis is `spring.data.redis.timeout`; SMTP needs `mail.smtp.connectiontimeout`/`timeout`/`writetimeout`.
- **Failure mode is a design decision, per capability** — fail-open vs fail-closed is recorded in the design (see ADR 0016's per-capability table for Redis). Security decisions (authz, lockout, denylist) fail **closed**.
- **Retries** only for idempotent operations, bounded (≤ 3 attempts, exponential backoff with jitter), and never inside a DB transaction. Non-idempotent writes need an idempotency key (`api-design` skill).
- **No unbounded queues or buffers** in memory; a bounded buffer states what it drops and emits a metric when it does (ADR 0011 is the reference).
- Add a circuit breaker only when a dependency failure would otherwise exhaust request threads — record the choice in the design, don't add one by default.

## Pitfalls (each one has shipped in this codebase)

Framework behaviour that reads correctly in a diff and fails at runtime. Check every write path against this list.

- **`save()` doesn't run SQL for an entity already loaded in the transaction.** `@Version` conflicts and constraint violations surface at flush/commit — outside a `try/catch` around `save()`, as a 500. Call `flush()`/`saveAndFlush()` inside the `try` (`VerifyEmailUseCase`), or use a conditional UPDATE. *Seen in:* `RefreshTokenUseCase` rotation, `SecureEventService.persistFailedAttempt`.
- **State transitions and counters: one conditional UPDATE, not read-modify-write.** `UPDATE … SET revoked_at=? WHERE id=? AND revoked_at IS NULL` (0 rows = lost the race) or `SET n = n + 1`. Read-modify-write loses concurrent updates. *Model:* RBAC revoke in `JpaUserRoleRepository`.
- **JPQL bulk `UPDATE` bypasses `@Version`.** It does not fence a concurrent optimistic writer that already read the row; bump `version` in the same statement if the entity is versioned. *Seen in:* `JpaRefreshTokenRepository.revokeBy*`.
- **A row written before a `throw` inside `@Transactional` rolls back with it.** A failure-path audit must commit separately (`SecureEventService`) or after rollback. *Seen in:* `VerifyEmailUseCase` `VERIFICATION_FAILED`.
- **`REQUIRES_NEW` takes a second pooled connection while the outer one is held.** With virtual threads, request concurrency is unbounded, so N concurrent requests can deadlock the pool. Use it only for writes that must survive a rollback — never for success-path events, never while holding row locks. *Seen in:* `SecureEventService`, `RoleAssignmentService.recordDenial`.
- **Catching an exception from a `@Transactional` call doesn't rescue the outer transaction** — it is already rollback-only and fails at commit with `UnexpectedRollbackException`. A best-effort write needs its own `TransactionTemplate`, with the `try/catch` around `execute`. *Seen in:* `JpaAuthEventAdapter`.
- **No CPU-heavy work or outbound I/O inside a transaction.** Argon2, Redis, SMTP and HTTP calls hold the DB connection for their whole duration. *Seen in:* `LoginUseCase`, `JwtRs256Service.issue` → `RoleResolutionService`.
- **Check-then-insert is a race; the unique constraint is the guard.** `saveAndFlush` inside a `try` and map `DataIntegrityViolationException` to the domain outcome (`JpaUserRoleAssignmentAdapter`), or it escapes as a 500. *Seen in:* `RegisterUserUseCase`.
- **`save()` on an entity with an assigned id `merge`s** — a SELECT before every INSERT. Insert-only entities implement `Persistable<UUID>` with `isNew() = true`. *Seen in:* `AuthEvent`.
- **Several Redis commands are not atomic.** `DEL` + `SADD` + `EXPIRE` can leave a key with no TTL. Use one command (`SET key value EX ttl`) or a Lua script. *Seen in:* `RedisPermissionCacheAdapter.writeSet`.
- **In-memory per-key state is per instance and must be bounded.** Cap its size, evict each key on its own window, and remember limits multiply by replica count. *Seen in:* `InMemoryRateLimitStore` (60 s sweep applied to 900 s buckets).
- **Locking reads under REPEATABLE READ lock every index record they scan** — including revoked/historical rows. Make the index match the full predicate and select only the columns needed. *Seen in:* `JpaUserRoleRepository` (`FOR UPDATE` / `FOR SHARE` on `fk_user_roles_role`).
- **One clock.** Don't compare app-`Clock` bounds against a DB-defaulted `CURRENT_TIMESTAMP` column; set timestamps from the injected `Clock`.

## Testing

- **Unit:** plain JUnit 5 + Mockito. No Spring context.
- **Slice:** `@DataJpaTest`, `@WebMvcTest` for focused layer tests.
- **Integration:** `@SpringBootTest` + Testcontainers MySQL — not H2. H2 exists only for the `test`-profile context smoke test (`NexusBackendApplicationTests`).
- Naming: `should_<expected>_when_<condition>`.
- One logical assertion per test.

## Forbidden

- `System.out.println`, `e.printStackTrace()`
- Field injection (`@Autowired` on fields)
- Catching `Exception` without specific handling or re-throw
- Business logic in controllers
- Raw SQL outside repository layer
- `Optional` as method parameter (use overloads or `@Nullable`)
- Static mutable state
- Returning JPA entities from `@RestController`
