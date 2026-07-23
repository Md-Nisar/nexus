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
- Add indexes via `@Table(indexes = ...)` for any column used in WHERE / ORDER BY / JOIN.
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
- Centralise mapping in a `@RestControllerAdvice`:

```java
@RestControllerAdvice
class GlobalExceptionHandler {
    @ExceptionHandler(UserNotFoundException.class)
    ResponseEntity<ErrorResponse> handle(UserNotFoundException e) {
        return ResponseEntity.status(NOT_FOUND).body(
            new ErrorResponse("USER_NOT_FOUND", e.getMessage(), MDC.get("traceId"))
        );
    }
}
```

- Standard error shape:
  ```json
  { "code": "USER_NOT_FOUND", "message": "...", "traceId": "..." }
  ```
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
- MDC for `traceId`, `userId`, `tenantId` — set in a filter, cleared in a finally block.

## Security

- All endpoints have explicit auth. Default-deny config:
  ```java
  http.authorizeHttpRequests(auth -> auth.anyRequest().authenticated());
  ```
- `@PreAuthorize` on service methods that need authorization (if auth module exists).
- Method-level permission checks use `@RequiresPermission("resource:action")` — see `SECURITY.md` §3.1 for the usage pattern, the `RBAC_001` response shape, and the **Spring AOP self-invocation caveat** (annotated methods called from within the same bean are silently unenforced).
- Object-level checks for IDOR — never trust the client-provided owner ID.
- Use `SecureRandom`, never `Math.random`, for any security-sensitive randomness.
- Bean validation is **not** a security boundary. Always validate again at the service layer for sensitive operations.

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
