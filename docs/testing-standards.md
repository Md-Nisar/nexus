# Testing Standards — Nexus

## The Test Pyramid

```
           /‾‾‾‾‾‾‾‾‾‾‾‾\
          /   E2E (5%)   \        Playwright (future)
         /‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾\
        / Integration (25%) \     @SpringBootTest + Testcontainers
       /‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾\   Angular TestBed + HttpTestingController
      /     Unit (70%)        \   JUnit 5 + Mockito / Vitest
     /‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾\
```

## Coverage Targets

| Layer | Target | Measured by |
|-------|--------|-------------|
| `domain/` | ≥ 90% line | JaCoCo |
| `application/` | ≥ 85% line | JaCoCo |
| `infrastructure/` | ≥ 70% line | JaCoCo |
| `interfaces/rest/` | ≥ 80% line | JaCoCo |
| Angular components | ≥ 80% statement | Vitest coverage |
| Angular services | ≥ 85% statement | Vitest coverage |

Coverage gates run in CI. A PR that drops below a threshold is blocked.

---

## Backend Testing

### Tools

| Tool | Purpose |
|------|---------|
| JUnit 5 | Test runner, lifecycle annotations |
| Mockito | Mocking collaborators in unit tests |
| AssertJ | Fluent assertions — `assertThat(result).isEqualTo(...)` |
| Testcontainers (MySQL) | Real DB in integration tests |
| Spring Boot Test | `@SpringBootTest`, `@WebMvcTest`, `@DataJpaTest` |
| WireMock | Stub external HTTP services |
| Awaitility | Async assertions (`await().atMost(...)`) |
| MockMvc | Controller tests without a running server |

**H2 is banned.** It does not replicate MySQL's behaviour. Testcontainers starts a real MySQL container.

### Test types

**Unit tests** — no Spring context, instantiate classes directly, mock collaborators:

```java
class PasswordResetServiceTest {

    private final UserRepository users = mock(UserRepository.class);
    private final PasswordResetTokenRepository tokens = mock(PasswordResetTokenRepository.class);
    private final EmailPort email = mock(EmailPort.class);
    private final Clock clock = Clock.fixed(Instant.parse("2025-11-14T10:00:00Z"), ZoneOffset.UTC);

    private final PasswordResetService service =
        new PasswordResetService(users, tokens, email, clock);

    @Test
    void should_issueToken_when_emailExists() {
        // Arrange
        var user = TestUsers.active("alice@example.com");
        when(users.findByEmail("alice@example.com")).thenReturn(Optional.of(user));

        // Act
        service.requestReset("alice@example.com");

        // Assert
        verify(tokens).save(argThat(t -> t.userId().equals(user.id())));
        verify(email).sendPasswordReset(eq(user), anyString());
    }
}
```

**Slice tests** — test one layer with its framework wiring:

```java
@DataJpaTest
@AutoConfigureTestDatabase(replace = NONE) // use Testcontainers, not H2
@Testcontainers
class JpaPasswordResetTokenRepositoryTest {
    @Container
    static MySQLContainer<?> mysql = new MySQLContainer<>("mysql:8");

    @DynamicPropertySource
    static void mysqlProperties(DynamicPropertyRegistry r) {
        r.add("spring.datasource.url", mysql::getJdbcUrl);
        r.add("spring.datasource.username", mysql::getUsername);
        r.add("spring.datasource.password", mysql::getPassword);
    }
    // ...
}
```

**Integration tests** — full Spring context + real MySQL:

```java
@SpringBootTest(webEnvironment = RANDOM_PORT)
@Testcontainers
class PasswordResetFlowTest {
    @Container
    static MySQLContainer<?> mysql = new MySQLContainer<>("mysql:8");

    @Test
    void should_resetPassword_when_validTokenProvided() { ... }
}
```

### Conventions

- **Naming:** `should_<expected>_when_<condition>` — readable as a sentence.
- **AAA structure** with blank lines:

```java
@Test
void should_rejectToken_when_expired() {
    // Arrange
    var expired = TestTokens.expiredFor(user.id());

    // Act + Assert
    assertThatThrownBy(() -> service.confirmReset(expired.id(), "newPass123!"))
        .isInstanceOf(TokenExpiredException.class);
}
```

- **One logical assertion per test.** Multiple `assertThat` calls are fine when they describe one outcome; don't test two scenarios in one test.
- **Builders / factories for test data.** `TestUsers.active(email)`, `TestTokens.validFor(userId)` — not `new User(...)` with all fields inline.
- **No `Thread.sleep`.** Use Awaitility for async, or inject a `Clock` and control time.

---

## Frontend Testing (Vitest)

### Tools

| Tool | Purpose |
|------|---------|
| Vitest | Test runner |
| Angular `TestBed` | Component wiring |
| `HttpTestingController` | Mock HTTP client |
| `vi.fn()` | Function mocks |
| `vi.useFakeTimers()` | Timer control |

### Conventions

- File next to source: `user-card.component.spec.ts`.
- Use `data-testid` for selectors:
  ```html
  <button data-testid="reset-button">Reset Password</button>
  ```
  ```ts
  const btn = fixture.nativeElement.querySelector('[data-testid="reset-button"]');
  ```
- Cover every state of a state machine:
  - Initial / loading
  - Success (with data)
  - Empty (no data)
  - Error

Example:
```ts
describe('ForgotPasswordComponent', () => {
  let component: ForgotPasswordComponent;
  let fixture: ComponentFixture<ForgotPasswordComponent>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [ForgotPasswordComponent, provideHttpClientTesting()],
    }).compileComponents();
    fixture = TestBed.createComponent(ForgotPasswordComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should show success message after valid submission', async () => {
    const emailInput = fixture.nativeElement.querySelector('[data-testid="email-input"]');
    emailInput.value = 'alice@example.com';
    emailInput.dispatchEvent(new Event('input'));
    fixture.nativeElement.querySelector('[data-testid="submit-button"]').click();

    await fixture.whenStable();
    fixture.detectChanges();

    expect(fixture.nativeElement.querySelector('[data-testid="success-message"]')).toBeTruthy();
  });
});
```

---

## Load Testing

For any endpoint expected to handle > 10 RPS, include a load test scenario:

- **Tool:** k6 (preferred) or Gatling.
- **Location:** `nexus-backend/src/test/load/`.
- **Targets:**
  - Read endpoints: p95 < 200 ms at 100 RPS
  - Write endpoints: p95 < 500 ms at 50 RPS
  - Error rate < 0.1% under normal load

Run against a staging environment with production-like data volume, not local.

---

## Flaky Tests

A flaky test is worse than no test — it destroys trust in the suite.

If a test fails intermittently:
1. Quarantine it (skip + create a Jira ticket labelled `flaky-test`).
2. Fix within one sprint. If not fixed, the test is deleted.

Common causes: `Thread.sleep`, non-deterministic ordering, shared mutable state between tests, real clocks, non-stubbed randomness.

---

## CI Gates

The following must all be green before a PR can merge:

- Backend: `./mvnw test` with all JUnit tests passing
- Frontend: `npm test -- --run` with all Vitest tests passing
- Coverage thresholds not regressed
- `npm audit` no high/critical
- `./mvnw dependency:check` (OWASP) no CVSS >= 7.0

No exceptions without explicit team lead sign-off.
