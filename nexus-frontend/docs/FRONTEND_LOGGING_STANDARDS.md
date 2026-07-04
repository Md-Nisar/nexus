# Frontend Logging and Observability Standards

This document defines the rules, conventions, and architecture for logging and error handling across the Nexus Frontend application. All developers and AI assistants must follow these standards.

---

## Core Principles

1. **Keep Production Console Output Minimal**: Production browser logs must only contain warnings and errors that are operationally actionable. Never log routine execution paths.
2. **Selective HTTP Failure Logging**: Never log every HTTP request or successful outcome. Log HTTP failures selectively depending on the status code (e.g. routine validation issues should not spam the log).
3. **No Direct Console Statements**: Never write `console.log`, `console.debug`, `console.info`, `console.warn`, or `console.error` directly in feature files. Always use `LoggerService`.
4. **Never Log Sensitive Information**: Never print credentials, tokens, or PII.

---

## 1. Centralized Logger (`LoggerService`)

All diagnostic logs must be directed through `LoggerService`. It enforces level filtering based on the configured environment threshold (typically `debug` in dev, `warn` in production) and performs key scrubbing on metadata context.

### Log Levels
* **`ERROR`**: Unexpected application or runtime failures requiring active investigation (e.g. server crashes, uncaught type errors).
* **`WARN`**: Recoverable issues that are operationally meaningful (e.g. rate-limit hits, degraded connection state).
* **`INFO`**: High-value application lifecycle events (e.g. bootstrap, user session start/termination). Avoid logging individual user clicks or routine workflows.
* **`DEBUG`**: Detailed debugging context for local troubleshooting. Entirely filtered out in production.

### Structured Fields
The logging methods accept a message and a typed `LogParams` payload:

```typescript
export interface LogParams {
  event?: string;             // Broad category (e.g. 'session_expired')
  operation?: string;         // API method or action path (e.g. 'POST /v1/auth/login')
  correlationId?: string;     // Request-specific X-Correlation-Id header
  outcome?: 'SUCCESS' | 'FAILURE'; // Strictly typed result
  errorCode?: string;         // Domain error code (e.g. 'AUTH_001')
  errorType?: string;         // Exception type (e.g. 'TypeError')
  context?: Record<string, unknown>; // Safe metadata key-value map
}
```

---

## 2. Error & Logging Ownership Model

To prevent duplicate logs, each layer has explicit responsibilities:

```
[ Outgoing Request ] ──> correlationIdInterceptor (Attaches X-Correlation-Id)
                               │
[ HTTP Failure ]     ──> apiErrorInterceptor (Logs HTTP Failure & Rethrows AppError)
                               │
                       Service / Store handles
                       (Recovers or maps to ViewState)
                               │
                       Component renders UI
                       (Renders toasts / messages, NO logs)
```

1. **`apiErrorInterceptor`**: Captures and logs all HTTP failures. Stamps the correlation ID on the generated `AppError`.
   * **400, 401, 403, 404, 409 (Routine failures)**: Logged as `DEBUG` only.
   * **429 (Rate limiting)**: Logged as `WARN`.
   * **5xx (Server error) & 0 (Network drop/transport error)**: Logged as `ERROR`.
2. **Services / Stores**: Perform functional recovery (e.g., token refreshes). They must **not** log duplicate HTTP errors because the interceptor has already recorded them.
3. **Components**: Render errors into the user interface (e.g. form fields, toast warnings). Components **never** call `LoggerService` to log errors.
4. **`GlobalErrorHandler`**: Catches uncaught runtime exceptions (e.g., `TypeError`, syntax errors). It logs these as `ERROR` alongside the stack trace (in development only).

---

## 3. Sensitive Data Protection

### Primary Rule
**Never pass arbitrary objects** (such as HTTP response bodies, raw error objects, full user records, or tokens) directly into `LoggerService`. Explicitly select safe, non-sensitive fields to populate the log parameters.

### Secondary Safeguard
`LoggerService` contains a defensive recursive scrubber that replaces any key matching the following pattern with `[REDACTED]`:
`/password|token|secret|authorization|cookie|apiKey|session/i`

Additionally, stack traces (`stack` property inside context) are automatically deleted in production mode to avoid leaking application internals.

---

## 4. Correlation ID Flow

* Generated per outgoing HTTP request inside `correlationIdInterceptor` using `crypto.randomUUID()`.
* Sent to the backend via the `X-Correlation-Id` header.
* On request failure, `apiErrorInterceptor` extracts the value and associates it with the failure log and the returned `AppError`.
* Correlation IDs are request-specific transaction markers and must **never** be stored as global frontend state or mixed with span/trace IDs.

---

## 5. Examples & Code Snippets

### ✅ Correct Code Logging
```typescript
// Local debug statement in feature code
this.logger.debug('Initializing user profile view', {
  event: 'profile_init',
  context: { profileId: id }
});

// Handling a routine recoverable operation
this.authStore.clearSession();
this.logger.info('User session terminated successfully', {
  event: 'logout_success',
  outcome: 'SUCCESS'
});
```

### ❌ Anti-Patterns to Avoid
```typescript
// ❌ Don't use raw console.log
console.log('User logged in!');

// ❌ Don't pass raw/arbitrary error objects or responses
this.logger.error('Login failed', { context: { rawError: err } });

// ❌ Don't log expected routine user behaviors at WARN or ERROR level
if (form.invalid) {
  this.logger.warn('Form validation failed'); // Do not log validation failures
}
```

---

## 6. Linter Enforcement

ESLint strictly prohibits direct console methods across the application:
* Rules: `"no-console": "error"` is configured globally.
* Overrides: Controlled console usage is permitted only inside:
  - `src/app/core/logging/logger.service.ts` (essential implementation)
  - `src/main.ts` (application bootstrap failure logging)
