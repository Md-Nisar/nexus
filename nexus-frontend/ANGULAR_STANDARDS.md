You are an expert in TypeScript, Angular, and scalable web application development. You write functional, maintainable, performant, and accessible code following Angular and TypeScript best practices.
## TypeScript Best Practices
- Use strict type checking
- Prefer type inference when the type is obvious
- Avoid the `any` type; use `unknown` when type is uncertain
## Angular Best Practices
- Always use standalone components over NgModules
- Must NOT set `standalone: true` inside Angular decorators. It's the default in Angular v20+.
- Do NOT set `changeDetection: ChangeDetectionStrategy.OnPush` explicitly. `OnPush` is the default in Angular v22+.
- Use signals for state management
- Implement lazy loading for feature routes
- Do NOT use the `@HostBinding` and `@HostListener` decorators. Put host bindings inside the `host` object of the `@Component` or `@Directive` decorator instead
- Use `NgOptimizedImage` for all static images.
  - `NgOptimizedImage` does not work for inline base64 images.
## Accessibility Requirements
- It MUST pass all AXE checks.
- It MUST follow all WCAG AA minimums, including focus management, color contrast, and ARIA attributes.
### Components
- Keep components small and focused on a single responsibility
- Use `input()` and `output()` functions instead of decorators
- Use `computed()` for derived state
- Prefer inline templates for small components
- Prefer Signal Forms (`@angular/forms/signals`) for new forms. They are stable in Angular v22+ and provide signal-based state, type-safe field access, and schema-based validation
- When not using Signal Forms, prefer Reactive forms instead of Template-driven ones
- Do NOT use `ngClass`, use `class` bindings instead
- Do NOT use `ngStyle`, use `style` bindings instead
- When using external templates/styles, use paths relative to the component TS file.
## State Management
- Use signals for local component state
- Use `computed()` for derived state
- Keep state transformations pure and predictable
- Do NOT use `mutate` on signals, use `update` or `set` instead
## Templates
- Keep templates simple and avoid complex logic
- Use native control flow (`@if`, `@for`, `@switch`) instead of `*ngIf`, `*ngFor`, `*ngSwitch`
- Use the async pipe to handle observables
- Do not assume globals like (`new Date()`) are available.
## Services
- Design services around a single responsibility
- Use the `providedIn: 'root'` option for singleton services
- Prefer the `@Service` decorator over `@Injectable({providedIn: 'root'})` for new singleton services (Angular v22+)
- Use the `inject()` function instead of constructor injection
## Async, Routing & HTTP Pitfalls (each one has shipped in this codebase)
- `computed()` re-runs only when a signal it reads changes; non-signal values such as `Date.now()` are frozen at the last run. Use a method, or a timer-driven signal, for time-based checks (seen in `AuthStore.isAuthenticated`)
- Guards in one `canActivate` array run concurrently; array order only ranks their results. A guard that depends on another guard's async work must wait on that shared state itself, or sit on a child route (seen in `permissionGuard` with `authGuard`)
- In a retry flow, put the `catchError` that handles refresh failure before `switchMap(() => next(retry))`; placed after it, it also catches errors from the replayed request (seen in `authInterceptor`, reactive path)
- An HTTP call made from inside an interceptor flow passes through the same interceptor and can end up waiting on itself. Mark such calls with an `HttpContextToken` that the interceptor skips (seen in `AuthService.refresh()` → `/users/me`)
- A refresh that rotates credentials must be single-flight for every caller (guards and interceptors), owned by one service, not cancellable by an unsubscribing caller (`shareReplay` without `refCount`), and bounded by `timeout()`