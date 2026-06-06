---
name: angular-standards
description: Use when writing or reviewing Angular 21 code in the Nexus frontend. Covers standalone components, signals, control flow, routing, services, types, styling, and Vitest testing.
---

# Angular 21 Standards for Nexus

## Architectural baseline

- **Standalone components only.** No `NgModule` outside legacy interop.
- **Signals first.** Use `signal()`, `computed()`, `effect()` for component and service state. Reserve RxJS for HTTP streams and event flows.
- **Strict mode is non-negotiable.** `strict`, `strictTemplates`, `strictInjectionParameters` all on.
- **Prettier:** 100-char line, single quotes (configured in `package.json`).

## Components

- Decorator essentials:
  ```ts
  @Component({
    selector: 'nx-user-card',
    standalone: true,
    imports: [/* explicit imports only */],
    templateUrl: './user-card.html',
    styleUrl: './user-card.scss',
    changeDetection: ChangeDetectionStrategy.OnPush,
  })
  ```
- Use `input()` and `output()` functions, not decorators:
  ```ts
  readonly userId = input.required<string>();
  readonly saved = output<User>();
  ```
- Use `inject()` over constructor injection where idiomatic.
- Use the modern control flow — **never** `*ngIf`, `*ngFor`, `*ngSwitch`:
  ```html
  @if (user(); as u) {
    <div>{{ u.name }}</div>
  } @else {
    <empty-state />
  }
  @for (item of items(); track item.id) {
    <item-row [item]="item" />
  }
  ```
- Prefer `@defer` for non-critical sections to improve initial bundle size.
- Templates contain no logic beyond property access. Non-trivial expressions → `computed`.

## State

- Component-local state: `signal()` and `computed()`.
- Cross-component state: a service with `signal()` exposed read-only (`asReadonly()` or computed getter).
- Effects (`effect()`) for side effects only. Never for derived state — use `computed`.
- Discriminated unions for view-state machines:
  ```ts
  type ViewState =
    | { kind: 'loading' }
    | { kind: 'success'; data: User }
    | { kind: 'error'; error: string };
  ```

## Services

- `providedIn: 'root'` unless scope is intentional.
- Typed `HttpClient` calls — never `any`.
- Error transformation in the service, not the component.
- Use the `resource()` / `httpResource()` patterns where loading + error + data are needed together.
- Subscribe in components only via `async` pipe or `takeUntilDestroyed()`.

```ts
@Injectable({ providedIn: 'root' })
export class UserService {
  private readonly http = inject(HttpClient);

  getById(id: string): Observable<User> {
    return this.http.get<UserDto>(`/api/users/${id}`).pipe(
      map(toUser),
      catchError((err) => throwError(() => toAppError(err))),
    );
  }
}
```

## Routing

- Functional guards only:
  ```ts
  export const authGuard: CanActivateFn = () => {
    const auth = inject(AuthService);
    return auth.isAuthenticated() || inject(Router).createUrlTree(['/login']);
  };
  ```
- Lazy-load with `loadComponent` and `loadChildren`.
- Use `withComponentInputBinding()` so route params arrive via `input()`.

## Types

- **No `any`.** Use `unknown` and narrow.
- `readonly` and `as const` by default for shared shapes.
- DTO types (from backend) live in `src/app/api/types/` and are converted to domain types at the service boundary.
- Branded types for IDs where mix-ups would be costly:
  ```ts
  type UserId = string & { readonly __brand: 'UserId' };
  ```

## Styling

- Component-scoped styles by default.
- CSS variables for tokens — never hardcoded brand colors in components.
- Use `:host` for the component root style.
- Avoid `::ng-deep`. If you need it, document why.

## Accessibility

- Semantic HTML first. Use `button`, not `div` with click handler.
- All interactive elements keyboard-reachable.
- `aria-*` attributes where roles aren't implicit.
- Visible focus rings — do not remove without replacement.
- Color contrast: 4.5:1 for text, 3:1 for large text and UI components.

## Forbidden

- `NgModule` outside legacy compatibility
- `any` (use `unknown` and narrow)
- `*ngIf`, `*ngFor`, `*ngSwitch` (use `@if`, `@for`, `@switch`)
- Subscriptions without `takeUntilDestroyed()` or `async` pipe
- `console.log` in committed code — use a logger service
- Manual DOM access (`document.querySelector`, `nativeElement.querySelector`) — use Angular APIs
- Logic in templates beyond simple property access
- Hardcoded URLs — use a config service

## Testing (Vitest)

- File naming: `*.spec.ts` next to the source file.
- Use Vitest's `describe / it / expect` and `vi.fn()` for mocks.
- Components: `TestBed.configureTestingModule({ imports: [Component] })` since they're standalone.
- HTTP: `provideHttpClientTesting()` + `HttpTestingController`.
- Use `data-testid` for stable selectors:
  ```html
  <button data-testid="save-button">Save</button>
  ```
  ```ts
  const btn = fixture.nativeElement.querySelector('[data-testid="save-button"]');
  ```
- Fake timers via `vi.useFakeTimers()`. Never `await new Promise(r => setTimeout(r, ...))` in tests.
- Cover every state of a state machine.

## Commands recap

```bash
npm start          # dev server on port 2000
npm run build      # production build (validates strict templates)
npm test           # Vitest
npm run watch      # incremental dev build
```
