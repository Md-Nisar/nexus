import {
  Directive,
  TemplateRef,
  ViewContainerRef,
  computed,
  effect,
  inject,
  input,
} from '@angular/core';
import { AuthStore } from '../../core/auth/auth.store';

/**
 * Structural directive that renders its host element only when the current user holds a
 * given RBAC permission.
 *
 * ```html
 * <button *appHasPermission="'users:delete'" (click)="delete()">Delete user</button>
 * ```
 *
 * Reactive: the element appears or disappears automatically when
 * {@link AuthStore.permissions} changes (e.g. after login, token refresh, or a
 * `/users/me` re-fetch). No subscription and no manual change detection are involved.
 *
 * Each consuming standalone component adds `HasPermissionDirective` to its own
 * `imports: [...]` array — there is no global shared-imports barrel in this codebase,
 * and it is intentionally **not** exported from `shared/ui/index.ts` (that barrel is the
 * documented UI component library).
 *
 * Degrades gracefully: when the permission list is empty — including the pre-session
 * cold-start state — the element is simply absent. Nothing is thrown and nothing is
 * logged (US-013 AC-4).
 *
 * @security **UX only — not a security boundary.** Hiding a control does not protect the
 * operation behind it. Every action this directive hides must also be enforced
 * server-side with `@RequiresPermission` (US-011). Never use this directive to hide data
 * that the user is not permitted to see: by the time it renders, that data has already
 * been delivered to the browser.
 */
@Directive({
  selector: '[appHasPermission]',
  standalone: true,
})
export class HasPermissionDirective {
  private readonly authStore = inject(AuthStore);
  private readonly viewContainer = inject(ViewContainerRef);
  private readonly template = inject<TemplateRef<unknown>>(TemplateRef);

  /**
   * The permission string required to render the host template.
   *
   * The input name must equal the selector for structural-directive microsyntax
   * (`*appHasPermission="…"`) to bind — this is not stylistic; `strictTemplates`
   * derives the input name from the selector.
   */
  readonly appHasPermission = input.required<string>();

  /**
   * Whether the user currently holds the required permission.
   *
   * A `computed` (rather than reading the store inside the effect) so Angular's
   * value-equality short-circuit suppresses the effect entirely when `permissions`
   * changes identity but the boolean answer does not — e.g. a token refresh that returns
   * the same permission set. This is the primary defence against redundant DOM work.
   */
  private readonly granted = computed(() =>
    this.authStore.permissions().includes(this.appHasPermission()),
  );

  /**
   * Tracks whether the embedded view is currently instantiated.
   *
   * Deliberately a plain field, not a signal: it is imperative view bookkeeping, not
   * application state, and writing a signal from inside an effect would make the effect
   * a producer as well as a consumer. It guards against redundant
   * `createEmbeddedView`/`clear()` calls independently of the `computed` above.
   */
  private hasView = false;

  constructor() {
    // The effect (rather than the constructor body) is what makes `input.required()`
    // safe to read: effects first run after the initial change-detection pass has set
    // inputs, whereas reading a required input in the constructor throws.
    effect(() => {
      const granted = this.granted();

      if (granted && !this.hasView) {
        this.viewContainer.createEmbeddedView(this.template);
        this.hasView = true;
      } else if (!granted && this.hasView) {
        // `clear()` (not a retained ViewRef + `destroy()`) is correct because this
        // container holds exactly one view — ours.
        this.viewContainer.clear();
        this.hasView = false;
      }
    });
  }
}
