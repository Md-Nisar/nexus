import { afterNextRender, Component, computed, ElementRef, inject, viewChild } from '@angular/core';
import { RouterLink } from '@angular/router';
import { AuthStore } from '../../../core/auth/auth.store';
import { APP_CONFIG, parseSupportContact } from '../../../core/config/app-config';
import { NxErrorState } from '../../ui';

/**
 * Access Denied page (US-013 AC-2, AC-5).
 *
 * The destination of `permissionGuard`'s denial redirect, registered at `/access-denied`
 * and intentionally **unguarded** — it makes no HTTP call, reveals nothing, and must
 * render even for an unauthenticated visitor who types the URL.
 *
 * ## Accessibility (AC-5)
 * - The page owns the `<main>` landmark and the `<h1>` — the app shell provides neither,
 *   and `NxErrorState` renders its `title` as a `<p>`, not a heading.
 * - The `<h1>` is **visually hidden**: it supplies the programmatic heading hierarchy
 *   while `<nx-error-state title="Access denied">` supplies the visible headline, so the
 *   same text is not shown twice. Both strings are identical, so the accessible name and
 *   the visible label agree.
 * - The `<h1>` carries `tabindex="-1"` and receives focus on route entry, so a screen
 *   reader announces the page on SPA navigation and the next `Tab` lands on
 *   "Return to dashboard".
 * - Both calls to action are real `<a>` elements with descriptive text (never
 *   "click here"), keyboard-operable by default.
 *
 * ## Contact and roles (US-019 A9)
 * The contact link renders only when `AppConfig.supportContact` passes `parseSupportContact`.
 * Role names come from `AuthStore` (as of sign-in); the page still makes no HTTP call.
 *
 * @security Renders static copy, the validated contact and the session's role names only. It must never display `AppError.requiredPermission`
 * or any other RBAC detail (EPIC-002 §UX).
 */
@Component({
  selector: 'nx-access-denied',
  imports: [NxErrorState, RouterLink],
  template: `
    <main class="access-denied" data-testid="access-denied-root">
      <h1 #heading class="access-denied__heading" tabindex="-1" data-testid="access-denied-heading">
        Access denied
      </h1>

      <nx-error-state
        title="Access denied"
        message="You don't have permission to view this resource. If you believe this is a mistake, contact your administrator."
        [showRetry]="false"
      >
        <div class="access-denied__actions">
          <a
            class="access-denied__action"
            routerLink="/dashboard"
            data-testid="access-denied-dashboard-link"
          >
            Return to dashboard
          </a>
          @if (contact(); as support) {
            <a
              class="access-denied__action"
              [href]="support.href"
              rel="noopener noreferrer"
              data-testid="access-denied-contact-link"
            >
              {{ support.label }}
            </a>
          }
        </div>
      </nx-error-state>

      @if (roles().length > 0) {
        <p class="access-denied__roles" data-testid="access-denied-roles">
          Your roles: {{ roleList() }}
          <span class="access-denied__roles-caption">(as of when you signed in)</span>
        </p>
      }
    </main>
  `,
  styleUrl: './access-denied.component.scss',
})
export class AccessDeniedComponent {
  private readonly heading = viewChild.required<ElementRef<HTMLHeadingElement>>('heading');
  private readonly authStore = inject(AuthStore);
  private readonly config = inject(APP_CONFIG);

  /** Configured contact link, or null (hidden) unless its href is `mailto:` or `https://`. */
  protected readonly contact = computed(() => parseSupportContact(this.config.supportContact));

  /** Role names from the session, i.e. as of sign-in; empty when signed out. */
  protected readonly roles = computed(() => this.authStore.currentUser()?.roles ?? []);

  protected readonly roleList = computed(() => this.roles().join(', '));

  constructor() {
    // afterNextRender (not ngAfterViewInit) is Angular's sanctioned hook for DOM writes
    // in a signals/standalone component and needs no lifecycle interface. It runs
    // browser-only, which is also correct for a focus call.
    afterNextRender(() => this.heading().nativeElement.focus());
  }
}
