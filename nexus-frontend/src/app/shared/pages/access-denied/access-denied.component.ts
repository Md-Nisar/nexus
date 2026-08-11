import {
  afterNextRender,
  ChangeDetectionStrategy,
  Component,
  ElementRef,
  viewChild,
} from '@angular/core';
import { RouterLink } from '@angular/router';
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
 * @security Renders static copy only. It must never display `AppError.requiredPermission`
 * or any other RBAC detail (EPIC-002 §UX).
 */
@Component({
  selector: 'nx-access-denied',
  standalone: true,
  imports: [NxErrorState, RouterLink],
  changeDetection: ChangeDetectionStrategy.OnPush,
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
          <!-- TODO(PM): replace this RFC 2606 reserved placeholder domain with the real
               support address before release. -->
          <a
            class="access-denied__action"
            href="mailto:support@yourcompany.example"
            data-testid="access-denied-contact-link"
          >
            Contact your administrator
          </a>
        </div>
      </nx-error-state>
    </main>
  `,
  styleUrl: './access-denied.component.scss',
})
export class AccessDeniedComponent {
  private readonly heading = viewChild.required<ElementRef<HTMLHeadingElement>>('heading');

  constructor() {
    // afterNextRender (not ngAfterViewInit) is Angular's sanctioned hook for DOM writes
    // in a signals/standalone component and needs no lifecycle interface. It runs
    // browser-only, which is also correct for a focus call.
    afterNextRender(() => this.heading().nativeElement.focus());
  }
}
