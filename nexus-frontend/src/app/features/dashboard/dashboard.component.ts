import { Component, computed, inject } from '@angular/core';
import { RouterLink } from '@angular/router';
import { AuthStore } from '../../core/auth/auth.store';
import { APP_CONFIG } from '../../core/config/app-config';
import { ACCESS_CONSOLE_ANY_OF } from '../../core/layout/nav.config';
import { NxCard } from '../../shared/ui';

/**
 * Dashboard page, the landing page after sign-in (US-005).
 *
 * Intentionally minimal. The page chrome, the `/v1/users/me` priming request and logout belong
 * to the shell (`core/layout/shell`), which also provides the page's single `main` landmark.
 *
 * Shows the "Access management" card (US-020 design §4.4, §12.12) when the console is switched on
 * and the user holds any of {@link ACCESS_CONSOLE_ANY_OF}. UX only: `anyPermissionGuard` and the
 * server decide access.
 *
 * Ref: docs/features/US-005/03-design.md, docs/features/US-019/03-design.md section 12.3
 */
@Component({
  selector: 'nx-dashboard',
  imports: [NxCard, RouterLink],
  template: `
    <section class="dashboard" data-testid="dashboard-root">
      <h1>Dashboard</h1>
      @if (showAccessCard()) {
        <nx-card
          class="dashboard__card"
          title="Access management"
          elevation="outlined"
          data-testid="dashboard-access-card"
        >
          <p>Manage roles, permissions and who has access.</p>
          <a
            slot="actions"
            class="dashboard__link"
            routerLink="/admin/access"
            data-testid="dashboard-access-link"
            >Open access management</a
          >
        </nx-card>
      }
    </section>
  `,
  styles: `
    .dashboard__card {
      max-width: calc(var(--nx-space-24) * 4);
    }

    @media (max-width: 599px) {
      .dashboard__card {
        max-width: none;
      }
    }

    .dashboard__link {
      display: inline-flex;
      align-items: center;
      padding: var(--nx-space-2) var(--nx-space-4);
      border-radius: var(--nx-radius-md);
      background-color: var(--nx-color-primary);
      color: var(--nx-color-on-primary);
      font-weight: var(--nx-weight-medium);
      text-decoration: none;
    }

    .dashboard__link:hover {
      background-color: var(--nx-color-primary-hover);
    }
  `,
})
export class DashboardComponent {
  private readonly config = inject(APP_CONFIG);
  private readonly authStore = inject(AuthStore);

  protected readonly showAccessCard = computed(
    () =>
      this.config.accessConsoleEnabled &&
      ACCESS_CONSOLE_ANY_OF.some((p) => this.authStore.permissions().includes(p)),
  );
}
