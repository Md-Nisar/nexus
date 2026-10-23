import { Component } from '@angular/core';

/**
 * Dashboard page, the landing page after sign-in (US-005).
 *
 * Intentionally minimal. The page chrome, the `/v1/users/me` priming request and logout belong
 * to the shell (`core/layout/shell`), which also provides the page's single `main` landmark.
 *
 * Ref: docs/features/US-005/03-design.md, docs/features/US-019/03-design.md section 12.3
 */
@Component({
  selector: 'nx-dashboard',
  template: `
    <section class="dashboard" data-testid="dashboard-root">
      <h1>Dashboard</h1>
    </section>
  `,
})
export class DashboardComponent {}
