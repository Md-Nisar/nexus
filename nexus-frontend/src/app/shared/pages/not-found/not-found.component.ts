import { Component } from '@angular/core';
import { RouterLink } from '@angular/router';
import { NxPageHeader } from '../../ui';

/** Shown inside the shell for any URL that matches no route. */
@Component({
  selector: 'nx-not-found',
  imports: [NxPageHeader, RouterLink],
  template: `
    <nx-page-header
      title="Page not found"
      description="The page you are looking for does not exist or has moved."
    />
    <a routerLink="/dashboard" data-testid="not-found-dashboard-link">Go to dashboard</a>
  `,
})
export class NotFoundComponent {}
