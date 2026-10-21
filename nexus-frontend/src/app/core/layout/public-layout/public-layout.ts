import { Component } from '@angular/core';
import { RouterLink, RouterOutlet } from '@angular/router';
import { ThemeToggle } from '../theme-toggle/theme-toggle';

/**
 * Layout of the pages reachable without a session (auth, access denied, design system):
 * wordmark and theme toggle above the routed page. It renders no `main`; each page owns its own.
 */
@Component({
  selector: 'app-public-layout',
  imports: [RouterLink, RouterOutlet, ThemeToggle],
  template: `
    <header class="app-header">
      <a class="app-header__wordmark" routerLink="/" aria-label="Nexus home">Nexus</a>
      <app-theme-toggle />
    </header>
    <router-outlet />
  `,
  styleUrl: './public-layout.scss',
})
export class PublicLayout {}
