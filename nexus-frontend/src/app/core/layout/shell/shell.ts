import { httpResource } from '@angular/common/http';
import { Component, ElementRef, computed, inject, signal, viewChild } from '@angular/core';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { NavigationEnd, Router, RouterOutlet } from '@angular/router';
import { filter, finalize } from 'rxjs';
import { AuthService } from '../../../features/auth/auth.service';
import { NxToast } from '../../../shared/ui';
import { AuthStore } from '../../auth/auth.store';
import { APP_CONFIG } from '../../config/app-config';
import { NAV_ITEMS_TOKEN, visibleNavItems } from '../nav.config';
import { PrimaryNav } from '../primary-nav/primary-nav';
import { ShellHeader } from '../shell-header/shell-header';

/**
 * Layout of every signed-in page: skip link, header, permission-filtered primary nav and the
 * single `main` landmark around the routed page. Mounted lazily at `''` behind `authGuard`.
 *
 * Owns the `/v1/users/me` request that primes the auth interceptor's proactive refresh and the
 * logout flow (revokes the server-side refresh family, clears the session, returns to login).
 * Logout always ends on `/auth/login`, even when the request fails, because the client session
 * is already cleared.
 *
 * @security The nav filter is UX only; route guards and the server enforce access.
 */
@Component({
  selector: 'app-shell',
  imports: [RouterOutlet, ShellHeader, PrimaryNav],
  template: `
    <a
      class="shell__skip-link"
      href="#main-content"
      data-testid="skip-link"
      (click)="skipToMain($event)"
      >Skip to main content</a
    >
    <app-shell-header
      productName="Nexus"
      [userLabel]="userLabel()"
      [navOpen]="navOpen()"
      (toggleNav)="navOpen.set(!navOpen())"
      (logout)="onLogout()"
    />
    <div class="shell__body" [class.shell__body--nav-open]="navOpen()">
      <app-primary-nav [items]="navItems()" />
      <main id="main-content" class="shell__main" tabindex="-1" #main>
        <router-outlet />
      </main>
    </div>
  `,
  styleUrl: './shell.scss',
})
export class Shell {
  private readonly config = inject(APP_CONFIG);
  private readonly authStore = inject(AuthStore);
  private readonly authService = inject(AuthService);
  private readonly router = inject(Router);
  private readonly toast = inject(NxToast);
  private readonly navConfig = inject(NAV_ITEMS_TOKEN);
  private readonly main = viewChild.required<ElementRef<HTMLElement>>('main');

  /** Whether the nav is expanded below 960 px; wide screens always show it. */
  readonly navOpen = signal(false);
  readonly loggingOut = signal(false);

  protected readonly navItems = computed(() =>
    visibleNavItems(this.navConfig, this.authStore.permissions()),
  );
  protected readonly userLabel = computed(
    () => this.authStore.currentUser()?.roles.join(', ') || 'Account',
  );

  /** Side-effect-only request: keeps the interceptor's proactive refresh active. */
  readonly userProfile = httpResource(() => `${this.config.apiBaseUrl}/v1/users/me`);

  constructor() {
    this.router.events
      .pipe(
        filter((event) => event instanceof NavigationEnd),
        takeUntilDestroyed(),
      )
      .subscribe(() => this.navOpen.set(false));
  }

  /** Moves focus to `main` without a fragment navigation, which the router would intercept. */
  protected skipToMain(event: Event): void {
    event.preventDefault();
    this.main().nativeElement.focus();
  }

  onLogout(): void {
    if (this.loggingOut()) return;
    this.loggingOut.set(true);
    this.authService
      .logout()
      .pipe(finalize(() => this.loggingOut.set(false)))
      .subscribe({
        next: () => {
          this.toast.success('You have been logged out.');
          void this.router.navigate(['/auth/login']);
        },
        error: () => {
          this.toast.error('Logout could not be confirmed, but your session was ended.');
          void this.router.navigate(['/auth/login']);
        },
      });
  }
}
