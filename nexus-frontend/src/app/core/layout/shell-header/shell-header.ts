import { Component, input, output } from '@angular/core';
import { RouterLink } from '@angular/router';
import { MenuItem, NxMenu } from '../../../shared/ui';
import { ThemeToggle } from '../theme-toggle/theme-toggle';

const LOGOUT_ID = 'logout';

/** Header of the signed-in shell: nav toggle (narrow screens), wordmark, theme and user menu. */
@Component({
  selector: 'app-shell-header',
  imports: [RouterLink, ThemeToggle, NxMenu],
  template: `
    <header class="shell-header" data-testid="shell-header">
      <button
        type="button"
        class="shell-header__nav-toggle"
        data-testid="nav-toggle"
        aria-label="Main menu"
        aria-controls="primary-nav"
        [attr.aria-expanded]="navOpen()"
        (click)="toggleNav.emit()"
      >
        <span class="material-icons" aria-hidden="true">menu</span>
      </button>
      <a
        class="shell-header__wordmark"
        routerLink="/"
        [attr.aria-label]="productName() + ' home'"
        >{{ productName() }}</a
      >
      <div class="shell-header__actions">
        <app-theme-toggle />
        <span class="shell-header__user" data-testid="user-label">{{ userLabel() }}</span>
        <nx-menu
          triggerLabel="Account menu"
          triggerIcon="account_circle"
          [items]="userMenuItems"
          (selected)="onSelected($event)"
        />
      </div>
    </header>
  `,
  styleUrl: './shell-header.scss',
})
export class ShellHeader {
  readonly productName = input.required<string>();
  readonly userLabel = input.required<string>();
  readonly navOpen = input.required<boolean>();

  readonly toggleNav = output<void>();
  readonly logout = output<void>();

  protected readonly userMenuItems: readonly MenuItem[] = [
    { id: LOGOUT_ID, label: 'Log out', icon: 'logout', testId: 'logout-button' },
  ];

  protected onSelected(id: string): void {
    if (id === LOGOUT_ID) this.logout.emit();
  }
}
