import { Component, input } from '@angular/core';
import { RouterLink, RouterLinkActive } from '@angular/router';
import { NavItem } from '../nav.config';

/** The shell's primary navigation landmark. Items arrive already filtered by permission. */
@Component({
  selector: 'app-primary-nav',
  imports: [RouterLink, RouterLinkActive],
  template: `
    <nav id="primary-nav" aria-label="Primary" data-testid="primary-nav">
      <ul class="primary-nav__list">
        @for (item of items(); track item.id) {
          <li>
            <a
              class="primary-nav__link"
              routerLinkActive="primary-nav__link--active"
              ariaCurrentWhenActive="page"
              [routerLink]="item.path"
              [attr.data-testid]="'nav-' + item.id"
            >
              <span class="material-icons" aria-hidden="true">{{ item.icon }}</span>
              {{ item.label }}
            </a>
          </li>
        }
      </ul>
    </nav>
  `,
  styleUrl: './primary-nav.scss',
})
export class PrimaryNav {
  readonly items = input.required<readonly NavItem[]>();
}
