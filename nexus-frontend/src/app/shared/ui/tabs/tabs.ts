import { Component, input } from '@angular/core';
import { MatTabsModule } from '@angular/material/tabs';
import { RouterLink, RouterLinkActive } from '@angular/router';

/** One routable tab of an {@link NxTabs}. */
export interface NavTab {
  readonly label: string;
  /** Absolute route path the tab links to. */
  readonly path: string;
  /** Overrides the default `nx-tab-{path}` test id. */
  readonly testId?: string;
}

/**
 * Routable tab bar wrapping `MatTabNav`. The active tab follows the router
 * (`routerLinkActive`); the projected content sits in the tab panel. The tab bar is named by
 * the required `ariaLabel`.
 */
@Component({
  selector: 'nx-tabs',
  imports: [MatTabsModule, RouterLink, RouterLinkActive],
  template: `
    <nav mat-tab-nav-bar class="nx-tabs" [tabPanel]="panel" [attr.aria-label]="ariaLabel()">
      @for (tab of tabs(); track tab.path) {
        <a
          mat-tab-link
          [routerLink]="tab.path"
          routerLinkActive
          #rla="routerLinkActive"
          [active]="rla.isActive"
          [attr.data-testid]="tab.testId ?? defaultTestId(tab)"
          >{{ tab.label }}</a
        >
      }
    </nav>
    <mat-tab-nav-panel #panel class="nx-tabs__panel"><ng-content /></mat-tab-nav-panel>
  `,
  styleUrl: './tabs.scss',
})
export class NxTabs {
  readonly tabs = input.required<readonly NavTab[]>();
  readonly ariaLabel = input.required<string>();

  protected defaultTestId(tab: NavTab): string {
    return 'nx-tab-' + tab.path.replace(/^\//, '').replace(/\//g, '-');
  }
}
