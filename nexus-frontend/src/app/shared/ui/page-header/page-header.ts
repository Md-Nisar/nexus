import { Component, input } from '@angular/core';

/**
 * Page heading block. Renders the page's single `h1` (`tabindex="-1"`, so route focus
 * management can move focus to it without adding a tab stop), an optional description, and
 * the `[slot=breadcrumb]` and `[slot=actions]` content slots.
 */
@Component({
  selector: 'nx-page-header',
  template: `
    <header class="nx-page-header">
      <div class="nx-page-header__breadcrumb"><ng-content select="[slot=breadcrumb]" /></div>
      <div class="nx-page-header__row">
        <div class="nx-page-header__text">
          <h1 class="nx-page-header__title" tabindex="-1" data-testid="nx-page-header-title">
            {{ title() }}
          </h1>
          @if (description()) {
            <p class="nx-page-header__description" data-testid="nx-page-header-description">
              {{ description() }}
            </p>
          }
        </div>
        <div class="nx-page-header__actions"><ng-content select="[slot=actions]" /></div>
      </div>
    </header>
  `,
  styleUrl: './page-header.scss',
})
export class NxPageHeader {
  readonly title = input.required<string>();
  readonly description = input('');
}
