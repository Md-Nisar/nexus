import { Component, computed, input } from '@angular/core';
import { RouterLink } from '@angular/router';

/** One crumb of an {@link NxBreadcrumb}. */
export interface BreadcrumbItem {
  readonly label: string;
  /** Absolute route path; ignored on the last item, which is the current page. */
  readonly path?: string;
}

/**
 * Breadcrumb trail. Earlier items with a path are links; the last item is plain text marked
 * `aria-current="page"`. The separator is decorative and hidden from assistive technology.
 */
@Component({
  selector: 'nx-breadcrumb',
  imports: [RouterLink],
  template: `
    @if (crumbs().length > 0) {
      <nav aria-label="Breadcrumb" data-testid="nx-breadcrumb">
        <ol class="nx-breadcrumb__list">
          @for (crumb of crumbs(); track $index) {
            <li class="nx-breadcrumb__item">
              @if (crumb.current) {
                <span class="nx-breadcrumb__current" aria-current="page">{{ crumb.label }}</span>
              } @else if (crumb.path) {
                <a class="nx-breadcrumb__link" [routerLink]="crumb.path">{{ crumb.label }}</a>
              } @else {
                <span>{{ crumb.label }}</span>
              }
            </li>
          }
        </ol>
      </nav>
    }
  `,
  styleUrl: './breadcrumb.scss',
})
export class NxBreadcrumb {
  readonly items = input<readonly BreadcrumbItem[]>([]);

  protected readonly crumbs = computed(() => {
    const items = this.items();
    return items.map((item, index) => ({ ...item, current: index === items.length - 1 }));
  });
}
