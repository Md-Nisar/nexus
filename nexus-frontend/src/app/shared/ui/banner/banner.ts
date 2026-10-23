import { Component, computed, input, output } from '@angular/core';
import { NxButton } from '../button/button';
import { NxIcon } from '../icon/icon';

export type BannerVariant = 'info' | 'success' | 'warning' | 'error';
/** `polite` renders `role=status`, `assertive` `role=alert`, `off` no live region. */
export type BannerLive = 'polite' | 'assertive' | 'off';

const ICONS: Readonly<Record<BannerVariant, string>> = {
  info: 'info',
  success: 'check_circle',
  warning: 'warning',
  error: 'error',
};

const ROLES: Readonly<Record<BannerLive, 'status' | 'alert' | null>> = {
  polite: 'status',
  assertive: 'alert',
  off: null,
};

/**
 * Page-level message strip (US-020 design §15.1; token-native, no Material component).
 *
 * - The title is text and the variant icon is decorative, so meaning never rests on colour.
 * - Body content is projected; actions go in `[slot=actions]`.
 * - Live region by `live`: `polite` gives `role=status`, `assertive` `role=alert`, `off` none.
 *   Unset, it follows the variant: `error` is assertive, every other variant polite.
 * - `dismissible` adds a named dismiss button that emits `dismissed`; the host removes the
 *   banner, so its visibility stays host state.
 * - The title is a paragraph, not a heading: a banner sits above the page `h1` and must not
 *   break the heading order.
 *
 * @example
 * ```html
 * <nx-banner variant="warning" title="Changes are off">
 *   <p>We couldn't load your access details.</p>
 *   <nx-button slot="actions" (clicked)="retry()">Retry</nx-button>
 * </nx-banner>
 * ```
 */
@Component({
  selector: 'nx-banner',
  imports: [NxButton, NxIcon],
  template: `
    <div [class]="'nx-banner nx-banner--' + variant()" [attr.role]="role()" data-testid="nx-banner">
      <nx-icon class="nx-banner__icon" [name]="icon()" />
      <div class="nx-banner__content">
        <p class="nx-banner__title" data-testid="nx-banner-title">{{ title() }}</p>
        <div class="nx-banner__body"><ng-content /></div>
        <div class="nx-banner__actions"><ng-content select="[slot=actions]" /></div>
      </div>
      @if (dismissible()) {
        <nx-button
          class="nx-banner__dismiss"
          variant="ghost"
          size="sm"
          leadingIcon="close"
          [ariaLabel]="dismissLabel()"
          (clicked)="dismissed.emit()"
          data-testid="nx-banner-dismiss"
        />
      }
    </div>
  `,
  styleUrl: './banner.scss',
})
export class NxBanner {
  /** Semantic colour and icon. @default 'info' */
  readonly variant = input<BannerVariant>('info');
  /** Short, visible title text. */
  readonly title = input.required<string>();
  /** Live-region politeness; unset follows the variant (`error` assertive, others polite). */
  readonly live = input<BannerLive | undefined>(undefined);
  /** Shows a dismiss button. @default false */
  readonly dismissible = input(false);

  /** The user pressed the dismiss button; the host removes the banner. */
  readonly dismissed = output<void>();

  protected readonly icon = computed(() => ICONS[this.variant()]);
  protected readonly role = computed(
    () => ROLES[this.live() ?? (this.variant() === 'error' ? 'assertive' : 'polite')],
  );
  protected readonly dismissLabel = computed(() => `Dismiss: ${this.title()}`);
}
