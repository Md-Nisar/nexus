import { Component, computed, input } from '@angular/core';
import { BadgeVariant, NxBadge, NxIcon } from '../../../shared/ui';
import type { UserStatus } from '../../../shared/types/api/user-directory';
import { CONSOLE_COPY } from '../copy/console-copy';

const LOOK: Readonly<
  Record<UserStatus, { readonly variant: BadgeVariant; readonly icon: string }>
> = {
  ACTIVE: { variant: 'success', icon: 'check_circle' },
  PENDING: { variant: 'warning', icon: 'schedule' },
  LOCKED: { variant: 'error', icon: 'lock' },
  DISABLED: { variant: 'neutral', icon: 'block' },
};

/**
 * A person's account status (US-020 design §6.1, §12.7, §14.2): icon plus text, never colour
 * alone. `data-status` is the wire value, the stable hook for tests.
 */
@Component({
  selector: 'app-user-status-badge',
  imports: [NxBadge, NxIcon],
  template: `
    <nx-badge
      [variant]="look().variant"
      [attr.data-status]="status()"
      data-testid="user-status-badge"
    >
      <nx-icon [name]="look().icon" />
      {{ label() }}
    </nx-badge>
  `,
})
export class UserStatusBadge {
  readonly status = input.required<UserStatus>();

  protected readonly look = computed(() => LOOK[this.status()]);
  protected readonly label = computed(() => CONSOLE_COPY.badges.status[this.status()]);
}
