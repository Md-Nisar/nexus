import { Component, computed, input } from '@angular/core';
import { BadgeVariant, NxBadge, NxIcon } from '../../../shared/ui';
import type { UserDirectoryEntry } from '../../../shared/types/api/user-directory';
import { CONSOLE_COPY } from '../copy/console-copy';
import { UserStatusBadge } from './user-status-badge';
import { UserText } from './user-text';

interface VerifiedLook {
  readonly label: string;
  readonly icon: string;
  readonly variant: BadgeVariant;
}

const VERIFIED: VerifiedLook = {
  label: CONSOLE_COPY.badges.verified,
  icon: 'verified',
  variant: 'success',
};
const UNVERIFIED: VerifiedLook = {
  label: CONSOLE_COPY.badges.unverified,
  icon: 'unpublished',
  variant: 'warning',
};

/**
 * Who an assign or revoke dialog acts on, shown at the moment of choice (US-020 design §12.9,
 * §12.10; threat model T-S15, RC-68 item 2): the address through {@link UserText} in `email`
 * mode, so every hidden character is a visible token and the "Contains hidden characters" badge
 * shows with its explanation; the account status; and the Verified or "Unverified email" badge.
 *
 * Without a directory entry it shows the `{person}` fallback, "this person" (FR-X5), and no badges.
 * Text only, by interpolation; nothing here is logged.
 */
@Component({
  selector: 'app-target-identity',
  imports: [NxBadge, NxIcon, UserStatusBadge, UserText],
  template: `
    <div class="target-identity" data-testid="target-identity">
      @if (target(); as person) {
        <span class="target-identity__address">
          <app-user-text [text]="person.email" mode="email" />
        </span>
        <span class="target-identity__badges">
          <app-user-status-badge [status]="person.status" />
          <nx-badge
            [variant]="verified().variant"
            [attr.data-verified]="person.emailVerified"
            data-testid="target-identity-verified"
          >
            <nx-icon [name]="verified().icon" />
            {{ verified().label }}
          </nx-badge>
        </span>
      } @else {
        <span class="target-identity__address">{{ copy.assign.person }}</span>
      }
    </div>
  `,
  styles: `
    .target-identity {
      display: flex;
      flex-wrap: wrap;
      align-items: center;
      gap: var(--nx-space-2) var(--nx-space-3);
      color: var(--nx-color-on-surface);
      font-size: var(--nx-text-sm);
    }

    .target-identity__address {
      min-width: 0;
      overflow-wrap: anywhere;
    }

    .target-identity__badges {
      display: inline-flex;
      flex-wrap: wrap;
      gap: var(--nx-space-2);
    }
  `,
})
export class TargetIdentity {
  /** The person, or `null` when the caller has no directory entry for them. */
  readonly target = input.required<UserDirectoryEntry | null>();

  protected readonly copy = CONSOLE_COPY;
  protected readonly verified = computed(() =>
    this.target()?.emailVerified ? VERIFIED : UNVERIFIED,
  );
}
