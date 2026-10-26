import { Component } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { describe, expect, it } from 'vitest';
import { expectNoAxeViolations } from '../../../shared/testing/axe';
import type { UserStatus } from '../../../shared/types/api/user-directory';
import { UserStatusBadge } from './user-status-badge';

@Component({
  imports: [UserStatusBadge],
  template: `<app-user-status-badge [status]="status" />`,
})
class Host {
  status: UserStatus = 'ACTIVE';
}

function render(status: UserStatus): HTMLElement {
  const fixture = TestBed.createComponent(Host);
  fixture.componentInstance.status = status;
  fixture.detectChanges();
  return (fixture.nativeElement as HTMLElement).querySelector(
    '[data-testid="user-status-badge"]',
  ) as HTMLElement;
}

describe('UserStatusBadge (US-020 design §6.1, §14.2)', () => {
  it.each([
    ['ACTIVE', 'Active', 'success'],
    ['PENDING', 'Pending', 'warning'],
    ['LOCKED', 'Locked', 'error'],
    ['DISABLED', 'Disabled', 'neutral'],
  ] as const)('shows %s as "%s" with an icon, never colour alone', (status, label, variant) => {
    const badge = render(status);

    expect(badge.textContent?.replace(/\s+/g, ' ')).toContain(label);
    expect(badge.querySelector('nx-icon')).not.toBeNull();
    expect(badge.getAttribute('data-status')).toBe(status);
    expect(badge.classList).toContain(`nx-badge--${variant}`);
  });

  it('has no axe violations', async () => {
    await expectNoAxeViolations(render('LOCKED'));
  });
});
