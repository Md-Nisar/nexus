import { Component } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { describe, expect, it } from 'vitest';
import { expectNoAxeViolations } from '../../../shared/testing/axe';
import { SystemRoleBadge } from './system-role-badge';

@Component({
  imports: [SystemRoleBadge],
  template: `<app-system-role-badge [isSystemRole]="isSystemRole" />`,
})
class Host {
  isSystemRole = true;
}

function render(isSystemRole: boolean): HTMLElement {
  const fixture = TestBed.createComponent(Host);
  fixture.componentInstance.isSystemRole = isSystemRole;
  fixture.detectChanges();
  return fixture.nativeElement;
}

describe('SystemRoleBadge', () => {
  it('says "System" with an icon, never colour alone', () => {
    const root = render(true);
    const badge = root.querySelector('[data-testid="system-role-badge"]') as HTMLElement;
    expect(badge.textContent?.replace(/\s+/g, ' ').trim()).toContain('System');
    expect(badge.querySelector('nx-icon')).not.toBeNull();
    expect(badge.getAttribute('data-kind')).toBe('system');
  });

  it('says "Custom" for a custom role', () => {
    const root = render(false);
    const badge = root.querySelector('[data-testid="system-role-badge"]') as HTMLElement;
    expect(badge.textContent?.trim()).toBe('Custom');
    expect(badge.getAttribute('data-kind')).toBe('custom');
  });

  it('has no axe violations', async () => {
    await expectNoAxeViolations(render(true));
  });
});
