import { ComponentFixture, TestBed } from '@angular/core/testing';
import { beforeEach, describe, expect, it } from 'vitest';
import { expectNoAxeViolations } from '../../testing/axe';
import { NxChip } from './chip';

describe('NxChip', () => {
  let fixture: ComponentFixture<NxChip>;

  beforeEach(async () => {
    fixture = TestBed.createComponent(NxChip);
    fixture.componentRef.setInput('label', 'Admins');
    await fixture.whenStable();
  });

  function remove(): HTMLButtonElement | null {
    return fixture.nativeElement.querySelector('[data-testid="nx-chip-remove"]');
  }

  it('renders the label with the default neutral variant', () => {
    const chip = fixture.nativeElement.querySelector('[data-testid="nx-chip"]');
    expect(chip.textContent).toContain('Admins');
    expect(chip.classList).toContain('nx-chip--neutral');
  });

  it.each(['success', 'error', 'warning', 'primary'] as const)(
    'applies the %s variant class',
    async (variant) => {
      fixture.componentRef.setInput('variant', variant);
      await fixture.whenStable();
      const chip = fixture.nativeElement.querySelector('[data-testid="nx-chip"]');
      expect(chip.classList).toContain(`nx-chip--${variant}`);
    },
  );

  it('has no remove button unless removable', () => {
    expect(remove()).toBeNull();
  });

  it('removable shows a button named "Remove {label}" that emits removed', async () => {
    let removed = 0;
    fixture.componentInstance.removed.subscribe(() => removed++);
    fixture.componentRef.setInput('removable', true);
    await fixture.whenStable();
    expect(remove()?.getAttribute('aria-label')).toBe('Remove Admins');
    remove()?.click();
    expect(removed).toBe(1);
  });

  it('has no axe violations, removable or not', async () => {
    await expectNoAxeViolations(fixture.nativeElement);
    fixture.componentRef.setInput('removable', true);
    await fixture.whenStable();
    await expectNoAxeViolations(fixture.nativeElement);
  });
});
