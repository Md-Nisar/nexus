import { Component } from '@angular/core';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { FormControl, ReactiveFormsModule } from '@angular/forms';
import { beforeEach, describe, expect, it } from 'vitest';
import { expectNoAxeViolations } from '../../testing/axe';
import { NxCheckbox } from './checkbox';

@Component({
  imports: [NxCheckbox, ReactiveFormsModule],
  template: `<nx-checkbox label="Accept" [formControl]="control" />`,
})
class HostComponent {
  readonly control = new FormControl(false, { nonNullable: true });
}

describe('NxCheckbox', () => {
  let fixture: ComponentFixture<NxCheckbox>;

  beforeEach(async () => {
    fixture = TestBed.createComponent(NxCheckbox);
    fixture.componentRef.setInput('label', 'Select all');
    await fixture.whenStable();
  });

  function input(): HTMLInputElement {
    return fixture.nativeElement.querySelector('input[type="checkbox"]');
  }

  it('renders the label and a default test id', () => {
    expect(fixture.nativeElement.textContent).toContain('Select all');
    expect(fixture.nativeElement.querySelector('[data-testid="nx-checkbox"]')).not.toBeNull();
  });

  it('honours a custom testId', async () => {
    fixture.componentRef.setInput('testId', 'terms');
    await fixture.whenStable();
    expect(fixture.nativeElement.querySelector('[data-testid="terms"]')).not.toBeNull();
  });

  it('is unchecked, then checked after writeValue(true)', async () => {
    expect(input().checked).toBe(false);
    expect(input().getAttribute('aria-checked')).toBeNull();
    fixture.componentInstance.writeValue(true);
    await fixture.whenStable();
    expect(input().checked).toBe(true);
  });

  it('exposes aria-checked="mixed" when indeterminate', async () => {
    fixture.componentRef.setInput('indeterminate', true);
    await fixture.whenStable();
    expect(input().getAttribute('aria-checked')).toBe('mixed');
  });

  it('emits changed and calls onChange when toggled', async () => {
    const emitted: boolean[] = [];
    const changes: boolean[] = [];
    fixture.componentInstance.changed.subscribe((v) => emitted.push(v));
    fixture.componentInstance.registerOnChange((v: boolean) => changes.push(v));
    input().click();
    await fixture.whenStable();
    expect(emitted).toEqual([true]);
    expect(changes).toEqual([true]);
  });

  it('setDisabledState disables the control and blocks changes', async () => {
    const emitted: boolean[] = [];
    fixture.componentInstance.changed.subscribe((v) => emitted.push(v));
    fixture.componentInstance.setDisabledState(true);
    await fixture.whenStable();
    expect(input().disabled).toBe(true);
    input().click();
    expect(emitted).toEqual([]);
  });

  it('with disabledReason stays focusable, aria-disabled, and described by the reason', async () => {
    fixture.componentRef.setInput('disabled', true);
    fixture.componentRef.setInput('disabledReason', 'Requires the admin role');
    await fixture.whenStable();
    expect(input().disabled).toBe(false);
    expect(input().getAttribute('aria-disabled')).toBe('true');
    const reason = fixture.nativeElement.querySelector('[data-testid="nx-checkbox-reason"]');
    expect(reason.textContent).toContain('Requires the admin role');
    expect(input().getAttribute('aria-describedby')).toBe(reason.id);
  });

  it('does not emit when a disabledReason checkbox is clicked', async () => {
    const emitted: boolean[] = [];
    fixture.componentInstance.changed.subscribe((v) => emitted.push(v));
    fixture.componentRef.setInput('disabled', true);
    fixture.componentRef.setInput('disabledReason', 'Locked');
    await fixture.whenStable();
    input().click();
    expect(emitted).toEqual([]);
  });

  it('works with a reactive form control', async () => {
    const host = TestBed.createComponent(HostComponent);
    await host.whenStable();
    host.nativeElement.querySelector('input').click();
    await host.whenStable();
    expect(host.componentInstance.control.value).toBe(true);
  });

  it('has no axe violations in each state', async () => {
    await expectNoAxeViolations(fixture.nativeElement);
    fixture.componentRef.setInput('indeterminate', true);
    await fixture.whenStable();
    await expectNoAxeViolations(fixture.nativeElement);
    fixture.componentRef.setInput('disabled', true);
    fixture.componentRef.setInput('disabledReason', 'Locked');
    await fixture.whenStable();
    await expectNoAxeViolations(fixture.nativeElement);
  });
});
