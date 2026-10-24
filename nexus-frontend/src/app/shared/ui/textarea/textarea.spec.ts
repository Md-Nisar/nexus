import { Component, signal, viewChild } from '@angular/core';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { FormControl, ReactiveFormsModule } from '@angular/forms';
import { provideAnimationsAsync } from '@angular/platform-browser/animations/async';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { expectNoAxeViolations } from '../../testing/axe';
import { NxTextarea } from './textarea';

@Component({
  imports: [NxTextarea, ReactiveFormsModule],
  template: `
    <nx-textarea
      [formControl]="control"
      [label]="label()"
      [hint]="hint()"
      [error]="error()"
      [maxLength]="maxLength()"
      [rows]="rows()"
      [testId]="testId()"
    />
  `,
})
class Host {
  readonly control = new FormControl('', { nonNullable: true });
  readonly label = signal('Description');
  readonly hint = signal('');
  readonly error = signal('');
  readonly maxLength = signal<number | null>(255);
  readonly rows = signal(4);
  readonly testId = signal('role-description');
  readonly textarea = viewChild.required(NxTextarea);
}

describe('NxTextarea', () => {
  let fixture: ComponentFixture<Host>;

  function el(): HTMLElement {
    return fixture.nativeElement as HTMLElement;
  }

  function field(): HTMLTextAreaElement {
    return el().querySelector('textarea') as HTMLTextAreaElement;
  }

  function describedBy(): string[] {
    return (field().getAttribute('aria-describedby') ?? '').split(' ').filter(Boolean);
  }

  function byId(id: string): HTMLElement | null {
    return el().querySelector(`[id="${id}"]`);
  }

  async function render(change: (host: Host) => void = () => undefined): Promise<void> {
    fixture = TestBed.createComponent(Host);
    change(fixture.componentInstance);
    fixture.detectChanges();
    await fixture.whenStable();
    fixture.detectChanges();
  }

  beforeEach(() => {
    TestBed.configureTestingModule({ providers: [provideAnimationsAsync('noop')] });
  });

  it('renders a textarea with a visible label tied to it, its rows and its test id', async () => {
    await render();
    const label = el().querySelector('label');
    expect(label?.textContent?.trim()).toBe('Description');
    expect(label?.getAttribute('for')).toBe(field().id);
    expect(field().rows).toBe(4);
    expect(field().getAttribute('data-testid')).toBe('role-description');
    // The counter and the validator say the limit; the browser never cuts a paste silently.
    expect(field().hasAttribute('maxlength')).toBe(false);
  });

  it('shows the hint as text linked through aria-describedby', async () => {
    await render((host) => host.hint.set('Plain text only'));
    const hint = describedBy()
      .map(byId)
      .find((node) => node?.textContent?.trim() === 'Plain text only');
    expect(hint).toBeDefined();
  });

  it('shows the counter "{n} of {max}", linked and not a live region', async () => {
    await render((host) => host.control.setValue('Handles tickets'));
    const counter = el().querySelector('[data-testid="nx-textarea-counter"]') as HTMLElement;
    expect(counter.textContent?.trim()).toBe('15 of 255');
    expect(describedBy()).toContain(counter.id);
    expect(counter.getAttribute('aria-live')).toBeNull();
    expect(counter.getAttribute('role')).toBeNull();
    expect(counter.closest('[aria-live],[role="status"],[role="alert"]')).toBeNull();
  });

  it('updates the counter as the user types', async () => {
    await render();
    field().value = 'abc';
    field().dispatchEvent(new Event('input'));
    fixture.detectChanges();
    expect(el().querySelector('[data-testid="nx-textarea-counter"]')?.textContent?.trim()).toBe(
      '3 of 255',
    );
  });

  it('renders no counter without a maximum', async () => {
    await render((host) => host.maxLength.set(null));
    expect(el().querySelector('[data-testid="nx-textarea-counter"]')).toBeNull();
  });

  it('links the error, marks the field invalid, and clears both without an error', async () => {
    await render((host) => host.error.set('Use 255 characters or fewer'));
    const error = el().querySelector('[data-testid="nx-textarea-error"]') as HTMLElement;
    expect(error.textContent?.trim()).toBe('Use 255 characters or fewer');
    expect(describedBy()).toContain(error.id);
    expect(field().getAttribute('aria-invalid')).toBe('true');

    fixture.componentInstance.error.set('');
    fixture.detectChanges();
    await fixture.whenStable();
    fixture.detectChanges();
    expect(el().querySelector('[data-testid="nx-textarea-error"]')).toBeNull();
    expect(describedBy()).not.toContain(error.id);
    expect(field().getAttribute('aria-invalid')).toBe('false');
  });

  it('writeValue shows the form value; null shows empty', async () => {
    await render((host) => host.control.setValue('From the form'));
    expect(field().value).toBe('From the form');
    fixture.componentInstance.textarea().writeValue(null);
    fixture.detectChanges();
    expect(field().value).toBe('');
  });

  it('reports typing to the form control and marks it touched on blur', async () => {
    await render();
    field().value = 'Typed';
    field().dispatchEvent(new Event('input'));
    field().dispatchEvent(new Event('blur'));
    expect(fixture.componentInstance.control.value).toBe('Typed');
    expect(fixture.componentInstance.control.touched).toBe(true);
  });

  it('setDisabledState disables and re-enables the field', async () => {
    await render();
    fixture.componentInstance.control.disable();
    fixture.detectChanges();
    expect(field().disabled).toBe(true);
    fixture.componentInstance.control.enable();
    fixture.detectChanges();
    expect(field().disabled).toBe(false);
  });

  it('focus() moves focus to the field', async () => {
    await render();
    fixture.componentInstance.textarea().focus();
    expect(document.activeElement).toBe(field());
  });

  it('keeps an explicit input id for the label and links', async () => {
    const single = TestBed.createComponent(NxTextarea);
    single.componentRef.setInput('label', 'Notes');
    single.componentRef.setInput('inputId', 'notes-field');
    single.detectChanges();
    const textarea = (single.nativeElement as HTMLElement).querySelector(
      'textarea',
    ) as HTMLTextAreaElement;
    expect(textarea.id).toBe('notes-field');
    const spy = vi.fn();
    single.componentInstance.registerOnChange(spy);
    textarea.value = 'x';
    textarea.dispatchEvent(new Event('input'));
    expect(spy).toHaveBeenCalledWith('x');
  });

  it('has no axe violations with a hint, a counter and an error', async () => {
    await render((host) => {
      host.hint.set('Plain text only');
      host.error.set('Remove line breaks and control characters');
    });
    await expectNoAxeViolations(el());
  });
});
