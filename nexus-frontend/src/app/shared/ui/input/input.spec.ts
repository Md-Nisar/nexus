import { TestBed } from '@angular/core/testing';
import { By } from '@angular/platform-browser';
import { provideAnimationsAsync } from '@angular/platform-browser/animations/async';
import { describe, it, expect, vi } from 'vitest';
import { NxInput } from './input';

describe('NxInput', () => {
  beforeEach(() => {
    TestBed.configureTestingModule({
      imports: [NxInput],
      providers: [provideAnimationsAsync()],
    });
  });

  it('renders the input element', () => {
    const fixture = TestBed.createComponent(NxInput);
    fixture.detectChanges();
    expect(fixture.debugElement.query(By.css('[data-testid="nx-input"]'))).toBeTruthy();
  });

  it('shows label when provided', () => {
    const fixture = TestBed.createComponent(NxInput);
    fixture.componentRef.setInput('label', 'Email');
    fixture.detectChanges();
    expect(fixture.nativeElement.textContent).toContain('Email');
  });

  it('emits valueChange on user input', () => {
    const fixture = TestBed.createComponent(NxInput);
    fixture.detectChanges();
    const handler = vi.fn();
    fixture.componentInstance.valueChange.subscribe(handler);
    const input: HTMLInputElement = fixture.debugElement.query(
      By.css('[data-testid="nx-input"]'),
    ).nativeElement;
    input.value = 'hello';
    input.dispatchEvent(new Event('input'));
    expect(handler).toHaveBeenCalledWith('hello');
  });

  it('is disabled when setDisabledState(true) is called', () => {
    const fixture = TestBed.createComponent(NxInput);
    fixture.detectChanges();
    fixture.componentInstance.setDisabledState(true);
    fixture.detectChanges();
    const input: HTMLInputElement = fixture.debugElement.query(
      By.css('[data-testid="nx-input"]'),
    ).nativeElement;
    expect(input.disabled).toBe(true);
  });

  it('appends describedBy ids to the input aria-describedby, beside the hint', async () => {
    const fixture = TestBed.createComponent(NxInput);
    fixture.componentRef.setInput('hint', 'Letters only');
    fixture.componentRef.setInput('describedBy', 'name-counter name-error');
    fixture.detectChanges();
    await fixture.whenStable();
    fixture.detectChanges();
    const input: HTMLInputElement = fixture.debugElement.query(
      By.css('[data-testid="nx-input"]'),
    ).nativeElement;
    const ids = (input.getAttribute('aria-describedby') ?? '').split(' ');
    expect(ids).toContain('name-counter');
    expect(ids).toContain('name-error');
    expect(ids.some((id) => id.startsWith('mat-mdc-hint'))).toBe(true);
  });

  it('focus() moves focus to the input', () => {
    const fixture = TestBed.createComponent(NxInput);
    fixture.detectChanges();
    fixture.componentInstance.focus();
    expect(document.activeElement?.getAttribute('data-testid')).toBe('nx-input');
  });

  it('shows hint text when provided', () => {
    const fixture = TestBed.createComponent(NxInput);
    fixture.componentRef.setInput('hint', 'Enter your email');
    fixture.detectChanges();
    expect(fixture.nativeElement.textContent).toContain('Enter your email');
  });
});
