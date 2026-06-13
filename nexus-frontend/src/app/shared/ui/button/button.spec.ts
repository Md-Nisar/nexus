import { TestBed } from '@angular/core/testing';
import { By } from '@angular/platform-browser';
import { provideAnimationsAsync } from '@angular/platform-browser/animations/async';
import { describe, it, expect, vi } from 'vitest';
import { NxButton } from './button';

describe('NxButton', () => {
  beforeEach(() => {
    TestBed.configureTestingModule({
      imports: [NxButton],
      providers: [provideAnimationsAsync()],
    });
  });

  it('renders with primary variant by default', () => {
    const fixture = TestBed.createComponent(NxButton);
    fixture.detectChanges();
    const btn = fixture.debugElement.query(By.css('[data-testid="nx-button"]'));
    expect(btn.nativeElement.classList).toContain('nx-btn--primary');
  });

  it('applies the requested variant class', () => {
    const fixture = TestBed.createComponent(NxButton);
    fixture.componentRef.setInput('variant', 'danger');
    fixture.detectChanges();
    const btn = fixture.debugElement.query(By.css('[data-testid="nx-button"]'));
    expect(btn.nativeElement.classList).toContain('nx-btn--danger');
  });

  it('is disabled when disabled=true', () => {
    const fixture = TestBed.createComponent(NxButton);
    fixture.componentRef.setInput('disabled', true);
    fixture.detectChanges();
    const btn: HTMLButtonElement = fixture.debugElement.query(
      By.css('[data-testid="nx-button"]'),
    ).nativeElement;
    expect(btn.disabled).toBe(true);
  });

  it('shows spinner icon when loading', () => {
    const fixture = TestBed.createComponent(NxButton);
    fixture.componentRef.setInput('loading', true);
    fixture.detectChanges();
    const spinner = fixture.debugElement.query(By.css('.nx-btn__spinner'));
    expect(spinner).toBeTruthy();
  });

  it('emits clicked when the button is pressed', () => {
    const fixture = TestBed.createComponent(NxButton);
    fixture.detectChanges();
    const handler = vi.fn();
    fixture.componentInstance.clicked.subscribe(handler);
    fixture.debugElement.query(By.css('[data-testid="nx-button"]')).nativeElement.click();
    expect(handler).toHaveBeenCalledOnce();
  });

  it('shows leading icon when provided', () => {
    const fixture = TestBed.createComponent(NxButton);
    fixture.componentRef.setInput('leadingIcon', 'add');
    fixture.detectChanges();
    const icons = fixture.debugElement.queryAll(By.css('mat-icon'));
    expect(icons.some((i) => i.nativeElement.textContent.trim() === 'add')).toBe(true);
  });
});
