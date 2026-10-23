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

  describe('ariaDisabled: disabled but focusable (US-020 design §12.0, §13)', () => {
    function native(fixture: ReturnType<typeof TestBed.createComponent<NxButton>>) {
      return fixture.debugElement.query(By.css('[data-testid="nx-button"]'))
        .nativeElement as HTMLButtonElement;
    }

    it('sets no aria-disabled or aria-describedby by default', () => {
      const fixture = TestBed.createComponent(NxButton);
      fixture.detectChanges();
      expect(native(fixture).hasAttribute('aria-disabled')).toBe(false);
      expect(native(fixture).hasAttribute('aria-describedby')).toBe(false);
    });

    it('marks the button aria-disabled and keeps it in the tab order', () => {
      const fixture = TestBed.createComponent(NxButton);
      fixture.componentRef.setInput('ariaDisabled', true);
      fixture.detectChanges();
      const btn = native(fixture);
      expect(btn.getAttribute('aria-disabled')).toBe('true');
      expect(btn.disabled).toBe(false);
      expect(btn.hasAttribute('tabindex')).toBe(false);
      btn.focus();
      expect(document.activeElement).toBe(btn);
    });

    it('swallows activation: no clicked output and no click reaches the host element', () => {
      const fixture = TestBed.createComponent(NxButton);
      fixture.componentRef.setInput('ariaDisabled', true);
      fixture.detectChanges();
      const clicked = vi.fn();
      const hostClick = vi.fn();
      fixture.componentInstance.clicked.subscribe(clicked);
      (fixture.nativeElement as HTMLElement).addEventListener('click', hostClick);

      native(fixture).click();

      expect(clicked).not.toHaveBeenCalled();
      expect(hostClick).not.toHaveBeenCalled();
    });

    it('does not submit its form while aria-disabled', () => {
      const fixture = TestBed.createComponent(NxButton);
      fixture.componentRef.setInput('type', 'submit');
      fixture.componentRef.setInput('ariaDisabled', true);
      fixture.detectChanges();
      const event = new MouseEvent('click', { bubbles: true, cancelable: true });

      native(fixture).dispatchEvent(event);

      expect(event.defaultPrevented).toBe(true);
    });

    it('emits clicked again once aria-disabled is cleared', () => {
      const fixture = TestBed.createComponent(NxButton);
      fixture.componentRef.setInput('ariaDisabled', true);
      fixture.detectChanges();
      fixture.componentRef.setInput('ariaDisabled', false);
      fixture.detectChanges();
      const clicked = vi.fn();
      fixture.componentInstance.clicked.subscribe(clicked);

      native(fixture).click();

      expect(native(fixture).hasAttribute('aria-disabled')).toBe(false);
      expect(clicked).toHaveBeenCalledOnce();
    });

    it('links the visible reason through aria-describedby', () => {
      const fixture = TestBed.createComponent(NxButton);
      fixture.componentRef.setInput('ariaDisabled', true);
      fixture.componentRef.setInput('ariaDescribedBy', 'reason-1');
      fixture.detectChanges();
      expect(native(fixture).getAttribute('aria-describedby')).toBe('reason-1');
    });
  });
});
