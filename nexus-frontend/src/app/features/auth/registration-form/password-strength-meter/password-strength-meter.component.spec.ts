import { TestBed } from '@angular/core/testing';
import { By } from '@angular/platform-browser';
import { provideAnimationsAsync } from '@angular/platform-browser/animations/async';
import { describe, it, expect, beforeEach } from 'vitest';
import { PasswordStrengthMeterComponent } from './password-strength-meter.component';

describe('PasswordStrengthMeterComponent', () => {
  beforeEach(() => {
    TestBed.configureTestingModule({
      imports: [PasswordStrengthMeterComponent],
      providers: [provideAnimationsAsync()],
    });
  });

  function setup(password: string) {
    const fixture = TestBed.createComponent(PasswordStrengthMeterComponent);
    fixture.componentRef.setInput('password', password);
    fixture.detectChanges();
    return fixture;
  }

  function ariaLabel(fixture: ReturnType<typeof setup>): string {
    return fixture.debugElement
      .query(By.css('[role="status"]'))
      .nativeElement.getAttribute('aria-label') as string;
  }

  function labelText(fixture: ReturnType<typeof setup>): string | null {
    const el = fixture.debugElement.query(By.css('.strength-meter__label'));
    return el ? el.nativeElement.textContent.trim() : null;
  }

  it('should report Very Weak for empty password (score 0)', () => {
    expect(ariaLabel(setup(''))).toContain('Very Weak');
  });

  it('should report Weak for abc123 (score 1: digit criterion only)', () => {
    const label = ariaLabel(setup('abc123'));
    expect(label).toContain('Weak');
    expect(label).not.toContain('Very Weak');
  });

  it('should report Very Strong for Str0ng!Pass99 (score 4: all criteria)', () => {
    expect(ariaLabel(setup('Str0ng!Pass99'))).toContain('Very Strong');
  });

  it('should hide label for empty password and show it for a strong password', () => {
    expect(labelText(setup(''))).toBeNull();
    expect(labelText(setup('Str0ng!Pass99'))).toBe('Very Strong');
  });

  it('should report Fair for password12Chars (score 2: length + uppercase criteria)', () => {
    // Length ≥ 12 (+1), uppercase (+1): total score 2 → Fair
    const label = ariaLabel(setup('ABCDEFghijkl'));
    expect(label).toContain('Fair');
  });

  it('should report Strong for password with length + uppercase + digit (score 3)', () => {
    // Length ≥ 12 (+1), uppercase (+1), digit (+1): total score 3 → Strong
    const label = ariaLabel(setup('ABCDEFghij1k'));
    expect(label).toContain('Strong');
    expect(label).not.toContain('Very Strong');
  });

  it('should include password strength label in aria-label for screen reader accessibility', () => {
    const label = ariaLabel(setup('Str0ng!Pass99'));
    expect(label).toMatch(/^Password strength:/);
  });
});
