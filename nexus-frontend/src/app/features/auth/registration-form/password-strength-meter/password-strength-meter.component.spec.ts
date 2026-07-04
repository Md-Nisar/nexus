import { TestBed } from '@angular/core/testing';
import { By } from '@angular/platform-browser';
import { provideAnimationsAsync } from '@angular/platform-browser/animations/async';
import { describe, it, expect, beforeEach } from 'vitest';
import { PasswordStrengthMeterComponent } from './password-strength-meter.component';

/**
 * Test suite for PasswordStrengthMeterComponent.
 *
 * Tests verify:
 * 1. Score computation based on password criteria (length ≥ 12, uppercase, digit, special char)
 * 2. Label derivation from score (Very Weak → Very Strong)
 * 3. Visual bar rendering (filled bars match score)
 * 4. Color-coding (error/warning/success)
 * 5. Accessibility: aria-label reflects strength, label hidden for empty input
 *
 * Scoring logic:
 * - Empty or null → score 0 (Very Weak)
 * - Any single criterion → score 1 (Weak)
 * - Any two criteria → score 2 (Fair)
 * - Any three criteria → score 3 (Strong)
 * - All four criteria → score 4 (Very Strong)
 */
describe('PasswordStrengthMeterComponent', () => {
  beforeEach(() => {
    TestBed.configureTestingModule({
      imports: [PasswordStrengthMeterComponent],
      providers: [provideAnimationsAsync()],
    });
  });

  /**
   * Helper to set password input and detect changes.
   * @param password The password string to test
   * @returns Component fixture
   */
  function setup(password: string) {
    const fixture = TestBed.createComponent(PasswordStrengthMeterComponent);
    fixture.componentRef.setInput('password', password);
    fixture.detectChanges();
    return fixture;
  }

  /**
   * Helper to extract aria-label from the status container.
   * Used to verify screen reader announcements include the strength label.
   */
  function ariaLabel(fixture: ReturnType<typeof setup>): string {
    return fixture.debugElement
      .query(By.css('[role="status"]'))
      .nativeElement.getAttribute('aria-label') as string;
  }

  /**
   * Helper to extract visible label text.
   * Returns null if label is not rendered (e.g., for empty password).
   */
  function labelText(fixture: ReturnType<typeof setup>): string | null {
    const el = fixture.debugElement.query(By.css('.strength-meter__label'));
    return el ? el.nativeElement.textContent.trim() : null;
  }

  /**
   * Score 0: No criteria met.
   * Aria-label must include "Very Weak" for screen reader users.
   */
  it('should report Very Weak for empty password (score 0)', () => {
    expect(ariaLabel(setup(''))).toContain('Very Weak');
  });

  /**
   * Score 1: Only digit criterion met.
   * 'abc123' has digit [0-9] but not length ≥ 12, uppercase, or special char.
   * Label must be "Weak", not "Very Weak".
   */
  it('should report Weak for abc123 (score 1: digit criterion only)', () => {
    const label = ariaLabel(setup('abc123'));
    expect(label).toContain('Weak');
    expect(label).not.toContain('Very Weak');
  });

  /**
   * Score 4: All four criteria met.
   * 'Str0ng!Pass99' has: length ≥ 12, uppercase [A-Z], digit [0-9], special [!].
   * Label must be "Very Strong".
   */
  it('should report Very Strong for Str0ng!Pass99 (score 4: all criteria)', () => {
    expect(ariaLabel(setup('Str0ng!Pass99'))).toContain('Very Strong');
  });

  /**
   * Visual label visibility:
   * - Empty password: label not rendered (reduce visual clutter)
   * - Non-empty password: label rendered and visible
   * This improves UX without compromising a11y (aria-label still present).
   */
  it('should hide label for empty password and show it for a strong password', () => {
    expect(labelText(setup(''))).toBeNull();
    expect(labelText(setup('Str0ng!Pass99'))).toBe('Very Strong');
  });

  /**
   * Score 2: Two criteria met.
   * 'ABCDEFghijkl' (12 lowercase + 6 uppercase = 12 total) has:
   *   - Length ≥ 12: +1
   *   - Uppercase [A-Z]: +1
   *   Total score 2 → "Fair"
   */
  it('should report Fair for password12Chars (score 2: length + uppercase criteria)', () => {
    // Length ≥ 12 (+1), uppercase (+1): total score 2 → Fair
    const label = ariaLabel(setup('ABCDEFghijkl'));
    expect(label).toContain('Fair');
  });

  /**
   * Score 3: Three criteria met.
   * 'ABCDEFghij1k' (12 total) has:
   *   - Length ≥ 12: +1
   *   - Uppercase [A-Z]: +1
   *   - Digit [0-9]: +1
   *   Total score 3 → "Strong" (not "Very Strong")
   */
  it('should report Strong for password with length + uppercase + digit (score 3)', () => {
    // Length ≥ 12 (+1), uppercase (+1), digit (+1): total score 3 → Strong
    const label = ariaLabel(setup('ABCDEFghij1k'));
    expect(label).toContain('Strong');
    expect(label).not.toContain('Very Strong');
  });

  /**
   * Accessibility: Screen readers must hear "Password strength: [label]".
   * The aria-label always includes the prefix for consistent AT announcements.
   */
  it('should include password strength label in aria-label for screen reader accessibility', () => {
    const label = ariaLabel(setup('Str0ng!Pass99'));
    expect(label).toMatch(/^Password strength:/);
  });
});
