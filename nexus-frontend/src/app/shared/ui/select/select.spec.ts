import { TestBed } from '@angular/core/testing';
import { By } from '@angular/platform-browser';
import { provideAnimationsAsync } from '@angular/platform-browser/animations/async';
import { describe, it, expect } from 'vitest';
import { NxSelect, SelectOption } from './select';

const OPTS: SelectOption[] = [
  { label: 'Alpha', value: 'alpha' },
  { label: 'Beta', value: 'beta' },
];

describe('NxSelect', () => {
  beforeEach(() => {
    TestBed.configureTestingModule({
      imports: [NxSelect],
      providers: [provideAnimationsAsync()],
    });
  });

  it('renders the select trigger', () => {
    const fixture = TestBed.createComponent(NxSelect);
    fixture.componentRef.setInput('options', OPTS);
    fixture.detectChanges();
    expect(fixture.debugElement.query(By.css('[data-testid="nx-select"]'))).toBeTruthy();
  });

  it('shows label when provided', () => {
    const fixture = TestBed.createComponent(NxSelect);
    fixture.componentRef.setInput('label', 'Country');
    fixture.componentRef.setInput('options', OPTS);
    fixture.detectChanges();
    expect(fixture.nativeElement.textContent).toContain('Country');
  });

  it('calls writeValue without error', () => {
    const fixture = TestBed.createComponent(NxSelect);
    fixture.componentRef.setInput('options', OPTS);
    fixture.detectChanges();
    expect(() => fixture.componentInstance.writeValue('alpha')).not.toThrow();
  });

  it('is disabled after setDisabledState(true)', () => {
    const fixture = TestBed.createComponent(NxSelect);
    fixture.componentRef.setInput('options', OPTS);
    fixture.detectChanges();
    fixture.componentInstance.setDisabledState(true);
    fixture.detectChanges();
    const trigger = fixture.debugElement.query(By.css('[data-testid="nx-select"]'));
    expect(trigger.nativeElement.getAttribute('aria-disabled')).toBe('true');
  });
});
