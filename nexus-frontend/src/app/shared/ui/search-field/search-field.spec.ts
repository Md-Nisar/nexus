import { ComponentFixture, TestBed } from '@angular/core/testing';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { expectNoAxeViolations } from '../../testing/axe';
import { NxSearchField } from './search-field';

describe('NxSearchField', () => {
  let fixture: ComponentFixture<NxSearchField>;
  let searches: string[];
  let cleared: number;

  beforeEach(async () => {
    vi.useFakeTimers();
    fixture = TestBed.createComponent(NxSearchField);
    fixture.componentRef.setInput('label', 'Search users');
    searches = [];
    cleared = 0;
    fixture.componentInstance.search.subscribe((v) => searches.push(v));
    fixture.componentInstance.cleared.subscribe(() => cleared++);
    fixture.detectChanges();
  });

  afterEach(() => vi.useRealTimers());

  function input(): HTMLInputElement {
    return fixture.nativeElement.querySelector('[data-testid="nx-search-input"]');
  }

  function type(value: string): void {
    input().value = value;
    input().dispatchEvent(new Event('input'));
  }

  function press(key: string): void {
    input().dispatchEvent(new KeyboardEvent('keydown', { key, bubbles: true }));
  }

  function clearButton(): HTMLButtonElement | null {
    return fixture.nativeElement.querySelector('[data-testid="nx-search-clear"]');
  }

  it('is a search landmark with a search input labelled by label', () => {
    expect(fixture.nativeElement.querySelector('[role="search"]')).not.toBeNull();
    expect(input().type).toBe('search');
    expect(input().getAttribute('aria-label')).toBe('Search users');
  });

  it('debounced mode emits the trimmed value once after 300 ms', () => {
    type('  ali');
    type('  alice  ');
    vi.advanceTimersByTime(299);
    expect(searches).toEqual([]);
    vi.advanceTimersByTime(1);
    expect(searches).toEqual(['alice']);
  });

  it('honours debounceMs', () => {
    fixture.componentRef.setInput('debounceMs', 50);
    type('bob');
    vi.advanceTimersByTime(50);
    expect(searches).toEqual(['bob']);
  });

  it('does not emit the same trimmed value twice in a row', () => {
    type('alice');
    vi.advanceTimersByTime(300);
    type(' alice ');
    vi.advanceTimersByTime(300);
    expect(searches).toEqual(['alice']);
  });

  it('does not emit values shorter than minLength', () => {
    fixture.componentRef.setInput('minLength', 3);
    type('al');
    vi.advanceTimersByTime(300);
    expect(searches).toEqual([]);
    type('ali');
    vi.advanceTimersByTime(300);
    expect(searches).toEqual(['ali']);
  });

  it('submit mode never emits while typing, only on Enter', () => {
    fixture.componentRef.setInput('mode', 'submit');
    type(' a@b.example ');
    vi.advanceTimersByTime(5000);
    expect(searches).toEqual([]);
    press('Enter');
    expect(searches).toEqual(['a@b.example']);
    press('Enter');
    expect(searches).toEqual(['a@b.example']);
  });

  it('Enter in debounced mode emits immediately and cancels the pending debounce', () => {
    type('alice');
    press('Enter');
    expect(searches).toEqual(['alice']);
    vi.advanceTimersByTime(300);
    expect(searches).toEqual(['alice']);
  });

  it('shows the clear button only when there is text', () => {
    expect(clearButton()).toBeNull();
    type('x');
    fixture.detectChanges();
    expect(clearButton()?.getAttribute('aria-label')).toBe('Clear search');
  });

  it('clear button empties the field, emits cleared, and cancels a pending search', () => {
    type('alice');
    fixture.detectChanges();
    clearButton()?.click();
    fixture.detectChanges();
    vi.advanceTimersByTime(300);
    expect(input().value).toBe('');
    expect(cleared).toBe(1);
    expect(searches).toEqual([]);
    expect(clearButton()).toBeNull();
  });

  it('Escape clears and lets the same value be searched again', () => {
    type('alice');
    vi.advanceTimersByTime(300);
    press('Escape');
    fixture.detectChanges();
    expect(input().value).toBe('');
    expect(cleared).toBe(1);
    type('alice');
    vi.advanceTimersByTime(300);
    expect(searches).toEqual(['alice', 'alice']);
  });

  it('Escape on an empty field does not emit cleared', () => {
    press('Escape');
    expect(cleared).toBe(0);
  });

  it('writeValue shows the value without emitting a search', () => {
    fixture.componentInstance.writeValue('preset');
    fixture.detectChanges();
    vi.advanceTimersByTime(300);
    expect(input().value).toBe('preset');
    expect(searches).toEqual([]);
  });

  it('notifies the form control of the raw value', () => {
    const values: string[] = [];
    fixture.componentInstance.registerOnChange((v: string) => values.push(v));
    type(' hi ');
    expect(values).toEqual([' hi ']);
  });

  it('setDisabledState disables the input and hides the clear button', () => {
    type('x');
    fixture.componentInstance.setDisabledState(true);
    fixture.detectChanges();
    expect(input().disabled).toBe(true);
    expect(clearButton()).toBeNull();
  });

  it('has no axe violations', async () => {
    vi.useRealTimers();
    type('x');
    fixture.detectChanges();
    await expectNoAxeViolations(fixture.nativeElement);
  });
});
