import { TestBed } from '@angular/core/testing';
import { describe, expect, it } from 'vitest';
import { ThemeService } from '../../theme.service';
import { ThemeToggle } from './theme-toggle';

describe('ThemeToggle', () => {
  function setup() {
    TestBed.configureTestingModule({ imports: [ThemeToggle] });
    const fixture = TestBed.createComponent(ThemeToggle);
    fixture.detectChanges();
    const button = fixture.nativeElement.querySelector('button') as HTMLButtonElement;
    return { fixture, button, theme: TestBed.inject(ThemeService) };
  }

  it('labels the action and shows the icon of the opposite theme', () => {
    const { button, theme } = setup();
    const dark = theme.theme() === 'dark';
    expect(button.getAttribute('aria-label')).toBe(
      dark ? 'Switch to light mode' : 'Switch to dark mode',
    );
    expect(button.textContent).toContain(dark ? 'light_mode' : 'dark_mode');
  });

  it('toggles the theme and updates the label on click', () => {
    const { fixture, button, theme } = setup();
    const before = theme.theme();
    button.click();
    fixture.detectChanges();
    expect(theme.theme()).not.toBe(before);
    expect(button.getAttribute('aria-label')).toBe(
      before === 'dark' ? 'Switch to dark mode' : 'Switch to light mode',
    );
  });
});
