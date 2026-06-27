import { Service, signal } from '@angular/core';

export type Theme = 'dark' | 'light';

const STORAGE_KEY = 'nx-theme';

@Service()
export class ThemeService {
  private readonly _theme = signal<Theme>(this.initialTheme());
  readonly theme = this._theme.asReadonly();

  constructor() {
    document.documentElement.setAttribute('data-theme', this._theme());
  }

  toggle(): void {
    const next: Theme = this._theme() === 'dark' ? 'light' : 'dark';
    this._theme.set(next);
    document.documentElement.setAttribute('data-theme', next);
    localStorage.setItem(STORAGE_KEY, next);
  }

  private initialTheme(): Theme {
    const stored = localStorage.getItem(STORAGE_KEY);
    if (stored === 'light' || stored === 'dark') return stored;
    return 'dark';
  }
}
