import { Component, computed, inject } from '@angular/core';
import { ThemeService } from '../../theme.service';

/** Dark/light switch shared by the public layout and the signed-in shell header. */
@Component({
  selector: 'app-theme-toggle',
  template: `
    <button
      type="button"
      class="theme-toggle"
      data-testid="theme-toggle"
      [attr.aria-label]="label()"
      (click)="themeService.toggle()"
      title="Toggle theme"
    >
      <span class="material-icons" aria-hidden="true">{{ icon() }}</span>
    </button>
  `,
  styleUrl: './theme-toggle.scss',
})
export class ThemeToggle {
  protected readonly themeService = inject(ThemeService);

  /** Icon of the theme a click switches to. */
  protected readonly icon = computed(() =>
    this.themeService.theme() === 'dark' ? 'light_mode' : 'dark_mode',
  );

  protected readonly label = computed(() =>
    this.themeService.theme() === 'dark' ? 'Switch to light mode' : 'Switch to dark mode',
  );
}
