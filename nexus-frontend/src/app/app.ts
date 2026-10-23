import { Component, inject } from '@angular/core';
import { RouterOutlet } from '@angular/router';
import { ThemeService } from './core/theme.service';

/**
 * Root component: a router outlet only. Layouts (`PublicLayout`, `Shell`) are route components
 * under `core/layout`.
 *
 * It instantiates {@link ThemeService} at bootstrap so the `data-theme` attribute is applied
 * before any layout renders, including the lazily loaded shell.
 */
@Component({
  selector: 'app-root',
  imports: [RouterOutlet],
  templateUrl: './app.html',
})
export class App {
  constructor() {
    inject(ThemeService);
  }
}
