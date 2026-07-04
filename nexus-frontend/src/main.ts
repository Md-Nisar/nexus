import { bootstrapApplication } from '@angular/platform-browser';
import { appConfig } from './app/app.config';
import { App } from './app/app';

/**
 * Application bootstrap entry point for Nexus Frontend.
 *
 * This file bootstraps the Angular application using the standalone component API:
 * - Root component: {@link App} (the root component selector is 'app-root')
 * - Configuration: {@link appConfig} provides all providers, interceptors, and routes
 *
 * Bootstrap flow:
 * 1. Angular initializes the platform and bootstrap zone
 * 2. appConfig providers are instantiated and registered (HTTP, Router, Animations, etc.)
 * 3. The App component is created and mounted to index.html's <app-root> element
 * 4. Router outlets and feature routes are initialized
 * 5. Change detection runs in OnPush mode for performance (set at component level)
 *
 * Error handling:
 * Bootstrap errors (provider instantiation failures, component initialization errors)
 * are logged to console. In production, consider sending to an error tracking service.
 *
 * @see {@link app.config.ts} for provider configuration
 * @see {@link app.ts} for root component definition
 */
bootstrapApplication(App, appConfig).catch((err) => console.error(err));
