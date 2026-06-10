import { InjectionToken } from '@angular/core';
import { environment } from '../../../environments/environment';

export type LogLevel = 'debug' | 'info' | 'warn' | 'error';

export interface AppConfig {
  readonly production: boolean;
  readonly apiBaseUrl: string;
  readonly logLevel: LogLevel;
}

/**
 * Single injection point for environment configuration. Feature code injects this token
 * instead of importing environment files, so tests can provide their own values.
 */
export const APP_CONFIG = new InjectionToken<AppConfig>('APP_CONFIG', {
  providedIn: 'root',
  factory: (): AppConfig => environment,
});
