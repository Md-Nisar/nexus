import type { AppError } from '../../../shared/types/app-error';

/**
 * State of one console store load (US-020 design §6.2). Stores own a signal of this union and
 * catch every failure into `error`, so an `AppError` never reaches `GlobalErrorHandler` (RC-73).
 *
 * `failedAt` (epoch ms) is when the failure was recorded: the `UnavailableNotice` cool-down for a
 * 503 `AUTH_005` runs from it (RC-75).
 */
export type LoadState<T> =
  | { readonly status: 'idle' }
  | { readonly status: 'loading' }
  | { readonly status: 'ready'; readonly data: T; readonly loadedAt: number }
  | { readonly status: 'error'; readonly error: AppError; readonly failedAt: number };
