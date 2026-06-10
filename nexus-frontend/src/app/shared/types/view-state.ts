import { AppError } from './app-error';

/**
 * Discriminated union for async view state. Use one signal of this type instead of
 * separate isLoading/error/data fields — the compiler then forces every state to be
 * handled in the template.
 */
export type ViewState<T> =
  | { readonly kind: 'idle' }
  | { readonly kind: 'loading' }
  | { readonly kind: 'success'; readonly data: T }
  | { readonly kind: 'error'; readonly error: AppError };

export const idle = { kind: 'idle' } as const;
export const loading = { kind: 'loading' } as const;

export function success<T>(data: T): ViewState<T> {
  return { kind: 'success', data };
}

export function failure<T>(error: AppError): ViewState<T> {
  return { kind: 'error', error };
}
