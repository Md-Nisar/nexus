import { AppError } from './app-error';

/**
 * Discriminated union for async view state management.
 *
 * Replaces separate isLoading/error/data signals with a single {@link ViewState} signal.
 * The TypeScript compiler enforces exhaustive pattern matching in templates (@switch)
 * and logic, eliminating race conditions (e.g. both loading and error being true).
 *
 * State transitions:
 * - idle → loading (on user action)
 * - loading → success (on success)
 * - loading → error (on failure)
 * - any state → idle (on reset)
 *
 * @template T The shape of the success data payload.
 *
 * @example
 * ```typescript
 * // Component logic
 * const viewState = signal<ViewState<User>>('idle');
 *
 * loadUser() {
 *   viewState.set(loading);
 *   this.service.getUser(id).subscribe({
 *     next: (user) => viewState.set(success(user)),
 *     error: (err) => viewState.set(failure(err)),
 *   });
 * }
 *
 * // Template: forces all four states to be handled
 * @switch (viewState()) {
 *   @case ({ kind: 'idle' }) {
 *     <p>Ready to load</p>
 *   }
 *   @case ({ kind: 'loading' }) {
 *     <app-spinner />
 *   }
 *   @case ({ kind: 'success', data: user }) {
 *     <p>{{ user.email }}</p>
 *   }
 *   @case ({ kind: 'error', error }) {
 *     <app-error-message [error]="error" />
 *   }
 * }
 * ```
 */
export type ViewState<T> = IdleState | LoadingState | SuccessState<T> | ErrorState;

/**
 * Idle state: no operation in flight, no data loaded.
 *
 * Initial state before any user action. Can also represent a reset state
 * after dismissing an error or clearing a view.
 */
interface IdleState {
  readonly kind: 'idle';
}

/**
 * Loading state: async operation in flight.
 *
 * Show a spinner or skeleton placeholder. Do not show stale data from a
 * previous successful load (avoid "flash of old data").
 */
interface LoadingState {
  readonly kind: 'loading';
}

/**
 * Success state: async operation completed successfully.
 *
 * Render the loaded {@link data}. The data shape is bound to the generic type T
 * at compile time, ensuring type safety in the template.
 *
 * @template T The shape of the loaded data (e.g. User, Post[], etc.).
 */
interface SuccessState<T> {
  readonly kind: 'success';
  /**
   * The loaded data payload. Type-safe; guaranteed to be the shape of T.
   */
  readonly data: T;
}

/**
 * Error state: async operation failed.
 *
 * Render an error message from {@link error.message}. The {@link error.code}
 * field can drive error-specific recovery flows (e.g. "ACCOUNT_LOCKED" →
 * show unlock instructions).
 */
interface ErrorState {
  readonly kind: 'error';
  /**
   * Normalized error details (see {@link AppError}).
   * Safe to display to the user; never log or persist.
   */
  readonly error: AppError;
}

/**
 * Idle state constant.
 *
 * Use to initialize signals or reset view state:
 * ```typescript
 * viewState.set(idle);
 * ```
 */
export const idle = { kind: 'idle' } as const;

/**
 * Loading state constant.
 *
 * Use to set view state while an async operation is in flight:
 * ```typescript
 * viewState.set(loading);
 * ```
 */
export const loading = { kind: 'loading' } as const;

/**
 * Factory for success state.
 *
 * Wraps loaded data in a {@link SuccessState}. Used after a successful
 * async operation to transition to the success state with type-safe data.
 *
 * @template T The shape of the loaded data.
 * @param data The loaded data payload.
 * @returns A success {@link ViewState}.
 *
 * @example
 * ```typescript
 * viewState.set(success(user));
 * ```
 */
export function success<T>(data: T): ViewState<T> {
  return { kind: 'success', data };
}

/**
 * Factory for error state.
 *
 * Wraps a normalized {@link AppError} in an {@link ErrorState}. Used to
 * transition to the error state after a failed async operation. The generic
 * type T is inferred from context to maintain ViewState type consistency.
 *
 * @template T The generic type of the ViewState (inferred from context).
 * @param error The normalized error details.
 * @returns An error {@link ViewState}.
 *
 * @example
 * ```typescript
 * // In an error handler
 * viewState.set(failure(error));
 * ```
 */
export function failure<T>(error: AppError): ViewState<T> {
  return { kind: 'error', error };
}
