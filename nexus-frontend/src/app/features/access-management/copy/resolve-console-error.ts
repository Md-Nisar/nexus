import { isRbacDenialReason } from '../../../shared/types/api/rbac';
import type { AppError } from '../../../shared/types/app-error';
import { retryAfterSeconds as secondsToWait } from '../util/retry-after';
import {
  ActionUnavailableCopy,
  ConsoleErrorArea,
  ConsoleErrorCode,
  ErrorCopy,
  ErrorPresentation,
  ListPageErrorCopy,
  NotEnabledCopy,
  Rbac001ReasonCopy,
  RbacErrorMessages,
  format,
} from './console-copy';

/** What the user was doing when the error came back; chooses between page and action copy. */
export type ConsoleAction = 'load' | 'save' | 'create' | 'assign' | 'revoke' | 'delete' | 'lookup';

export interface ConsoleErrorContext {
  readonly area: ConsoleErrorArea;
  readonly action: ConsoleAction;
  /** Fills `{n}` of copy that counts things (`RBAC_009`: members). */
  readonly count?: number;
}

/** A field the server rejected, with the server's own message (design §9.2). */
export interface ConsoleFieldError {
  readonly field: string;
  readonly message: string;
}

/**
 * An error as the console shows it: copy-module text only. There is no field for `AppError.message`
 * or `requiredPermission`, so neither can reach a template through this view.
 */
export interface ConsoleErrorView {
  readonly title: string;
  readonly body: string;
  /** `traceId ?? correlationId`, present only for copy that shows a reference. */
  readonly reference?: string;
  /** Seconds to wait before trying again; present only for copy that waits (429, 503). */
  readonly retryAfterSeconds?: number;
  readonly presentation: ErrorPresentation;
  /** The server already agrees with what the user wanted: treat as done. */
  readonly convergent: boolean;
  /** The copy waits out `retryAfterSeconds`. */
  readonly showsWait: boolean;
  /** A retry can help; false for "not found" and "not enabled". */
  readonly retryable: boolean;
  /** The area's feature is switched off (`RESOURCE_NOT_FOUND`). */
  readonly notEnabled: boolean;
  /** Per-field messages of a form `VALIDATION_FAILED`; absent otherwise. */
  readonly fieldErrors?: readonly ConsoleFieldError[];
}

const CODES: ReadonlySet<string> = new Set(Object.keys(RbacErrorMessages));

function isConsoleErrorCode(code: string): code is ConsoleErrorCode {
  return CODES.has(code);
}

function copyFor(
  error: AppError,
  code: ConsoleErrorCode | null,
  ctx: ConsoleErrorContext,
): ErrorCopy {
  if (code === null) return RbacErrorMessages.UNEXPECTED_ERROR;
  switch (code) {
    case 'RBAC_001':
      return isRbacDenialReason(error.reason)
        ? Rbac001ReasonCopy[error.reason]
        : Rbac001ReasonCopy.UNSPECIFIED;
    case 'RESOURCE_NOT_FOUND':
      return NotEnabledCopy[ctx.area];
    case 'AUTH_005':
      return ctx.action === 'load' ? RbacErrorMessages.AUTH_005 : ActionUnavailableCopy;
    case 'VALIDATION_FAILED':
      if (ctx.action !== 'load') return RbacErrorMessages.VALIDATION_FAILED;
      return ctx.area === 'users' ? ListPageErrorCopy.users : ListPageErrorCopy.default;
    default:
      return RbacErrorMessages[code];
  }
}

/**
 * Turns an `AppError` into what the console shows (US-020 design §9.1, §9.2).
 *
 * - **Copy only.** Title and body come from the copy module. `AppError.message` (the server's
 *   `detail`) and `requiredPermission` are never read. The one server text that is shown is a form
 *   field's `details[].message`, in `fieldErrors`, which the page renders by interpolation.
 * - **Unknown codes** (including inherited property names such as `constructor`) get the generic
 *   "Something went wrong" copy with a reference.
 * - **`RBAC_001`** is chosen by `reason`; a missing or unknown reason is `UNSPECIFIED`.
 * - **`RESOURCE_NOT_FOUND`** is the area's "not enabled" copy.
 * - **Waits** (429 `RBAC_011`, `USER_DIR_001/002`, 503 `AUTH_005`) use `Retry-After`, else 30 s.
 */
export function resolveConsoleError(error: AppError, ctx: ConsoleErrorContext): ConsoleErrorView {
  const code = isConsoleErrorCode(error.code) ? error.code : null;
  const copy = copyFor(error, code, ctx);
  const showsWait = copy.showsWait === true;
  const retryAfterSeconds = showsWait ? secondsToWait(error) : undefined;
  const reference = copy.showsReference ? (error.traceId ?? error.correlationId) : undefined;
  const isForm = code === 'VALIDATION_FAILED' && ctx.action !== 'load';

  const values: Record<string, string | number> = {};
  if (retryAfterSeconds !== undefined) values['n'] = retryAfterSeconds;
  else if (ctx.count !== undefined) values['n'] = ctx.count;

  return {
    title: format(copy.title, values),
    body: format(copy.body, values),
    ...(reference === undefined ? {} : { reference }),
    ...(retryAfterSeconds === undefined ? {} : { retryAfterSeconds }),
    presentation: copy.presentation,
    convergent: copy.convergent === true,
    showsWait,
    retryable: copy.retryable !== false,
    notEnabled: code === 'RESOURCE_NOT_FOUND',
    ...(isForm
      ? {
          fieldErrors: (error.details ?? []).map((detail) => ({
            field: detail.field,
            message: detail.message,
          })),
        }
      : {}),
  };
}
