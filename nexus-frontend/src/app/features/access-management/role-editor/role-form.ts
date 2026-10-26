import {
  AbstractControl,
  FormControl,
  FormGroup,
  ValidationErrors,
  ValidatorFn,
  Validators,
} from '@angular/forms';
import { CONSOLE_COPY, format } from '../copy/console-copy';

/** `CreateRoleRequest.name` `@Size(max = 64)`. */
export const ROLE_NAME_MAX = 64;
/** `CreateRoleRequest.description` `@Size(max = 255)`. */
export const ROLE_DESCRIPTION_MAX = 255;

/** `CreateRoleRequest.name` `@Pattern`, matched against the whole value as the server does. */
const NAME_PATTERN = /^[A-Za-z0-9][A-Za-z0-9 ._-]*$/;

/**
 * `CreateRoleRequest.description` `@Pattern(^[^\p{Cntrl}\u2028\u2029]*$)`. Java's `\p{Cntrl}` is
 * ASCII only (U+0000 to U+001F and U+007F), so C1 controls are accepted, as on the server.
 */
// eslint-disable-next-line no-control-regex -- the server's rule is about control characters
const DESCRIPTION_FORBIDDEN = /[\u0000-\u001f\u007f\u2028\u2029]/;

/** `RbacRoleNames.RESERVED`, compared case-insensitively and untrimmed (Q28 duplicates it). */
const RESERVED_NAMES: readonly string[] = ['TENANT_ADMIN', 'MEMBER'];

export type RoleForm = FormGroup<{
  name: FormControl<string>;
  description: FormControl<string>;
}>;

const reservedName: ValidatorFn = (control: AbstractControl<string>): ValidationErrors | null =>
  RESERVED_NAMES.includes(control.value.toUpperCase()) ? { reserved: true } : null;

const noControlCharacters: ValidatorFn = (
  control: AbstractControl<string>,
): ValidationErrors | null =>
  DESCRIPTION_FORBIDDEN.test(control.value) ? { controlCharacters: true } : null;

/**
 * The Create and Clone form (US-020 design §6.6). Its validators mirror `CreateRoleRequest`
 * (B-15) and the reserved-name rule exactly, so a value the form accepts is one the server's
 * validation accepts. The server stays final: it also refuses a name already in use (`RBAC_006`)
 * and reserved names (`RBAC_007`). Nothing is trimmed, as on the server.
 */
export function createRoleForm(): RoleForm {
  return new FormGroup({
    name: new FormControl('', {
      nonNullable: true,
      validators: [
        Validators.required,
        Validators.maxLength(ROLE_NAME_MAX),
        Validators.pattern(NAME_PATTERN),
        reservedName,
      ],
    }),
    description: new FormControl('', {
      nonNullable: true,
      validators: [Validators.maxLength(ROLE_DESCRIPTION_MAX), noControlCharacters],
    }),
  });
}

/** The copy of the first rule the name breaks, or `null` (design §14.1). */
export function nameError(control: AbstractControl): string | null {
  const { errors } = CONSOLE_COPY.createRole;
  if (control.hasError('required')) return errors.nameRequired;
  if (control.hasError('maxlength')) return errors.nameTooLong;
  if (control.hasError('pattern')) return errors.namePattern;
  if (control.hasError('reserved')) return errors.nameReserved;
  return null;
}

/** The copy of the first rule the description breaks, or `null` (design §14.1). */
export function descriptionError(control: AbstractControl): string | null {
  const { errors } = CONSOLE_COPY.createRole;
  if (control.hasError('maxlength')) return errors.descriptionTooLong;
  if (control.hasError('controlCharacters')) return errors.descriptionControl;
  return null;
}

/** "Copy of {name}", cut to the name limit (design §12.5). */
export function cloneName(sourceName: string): string {
  return format(CONSOLE_COPY.createRole.cloneName, { name: sourceName }).slice(0, ROLE_NAME_MAX);
}
