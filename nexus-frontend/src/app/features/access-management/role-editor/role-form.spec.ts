import { describe, expect, it } from 'vitest';
import { CONSOLE_COPY } from '../copy/console-copy';
import {
  ROLE_DESCRIPTION_MAX,
  ROLE_NAME_MAX,
  cloneName,
  createRoleForm,
  descriptionError,
  nameError,
} from './role-form';

const { errors } = CONSOLE_COPY.createRole;

function nameErrorFor(value: string): string | null {
  const form = createRoleForm();
  form.controls.name.setValue(value);
  return nameError(form.controls.name);
}

function descriptionErrorFor(value: string): string | null {
  const form = createRoleForm();
  form.controls.description.setValue(value);
  return descriptionError(form.controls.description);
}

describe('role-form (mirrors CreateRoleRequest; design §6.6, §14.1)', () => {
  it('starts with an empty name and description, and only the name required', () => {
    const form = createRoleForm();
    expect(form.getRawValue()).toEqual({ name: '', description: '' });
    expect(form.controls.name.errors).toEqual({ required: true });
    expect(form.controls.description.valid).toBe(true);
    form.reset();
    // Non-nullable: a reset never sends null to the server.
    expect(form.getRawValue()).toEqual({ name: '', description: '' });
  });

  describe('name', () => {
    it('is required', () => {
      expect(nameErrorFor('')).toBe(errors.nameRequired);
    });

    it(`accepts ${ROLE_NAME_MAX} characters and refuses ${ROLE_NAME_MAX + 1}`, () => {
      expect(ROLE_NAME_MAX).toBe(64);
      expect(nameErrorFor('a'.repeat(64))).toBeNull();
      expect(nameErrorFor('a'.repeat(65))).toBe(errors.nameTooLong);
    });

    it.each(['Support', 'a', '9 lives', 'Ops.team_2-b', 'Trailing space '])(
      'accepts the server pattern: %j',
      (value) => {
        expect(nameErrorFor(value)).toBeNull();
      },
    );

    it.each([
      ' Leading',
      '.dot',
      '_under',
      '-dash',
      'tab\there',
      'new\nline',
      'Café',
      'a/b',
      'a<b',
    ])('refuses what the server pattern refuses: %j', (value) => {
      expect(nameErrorFor(value)).toBe(errors.namePattern);
    });

    it('refuses a blank name as the server does (@NotBlank, then the pattern)', () => {
      expect(nameErrorFor('   ')).toBe(errors.namePattern);
    });

    it.each(['TENANT_ADMIN', 'tenant_admin', 'Tenant_Admin', 'MEMBER', 'member', 'mEmBeR'])(
      'refuses the reserved name %j in any case',
      (value) => {
        expect(nameErrorFor(value)).toBe(errors.nameReserved);
      },
    );

    it('does not treat a name that only contains a reserved word as reserved', () => {
      expect(nameErrorFor('MEMBERS')).toBeNull();
      expect(nameErrorFor('Copy of TENANT_ADMIN')).toBeNull();
      // The server compares the untrimmed name, so a trailing space is not the reserved name.
      expect(nameErrorFor('MEMBER ')).toBeNull();
    });

    it('reports the first failing rule only: length before pattern', () => {
      expect(nameErrorFor(`.${'a'.repeat(64)}`)).toBe(errors.nameTooLong);
    });
  });

  describe('description', () => {
    it('is optional', () => {
      expect(descriptionErrorFor('')).toBeNull();
    });

    it(`accepts ${ROLE_DESCRIPTION_MAX} characters and refuses ${ROLE_DESCRIPTION_MAX + 1}`, () => {
      expect(ROLE_DESCRIPTION_MAX).toBe(255);
      expect(descriptionErrorFor('d'.repeat(255))).toBeNull();
      expect(descriptionErrorFor('d'.repeat(256))).toBe(errors.descriptionTooLong);
    });

    it.each([
      ['U+2028', 'line\u2028separator'],
      ['U+2029', 'paragraph\u2029separator'],
      ['a newline', 'two\nlines'],
      ['a tab', 'tab\there'],
      ['NUL', 'nul\u0000'],
      ['U+001F', 'unit\u001fseparator'],
      ['DEL', 'del\u007f'],
    ])('refuses %s', (_name, value) => {
      expect(descriptionErrorFor(value)).toBe(errors.descriptionControl);
    });

    it.each([
      ['markup, stored as text (N6)', '<img src=x onerror=alert(1)>'],
      ['non-ASCII letters', 'Équipe support'],
      // Java's \p{Cntrl} is ASCII only: the server accepts C1 controls, so the client does too.
      ['a C1 control', 'next\u0085line'],
    ])('accepts %s, as the server does', (_name, value) => {
      expect(descriptionErrorFor(value)).toBeNull();
    });
  });

  describe('cloneName', () => {
    it('prefixes "Copy of"', () => {
      expect(cloneName('Support')).toBe('Copy of Support');
    });

    it('cuts the result to 64 characters', () => {
      const name = cloneName('n'.repeat(64));
      expect(name).toHaveLength(64);
      expect(name.startsWith('Copy of n')).toBe(true);
      expect(nameErrorFor(name)).toBeNull();
    });
  });
});
