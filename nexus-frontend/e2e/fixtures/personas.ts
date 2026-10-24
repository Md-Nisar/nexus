/**
 * Dev-profile personas seeded by the backend (`DevUserSeeder`). Dev only; never reuse these
 * addresses or the shared password anywhere else.
 */
export type PersonaKey =
  | 'admin'
  | 'admin2'
  | 'member'
  | 'roleManager'
  | 'userManager'
  | 'locked'
  | 'pending'
  | 'otherTenantAdmin'
  | 'roleReaderUserManager'
  | 'auditor'
  | 'targetA'
  | 'targetB';

export interface Persona {
  readonly email: string;
  /**
   * False when the account cannot obtain a session (locked, pending, second tenant) or must never
   * be signed in as (the ACTIVE assignment targets, which only receive and lose roles).
   */
  readonly canSignIn: boolean;
}

export const PERSONA_PASSWORD = 'TestPass99!';

export const PERSONAS: Readonly<Record<PersonaKey, Persona>> = {
  admin: { email: 'test@example.com', canSignIn: true },
  admin2: { email: 'admin2@example.com', canSignIn: true },
  member: { email: 'member@example.com', canSignIn: true },
  roleManager: { email: 'role-manager@example.com', canSignIn: true },
  userManager: { email: 'user-manager@example.com', canSignIn: true },
  locked: { email: 'locked@example.com', canSignIn: false },
  pending: { email: 'pending@example.com', canSignIn: false },
  otherTenantAdmin: { email: 'other-tenant-admin@example.com', canSignIn: false },
  roleReaderUserManager: { email: 'role-reader-user-manager@example.com', canSignIn: true },
  auditor: { email: 'auditor@example.com', canSignIn: true },
  targetA: { email: 'target-a@example.com', canSignIn: false },
  targetB: { email: 'target-b@example.com', canSignIn: false },
};

/** Personas that can sign in, in a stable order. */
export const SIGN_IN_PERSONAS: readonly PersonaKey[] = [
  'admin',
  'admin2',
  'member',
  'roleManager',
  'userManager',
  'roleReaderUserManager',
  'auditor',
];

/** Fixture-only second tenant (cross-tenant negative tests; nobody can sign in to it). */
export const SECOND_TENANT_ID = '00000000-0000-7000-8000-000000000002';
export const SECOND_TENANT_ADMIN_ID = '00000000-0000-7000-8000-0000000000a2';
