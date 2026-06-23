export interface AuthUser {
  readonly userId: string;
  readonly tenantId: string;
  readonly emailVerified: boolean;
  readonly roles: readonly string[];
  readonly tokenVersion: number;
}

export interface AuthSession {
  readonly accessToken: string;
  readonly tokenType: string;
  readonly expiresIn: number;
  readonly expiresAt: number; // epoch ms — set to Date.now() + expiresIn * 1000 on login/refresh
  readonly user: AuthUser;
}
