export type AuthErrorCode =
  | "INVALID_CREDENTIALS"
  | "ACCOUNT_DISABLED"
  | "INVITE_PENDING"
  | "ORG_REQUIRED"
  | "RATE_LIMITED"
  | "WEAK_PASSWORD"
  | "INVALID_TOKEN"
  | "UNAUTHENTICATED"
  | "FORBIDDEN";

const STATUS: Record<AuthErrorCode, number> = {
  INVALID_CREDENTIALS: 401,
  ACCOUNT_DISABLED: 403,
  INVITE_PENDING: 403,
  ORG_REQUIRED: 400,
  RATE_LIMITED: 429,
  WEAK_PASSWORD: 400,
  INVALID_TOKEN: 400,
  UNAUTHENTICATED: 401,
  FORBIDDEN: 403,
};

/** Every auth failure. `code` is stable for clients; `statusCode` suits HTTP and GraphQL extensions. */
export class AuthError extends Error {
  readonly statusCode: number;
  constructor(
    readonly code: AuthErrorCode,
    message: string,
    readonly details: { retryAfterMs?: number; permission?: string } = {},
  ) {
    super(message);
    this.name = "AuthError";
    this.statusCode = STATUS[code];
  }
}
