import { createHash, randomBytes } from 'crypto';
import { SignJWT, jwtVerify } from 'jose';

/**
 * CAC Session Management — 15-minute sliding window with server-side enforcement.
 * Separate from Better Auth sessions for clear security boundary.
 */

export interface CacSessionData {
  id: string;
  userId: string;
  edipi: string;
  certSerial: string;
  certThumbprint: string;
  csrfToken: string;
  createdAt: Date;
  expiresAt: Date;
  lastActivity: Date;
  revokedAt?: Date;
  ipAddress?: string;
  userAgent?: string;
}

export interface SessionConfig {
  idleTimeoutMinutes: number;
  absoluteTimeoutHours: number;
  csrfSecret: string;
  sessionSecret: string;
  cookieName: string;
  cookieOptions: {
    secure: boolean;
    httpOnly: boolean;
    sameSite: 'strict' | 'lax' | 'none';
    path: string;
    maxAge: number; // seconds
  };
}

const DEFAULT_CONFIG: SessionConfig = {
  idleTimeoutMinutes: 15,
  absoluteTimeoutHours: 12,
  csrfSecret: process.env.CAC_CSRF_SECRET || 'dev-secret-change-in-production',
  sessionSecret: process.env.CAC_SESSION_SECRET || 'dev-secret-change-in-production',
  cookieName: 'cac_session',
  cookieOptions: {
    secure: process.env.NODE_ENV === 'production',
    httpOnly: true,
    sameSite: 'strict',
    path: '/',
    maxAge: 15 * 60, // 15 minutes
  },
};

/**
 * Create a new CAC session.
 */
export async function createCacSession(
  data: Omit<CacSessionData, 'id' | 'csrfToken' | 'createdAt' | 'expiresAt' | 'lastActivity'>,
  config: Partial<SessionConfig> = {}
): Promise<{ session: CacSessionData; cookie: string; csrfToken: string }> {
  const cfg = { ...DEFAULT_CONFIG, ...config };
  const now = new Date();

  const session: CacSessionData = {
    ...data,
    id: generateSessionId(),
    csrfToken: generateCsrfToken(),
    createdAt: now,
    expiresAt: new Date(now.getTime() + cfg.idleTimeoutMinutes * 60 * 1000),
    lastActivity: now,
  };

  const cookie = await createSessionCookie(session, cfg);

  return { session, cookie, csrfToken: session.csrfToken };
}

/**
 * Validate and refresh session on authenticated request.
 * Returns updated session or null if invalid/expired/revoked.
 */
export async function validateAndRefreshSession(
  cookieValue: string,
  config: Partial<SessionConfig> = {}
): Promise<CacSessionData | null> {
  const cfg = { ...DEFAULT_CONFIG, ...config };

  try {
    const session = await verifySessionCookie(cookieValue, cfg);
    if (!session) return null;

    const now = new Date();

    // Check revoked
    if (session.revokedAt) return null;

    // Check absolute timeout
    const absoluteExpiry = new Date(session.createdAt.getTime() + cfg.absoluteTimeoutHours * 3600 * 1000);
    if (now > absoluteExpiry) return null;

    // Check idle timeout
    if (now > session.expiresAt) return null;

    // Refresh sliding window
    session.lastActivity = now;
    session.expiresAt = new Date(now.getTime() + cfg.idleTimeoutMinutes * 60 * 1000);

    return session;
  } catch {
    return null;
  }
}

/**
 * Revoke a session (logout, cert revocation, admin action).
 */
export async function revokeSession(
  sessionId: string,
  sessions: Map<string, CacSessionData>
): Promise<boolean> {
  const session = sessions.get(sessionId);
  if (!session) return false;

  session.revokedAt = new Date();
  return true;
}

/**
 * Generate CSRF token for double-submit cookie pattern.
 */
export function generateCsrfToken(): string {
  return randomBytes(32).toString('hex');
}

/**
 * Verify CSRF token from request header/body against session.
 */
export function verifyCsrfToken(sessionCsrfToken: string, requestCsrfToken: string): boolean {
  if (!sessionCsrfToken || !requestCsrfToken) return false;
  return timingSafeEqual(sessionCsrfToken, requestCsrfToken);
}

/**
 * Timing-safe string comparison.
 */
function timingSafeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let result = 0;
  for (let i = 0; i < a.length; i++) {
    result |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return result === 0;
}

/**
 * Generate unique session ID.
 */
function generateSessionId(): string {
  return randomBytes(16).toString('hex');
}

/**
 * Create signed session cookie (JWT).
 */
async function createSessionCookie(session: CacSessionData, config: SessionConfig): Promise<string> {
  const secret = new TextEncoder().encode(config.sessionSecret);

  return new SignJWT({
    sid: session.id,
    uid: session.userId,
    edipi: session.edipi,
    certSerial: session.certSerial,
    certThumbprint: session.certThumbprint,
    csrf: session.csrfToken,
    iat: Math.floor(session.createdAt.getTime() / 1000),
    exp: Math.floor(session.expiresAt.getTime() / 1000),
  })
    .setProtectedHeader({ alg: 'HS256' })
    .setIssuedAt()
    .setExpirationTime(`${config.idleTimeoutMinutes}m`)
    .sign(secret);
}

/**
 * Verify and decode session cookie.
 */
async function verifySessionCookie(cookie: string, config: SessionConfig): Promise<CacSessionData | null> {
  const secret = new TextEncoder().encode(config.sessionSecret);

  try {
    const { payload } = await jwtVerify(cookie, secret, {
      algorithms: ['HS256'],
    });

    return {
      id: payload.sid as string,
      userId: payload.uid as string,
      edipi: payload.edipi as string,
      certSerial: payload.certSerial as string,
      certThumbprint: payload.certThumbprint as string,
      csrfToken: payload.csrf as string,
      createdAt: new Date((payload.iat as number) * 1000),
      expiresAt: new Date((payload.exp as number) * 1000),
      lastActivity: new Date(), // Updated on each validation
    };
  } catch {
    return null;
  }
}

/**
 * Cookie serialization helpers for HTTP responses.
 */
export function serializeSessionCookie(cookie: string, config: Partial<SessionConfig> = {}): string {
  const cfg = { ...DEFAULT_CONFIG, ...config };
  const options = cfg.cookieOptions;

  const parts = [
    `${cfg.cookieName}=${cookie}`,
    `Path=${options.path}`,
    `Max-Age=${options.maxAge}`,
    options.httpOnly ? 'HttpOnly' : '',
    options.secure ? 'Secure' : '',
    `SameSite=${options.sameSite.charAt(0).toUpperCase() + options.sameSite.slice(1)}`,
  ].filter(Boolean);

  return parts.join('; ');
}

export function serializeClearedCookie(config: Partial<SessionConfig> = {}): string {
  const cfg = { ...DEFAULT_CONFIG, ...config };
  const options = cfg.cookieOptions;

  return [
    `${cfg.cookieName}=`,
    `Path=${options.path}`,
    'Max-Age=0',
    options.httpOnly ? 'HttpOnly' : '',
    options.secure ? 'Secure' : '',
    `SameSite=${options.sameSite.charAt(0).toUpperCase() + options.sameSite.slice(1)}`,
  ].filter(Boolean).join('; ');
}