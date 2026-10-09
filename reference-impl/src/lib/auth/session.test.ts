import { describe, it, expect, beforeEach, vi } from 'vitest';
import { createCacSession, validateAndRefreshSession, revokeSession, generateCsrfToken, verifyCsrfToken, serializeSessionCookie, serializeClearedCookie } from '../lib/auth/session';

describe('CAC Session Management', () => {
  const config = {
    idleTimeoutMinutes: 15,
    absoluteTimeoutHours: 12,
    csrfSecret: 'test-secret',
    sessionSecret: 'test-session-secret',
    cookieName: 'cac_session',
    cookieOptions: {
      secure: false,
      httpOnly: true,
      sameSite: 'strict' as const,
      path: '/',
      maxAge: 900,
    },
  };

  let sessionId: string;

  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date('2025-06-15T12:00:00Z'));
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it('creates session with correct defaults', async () => {
    const { session, cookie, csrfToken } = await createCacSession({
      userId: 'user-123',
      edipi: '1234567890',
      certSerial: 'ABC123',
      certThumbprint: 'thumbprint123',
      ipAddress: '10.0.0.1',
      userAgent: 'test-agent',
    }, config);

    expect(session.id).toBeDefined();
    expect(session.userId).toBe('user-123');
    expect(session.edipi).toBe('1234567890');
    expect(session.csrfToken).toBe(csrfToken);
    expect(session.createdAt).toEqual(new Date('2025-06-15T12:00:00Z'));
    expect(session.expiresAt).toEqual(new Date('2025-06-15T12:15:00Z'));
    expect(session.lastActivity).toEqual(new Date('2025-06-15T12:00:00Z'));
    expect(session.revokedAt).toBeUndefined();
    expect(cookie).toBeDefined();
  });

  it('validates and refreshes session on activity', async () => {
    const { session, cookie } = await createCacSession({
      userId: 'user-123',
      edipi: '1234567890',
      certSerial: 'ABC123',
      certThumbprint: 'thumbprint123',
    }, config);

    sessionId = session.id;

    // Advance 5 minutes
    vi.setSystemTime(new Date('2025-06-15T12:05:00Z'));

    const validated = await validateAndRefreshSession(cookie, config);
    expect(validated).not.toBeNull();
    expect(validated!.lastActivity).toEqual(new Date('2025-06-15T12:05:00Z'));
    expect(validated!.expiresAt).toEqual(new Date('2025-06-15T12:20:00Z'));
  });

  it('rejects expired session (idle timeout)', async () => {
    const { cookie } = await createCacSession({
      userId: 'user-123',
      edipi: '1234567890',
      certSerial: 'ABC123',
      certThumbprint: 'thumbprint123',
    }, config);

    // Advance 20 minutes (past 15 min idle timeout)
    vi.setSystemTime(new Date('2025-06-15T12:20:00Z'));

    const validated = await validateAndRefreshSession(cookie, config);
    expect(validated).toBeNull();
  });

  it('rejects session past absolute timeout', async () => {
    const { cookie } = await createCacSession({
      userId: 'user-123',
      edipi: '1234567890',
      certSerial: 'ABC123',
      certThumbprint: 'thumbprint123',
    }, config);

    // Advance 13 hours (past 12 hour absolute timeout)
    vi.setSystemTime(new Date('2025-06-16T01:00:00Z'));

    const validated = await validateAndRefreshSession(cookie, config);
    expect(validated).toBeNull();
  });

  it('rejects revoked session', async () => {
    const { session, cookie } = await createCacSession({
      userId: 'user-123',
      edipi: '1234567890',
      certSerial: 'ABC123',
      certThumbprint: 'thumbprint123',
    }, config);

    const sessions = new Map([[session.id, session]]);
    await revokeSession(session.id, sessions);

    const validated = await validateAndRefreshSession(cookie, config);
    expect(validated).toBeNull();
  });

  it('generates and verifies CSRF tokens', () => {
    const token1 = generateCsrfToken();
    const token2 = generateCsrfToken();

    expect(token1).not.toBe(token2);
    expect(token1.length).toBe(64); // 32 bytes hex
    expect(verifyCsrfToken(token1, token1)).toBe(true);
    expect(verifyCsrfToken(token1, token2)).toBe(false);
    expect(verifyCsrfToken('', token1)).toBe(false);
    expect(verifyCsrfToken(token1, '')).toBe(false);
  });

  it('serializes and clears cookies correctly', () => {
    const cookie = 'test-jwt-token';
    const serialized = serializeSessionCookie(cookie, config);
    expect(serialized).toContain('cac_session=test-jwt-token');
    expect(serialized).toContain('HttpOnly');
    expect(serialized).toContain('SameSite=Strict');
    expect(serialized).toContain('Path=/');
    expect(serialized).toContain('Max-Age=900');

    const cleared = serializeClearedCookie(config);
    expect(cleared).toContain('cac_session=');
    expect(cleared).toContain('Max-Age=0');
  });
});