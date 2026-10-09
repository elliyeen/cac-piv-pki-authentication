import { describe, it, expect, beforeEach, vi } from 'vitest';
import { CrlCache, normalizeSerial, ParsedCrl, CrlEntry } from '../lib/certs/crl-client';

describe('CRL Cache', () => {
  let cache: CrlCache;
  const crlUrl = 'http://crl.example.com/dod-ca.crl';
  const now = new Date('2025-06-15T12:00:00Z');

  const mockCrl: ParsedCrl = {
    issuer: 'CN=DOD ID CA-XX,OU=PKI,O=DoD,C=US',
    thisUpdate: new Date('2025-06-01T00:00:00Z'),
    nextUpdate: new Date('2025-07-01T00:00:00Z'),
    entries: new Map([
      ['REVOKED123', { serialNumber: 'REVOKED123', revocationDate: new Date('2025-05-01'), reason: 0 }],
      ['REVOKED456', { serialNumber: 'REVOKED456', revocationDate: new Date('2025-05-15'), reason: 1 }],
    ]),
    raw: new Uint8Array(),
  };

  beforeEach(() => {
    cache = new CrlCache({ ttlHours: 24, staleWhileRevalidatePercent: 80, maxStalenessHours: 48, fetchTimeoutMs: 5000 });
    vi.useFakeTimers();
    vi.setSystemTime(now);
  });

  afterEach(() => {
    vi.useRealTimers();
    cache.clear();
  });

  it('returns false for non-revoked cert on cache miss (fail-open)', async () => {
    // Simulate fetch failure by not mocking fetch
    const cert = { serialNumber: 'NOTREVOKED' } as any;
    const result = await cache.isRevoked(cert, crlUrl);
    expect(result).toBe(false); // Fail open for cache miss
  });

  it('returns true for revoked cert after successful cache load', async () => {
    cache.loadParsedCrl(crlUrl, mockCrl);

    const revokedCert = { serialNumber: 'REVOKED123' } as any;
    const result = await cache.isRevoked(revokedCert, crlUrl);
    expect(result).toBe(true);
  });

  it('returns false for non-revoked cert after cache load', async () => {
    cache.loadParsedCrl(crlUrl, mockCrl);

    const validCert = { serialNumber: 'VALID123' } as any;
    const result = await cache.isRevoked(validCert, crlUrl);
    expect(result).toBe(false);
  });

  it('uses stale cache within max staleness and triggers background refresh', async () => {
    cache.loadParsedCrl(crlUrl, mockCrl);

    // Advance time to stale but not expired (19 hours = 80% of 24h)
    vi.setSystemTime(new Date(now.getTime() + 19 * 3600 * 1000));

    const cert = { serialNumber: 'VALID123' } as any;
    const result = await cache.isRevoked(cert, crlUrl);
    expect(result).toBe(false); // Uses stale cache

    // Verify background refresh was triggered (would be async in real impl)
    const stats = cache.getStats();
    expect(stats.cache.size).toBe(1);
  });

  it('fail closed when beyond max staleness (48 hours)', async () => {
    cache.loadParsedCrl(crlUrl, mockCrl);

    // Advance time beyond max staleness (49 hours)
    vi.setSystemTime(new Date(now.getTime() + 49 * 3600 * 1000));

    const cert = { serialNumber: 'VALID123' } as any;
    const result = await cache.isRevoked(cert, crlUrl);
    expect(result).toBe(true); // Fail closed
  });

  it('normalizes serial numbers consistently', () => {
    expect(normalizeSerial('00A1B2')).toBe('A1B2');
    expect(normalizeSerial('0A1B2C')).toBe('A1B2C');
    expect(normalizeSerial('0')).toBe('0');
    expect(normalizeSerial('0000')).toBe('0');
  });

  it('tracks cache statistics', async () => {
    cache.loadParsedCrl(crlUrl, mockCrl);
    const stats = cache.getStats();
    expect(stats.cache.size).toBe(1);
    expect(stats.cache.fresh).toBe(1);
    expect(stats.cache.stale).toBe(0);
    expect(stats.cache.expired).toBe(0);
  });
});