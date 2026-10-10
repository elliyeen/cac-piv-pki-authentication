import { X509Certificate, X509Crl } from '@peculiar/x509';
import { createHash, createPublicKey, verify as cryptoVerify } from 'crypto';

/**
 * CRL (Certificate Revocation List) client with caching.
 * RFC 5280 CRL parsing via @peculiar/x509, 24h TTL, stale-while-revalidate, bounded staleness.
 *
 * Failure policy (see ADR-0002): fail closed by default. A CRL that cannot be obtained
 * and is not covered by a cache entry within the staleness bound is treated as "cannot
 * confirm not revoked" and surfaces as an error or `true`, never silently as `false`.
 */

export interface CrlEntry {
  serialNumber: string; // Hex string
  revocationDate: Date;
  reason?: number;
}

export interface ParsedCrl {
  issuer: string;
  thisUpdate: Date;
  nextUpdate: Date;
  entries: Map<string, CrlEntry>; // Key: serialNumber (uppercase hex, no leading zeros)
  raw: Uint8Array;
}

export interface CrlCacheEntry {
  crl: ParsedCrl;
  fetchedAt: Date;
  expiresAt: Date;
  staleAt: Date; // When to trigger background refresh (staleWhileRevalidatePercent of TTL)
}

export interface CrlCacheConfig {
  ttlHours: number;
  staleWhileRevalidatePercent: number;
  maxStalenessHours: number;
  fetchTimeoutMs: number;
  /** What to do when no CRL can be obtained and nothing usable is cached. */
  onUnavailable: 'fail-closed' | 'fail-open';
  /** Injectable for tests and for environments with an egress proxy. */
  fetchImpl: typeof fetch;
}

const DEFAULT_CONFIG: CrlCacheConfig = {
  ttlHours: 24,
  staleWhileRevalidatePercent: 80,
  maxStalenessHours: 48,
  fetchTimeoutMs: 5000,
  onUnavailable: 'fail-closed',
  fetchImpl: (...args) => fetch(...args),
};

export class CrlUnavailableError extends Error {
  constructor(url: string, cause?: unknown) {
    super(`CRL unavailable: ${url}${cause instanceof Error ? ` (${cause.message})` : ''}`);
    this.name = 'CrlUnavailableError';
  }
}

/**
 * In-memory CRL cache. Production should use a shared cache so all instances agree.
 */
export class CrlCache {
  private cache = new Map<string, CrlCacheEntry>(); // Key: CRL URL
  private inflight = new Map<string, Promise<void>>();
  private config: CrlCacheConfig;

  constructor(config: Partial<CrlCacheConfig> = {}) {
    this.config = { ...DEFAULT_CONFIG, ...config };
  }

  /**
   * True if the certificate is revoked, or if revocation status cannot be confirmed
   * within the staleness bound (fail closed). Throws CrlUnavailableError on a cache
   * miss when the CRL cannot be fetched, unless `onUnavailable` is 'fail-open'.
   */
  async isRevoked(cert: X509Certificate, crlUrl: string, issuer?: X509Certificate): Promise<boolean> {
    let entry = this.cache.get(crlUrl);

    if (!entry) {
      try {
        await this.fetchAndCache(crlUrl, issuer);
      } catch (e) {
        if (this.config.onUnavailable === 'fail-open') return false;
        throw new CrlUnavailableError(crlUrl, e);
      }
      return this.checkRevoked(cert, crlUrl);
    }

    const now = new Date();

    // Fresh: use as is
    if (now < entry.staleAt) return this.checkRevoked(cert, crlUrl);

    // Aging but unexpired: serve from cache, refresh in the background
    if (now < entry.expiresAt) {
      this.fetchAndCache(crlUrl, issuer).catch(() => undefined);
      return this.checkRevoked(cert, crlUrl);
    }

    // Expired: try a synchronous refresh. If it fails, serve stale only within the bound.
    try {
      await this.fetchAndCache(crlUrl, issuer);
      return this.checkRevoked(cert, crlUrl);
    } catch {
      entry = this.cache.get(crlUrl)!;
      const limit = entry.fetchedAt.getTime() + this.config.maxStalenessHours * 3600 * 1000;
      if (now.getTime() < limit) return this.checkRevoked(cert, crlUrl);
      return true; // Beyond max staleness: fail closed
    }
  }

  private checkRevoked(cert: X509Certificate, crlUrl: string): boolean {
    const entry = this.cache.get(crlUrl);
    if (!entry) return true; // Should be unreachable; fail closed
    const raw = cert.serialNumber.toUpperCase();
    return entry.crl.entries.has(raw) || entry.crl.entries.has(normalizeSerial(raw));
  }

  /** Fetch, parse and cache a CRL. Concurrent callers share one request. */
  fetchAndCache(crlUrl: string, issuer?: X509Certificate): Promise<void> {
    const existing = this.inflight.get(crlUrl);
    if (existing) return existing;

    const p = (async () => {
      const raw = await this.fetchWithTimeout(crlUrl);
      const parsed = await parseCrl(raw, issuer);
      this.store(crlUrl, parsed);
    })().finally(() => this.inflight.delete(crlUrl));

    this.inflight.set(crlUrl, p);
    return p;
  }

  private store(crlUrl: string, crl: ParsedCrl): void {
    const now = new Date();
    const ttlMs = this.config.ttlHours * 3600 * 1000;
    const staleMs = ttlMs * (this.config.staleWhileRevalidatePercent / 100);
    this.cache.set(crlUrl, {
      crl,
      fetchedAt: now,
      expiresAt: new Date(now.getTime() + ttlMs),
      staleAt: new Date(now.getTime() + staleMs),
    });
  }

  private async fetchWithTimeout(url: string): Promise<Uint8Array> {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), this.config.fetchTimeoutMs);
    try {
      const response = await this.config.fetchImpl(url, { signal: controller.signal });
      if (!response.ok) throw new Error(`HTTP ${response.status}: ${response.statusText}`);
      return new Uint8Array(await response.arrayBuffer());
    } finally {
      clearTimeout(timeout);
    }
  }

  /** Load a pre-parsed CRL (tests and offline fixtures). */
  loadParsedCrl(crlUrl: string, crl: ParsedCrl): void {
    this.store(crlUrl, crl);
  }

  getStats(): Record<string, { size: number; fresh: number; stale: number; expired: number }> {
    const now = new Date();
    let fresh = 0, stale = 0, expired = 0;
    for (const entry of this.cache.values()) {
      if (now < entry.staleAt) fresh++;
      else if (now < entry.expiresAt) stale++;
      else expired++;
    }
    return { cache: { size: this.cache.size, fresh, stale, expired } };
  }

  clear(): void {
    this.cache.clear();
    this.inflight.clear();
  }
}

/**
 * Parse a DER or PEM CRL. When `issuer` is given the CRL signature is verified
 * against it and an unverifiable CRL is rejected.
 */
export async function parseCrl(raw: Uint8Array, issuer?: X509Certificate): Promise<ParsedCrl> {
  const crl = new X509Crl(raw);
  if (issuer && !verifyCrlSignature(raw, crl, issuer)) {
    throw new Error('CRL signature verification failed');
  }
  const entries = new Map<string, CrlEntry>();
  for (const e of crl.entries) {
    const serial = normalizeSerial(e.serialNumber);
    entries.set(serial, { serialNumber: serial, revocationDate: e.revocationDate });
  }
  return {
    issuer: crl.issuer,
    thisUpdate: crl.thisUpdate,
    nextUpdate: crl.nextUpdate ?? new Date(crl.thisUpdate.getTime() + 24 * 3600 * 1000),
    entries,
    raw,
  };
}

/** Read one DER TLV header at `off`. */
function readTlv(buf: Uint8Array, off: number): { hdr: number; len: number } {
  let len = buf[off + 1];
  let hdr = 2;
  if (len & 0x80) {
    const n = len & 0x7f;
    if (n < 1 || n > 4) throw new Error('Unsupported DER length');
    len = 0;
    for (let i = 0; i < n; i++) len = len * 256 + buf[off + 2 + i];
    hdr = 2 + n;
  }
  if (off + hdr + len > buf.length) throw new Error('Truncated DER');
  return { hdr, len };
}

/**
 * Verify a CRL signature over the original signed bytes. (The library's own verify
 * re-serializes the TBS and does not match the signed encoding.) Supports RSA PKCS#1 v1.5
 * and ECDSA; any other algorithm, or any parsing problem, returns false.
 */
function verifyCrlSignature(raw: Uint8Array, crl: X509Crl, issuer: X509Certificate): boolean {
  try {
    const outer = readTlv(raw, 0);
    const tbsStart = outer.hdr;
    const tbs = readTlv(raw, tbsStart);
    const tbsEnd = tbsStart + tbs.hdr + tbs.len;
    const algo = readTlv(raw, tbsEnd);
    const sigStart = tbsEnd + algo.hdr + algo.len;
    const sig = readTlv(raw, sigStart);
    const sigBytes = raw.subarray(sigStart + sig.hdr + 1, sigStart + sig.hdr + sig.len); // skip unused-bits byte
    const name = (crl.signatureAlgorithm as { name: string; hash?: { name: string } });
    if (name.name !== 'ECDSA' && name.name !== 'RSASSA-PKCS1-v1_5') return false;
    const hash = name.hash?.name.replace('-', '').toLowerCase();
    if (!hash) return false;
    const key = createPublicKey({ key: Buffer.from(issuer.publicKey.rawData), format: 'der', type: 'spki' });
    return cryptoVerify(hash, raw.subarray(tbsStart, tbsEnd), key, sigBytes);
  } catch {
    return false;
  }
}

/** Remove leading zeros and uppercase so certificate and CRL serials compare equal. */
export function normalizeSerial(serial: string): string {
  return serial.replace(/^0+/, '').toUpperCase() || '0';
}

/** Generate CRL cache key from URL. */
export function getCrlCacheKey(url: string): string {
  return createHash('sha256').update(url).digest('hex').substring(0, 32);
}
