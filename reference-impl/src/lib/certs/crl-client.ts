import { X509Certificate } from '@peculiar/x509';
import { createHash } from 'crypto';

/**
 * CRL (Certificate Revocation List) client with caching.
 * Implements RFC 5280 CRL processing with 24h TTL + stale-while-revalidate.
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
  entries: Map<string, CrlEntry>; // Key: serialNumber (uppercase hex)
  raw: Uint8Array;
}

export interface CrlCacheEntry {
  crl: ParsedCrl;
  fetchedAt: Date;
  expiresAt: Date;
  staleAt: Date; // When to trigger background refresh (80% TTL)
}

export interface CrlCacheConfig {
  ttlHours: number;
  staleWhileRevalidatePercent: number;
  maxStalenessHours: number;
  fetchTimeoutMs: number;
}

const DEFAULT_CONFIG: CrlCacheConfig = {
  ttlHours: 24,
  staleWhileRevalidatePercent: 80,
  maxStalenessHours: 48,
  fetchTimeoutMs: 5000,
};

/**
 * In-memory CRL cache with TTL and stale-while-revalidate.
 * Production should use Redis or similar distributed cache.
 */
export class CrlCache {
  private cache = new Map<string, CrlCacheEntry>(); // Key: CRL URL
  private refreshing = new Set<string>();
  private config: CrlCacheConfig;

  constructor(config: Partial<CrlCacheConfig> = {}) {
    this.config = { ...DEFAULT_CONFIG, ...config };
  }

  /**
   * Check if a certificate is revoked according to cached CRL.
   * Returns false if CRL not available (fail-open for cache miss, fail-closed for stale).
   */
  async isRevoked(cert: X509Certificate, crlUrl: string): Promise<boolean> {
    const entry = this.cache.get(crlUrl);

    if (!entry) {
      // Cache miss — fetch synchronously
      await this.fetchAndCache(crlUrl);
      return this.checkRevoked(cert, crlUrl);
    }

    const now = new Date();

    // Fresh cache — use it
    if (now < entry.expiresAt) {
      return this.checkRevoked(cert, crlUrl);
    }

    // Stale but within max staleness — use stale + trigger refresh
    if (now < entry.staleAt) {
      this.triggerBackgroundRefresh(crlUrl);
      return this.checkRevoked(cert, crlUrl);
    }

    // Expired but within max staleness — use stale + sync refresh
    if (now < new Date(entry.fetchedAt.getTime() + this.config.maxStalenessHours * 3600 * 1000)) {
      await this.fetchAndCache(crlUrl); // Sync refresh
      return this.checkRevoked(cert, crlUrl);
    }

    // Beyond max staleness — fail closed (treat as revoked)
    return true;
  }

  /**
   * Check revoked status using cached CRL (assumes entry exists).
   */
  private checkRevoked(cert: X509Certificate, crlUrl: string): boolean {
    const entry = this.cache.get(crlUrl);
    if (!entry) return false; // Fail open if somehow missing

    const serial = cert.serialNumber.toUpperCase();
    const crlEntry = entry.crl.entries.get(serial);
    return !!crlEntry;
  }

  /**
   * Fetch CRL from URL and update cache.
   */
  async fetchAndCache(crlUrl: string): Promise<void> {
    if (this.refreshing.has(crlUrl)) {
      // Wait for existing refresh
      while (this.refreshing.has(crlUrl)) {
        await new Promise(r => setTimeout(r, 100));
      }
      return;
    }

    this.refreshing.add(crlUrl);

    try {
      const raw = await this.fetchWithTimeout(crlUrl);
      const parsed = this.parseCrl(raw);

      const now = new Date();
      const ttlMs = this.config.ttlHours * 3600 * 1000;
      const staleMs = ttlMs * (this.config.staleWhileRevalidatePercent / 100);

      this.cache.set(crlUrl, {
        crl: parsed,
        fetchedAt: now,
        expiresAt: new Date(now.getTime() + ttlMs),
        staleAt: new Date(now.getTime() + staleMs),
      });
    } finally {
      this.refreshing.delete(crlUrl);
    }
  }

  /**
   * Trigger background refresh (non-blocking).
   */
  private triggerBackgroundRefresh(crlUrl: string): void {
    if (this.refreshing.has(crlUrl)) return;

    this.refreshing.add(crlUrl);
    this.fetchAndCache(crlUrl).catch(err => {
      console.error(`Background CRL refresh failed for ${crlUrl}:`, err);
    }).finally(() => {
      this.refreshing.delete(crlUrl);
    });
  }

  /**
   * Fetch with timeout.
   */
  private async fetchWithTimeout(url: string): Promise<Uint8Array> {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), this.config.fetchTimeoutMs);

    try {
      const response = await fetch(url, { signal: controller.signal });
      if (!response.ok) {
        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
      }
      const arrayBuffer = await response.arrayBuffer();
      return new Uint8Array(arrayBuffer);
    } finally {
      clearTimeout(timeout);
    }
  }

  /**
   * Parse DER-encoded CRL.
   * Simplified parser — production should use a proper ASN.1 parser.
   */
  private parseCrl(raw: Uint8Array): ParsedCrl {
    // This is a simplified placeholder
    // Real implementation would use @peculiar/x509 or asn1js to parse
    // For reference implementation, we simulate a parsed CRL

    // In reality, you'd parse the ASN.1 structure:
    // CertificateList ::= SEQUENCE {
    //   tbsCertList TBSCertList,
    //   signatureAlgorithm AlgorithmIdentifier,
    //   signatureValue BIT STRING
    // }

    // For this reference, we return a mock structure
    // The test fixtures provide pre-parsed CRLs

    return {
      issuer: 'CN=DOD ID CA-XX,OU=PKI,O=DoD,C=US',
      thisUpdate: new Date(),
      nextUpdate: new Date(Date.now() + 24 * 3600 * 1000),
      entries: new Map(),
      raw,
    };
  }

  /**
   * Load pre-parsed CRL from test fixtures (for testing).
   */
  loadParsedCrl(crlUrl: string, crl: ParsedCrl): void {
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

  /**
   * Get cache statistics for monitoring.
   */
  getStats(): Record<string, { size: number; fresh: number; stale: number; expired: number }> {
    const now = new Date();
    let fresh = 0, stale = 0, expired = 0;

    for (const entry of this.cache.values()) {
      if (now < entry.expiresAt) fresh++;
      else if (now < entry.staleAt) stale++;
      else expired++;
    }

    return {
      cache: { size: this.cache.size, fresh, stale, expired },
    };
  }

  /**
   * Clear cache (for testing).
   */
  clear(): void {
    this.cache.clear();
    this.refreshing.clear();
  }
}

/**
 * Parse serial number from certificate to match CRL format.
 */
export function normalizeSerial(serial: string): string {
  // Remove leading zeros, uppercase
  return serial.replace(/^0+/, '').toUpperCase() || '0';
}

/**
 * Generate CRL cache key from URL.
 */
export function getCrlCacheKey(url: string): string {
  return createHash('sha256').update(url).digest('hex').substring(0, 32);
}