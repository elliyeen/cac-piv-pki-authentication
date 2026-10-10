import { createHash } from 'crypto';

/**
 * Header provenance validation — proves headers originated from trusted ALB/VDI.
 * This is the critical security control for header-based identity propagation.
 */

export interface ProvenanceConfig {
  /** Trusted ALB certificate fingerprints (SHA-256) for mTLS verification */
  trustedAlbCerts: string[];

  /** Trusted ALB CIDR ranges for source IP validation (fallback) */
  trustedAlbCidrs: string[];

  /** Public keys for signed header verification (future) */
  albSigningKeys: string[];

  /** Require mTLS validation (preferred) */
  requireMtls: boolean;
}

export interface RequestLike {
  headers: Record<string, string | undefined>;
  socket?: {
    authorized?: boolean;
    getPeerCertificate?: () => { fingerprint?: string; fingerprint256?: string; raw?: Buffer };
  };
  ip?: string;
}

/**
 * Validate that request headers originate from trusted ALB.
 * Fail closed — any validation failure rejects the request.
 */
export function validateHeaderProvenance(
  request: RequestLike,
  config: ProvenanceConfig
): { valid: boolean; method: 'mtls' | 'ip' | 'signature' | 'none'; error?: string } {
  // Method 1: mTLS between ALB and App (preferred)
  if (config.requireMtls && request.socket?.authorized && request.socket.getPeerCertificate) {
    const cert = request.socket.getPeerCertificate();
    const fingerprint = cert.fingerprint256?.replace(/:/g, '').toLowerCase() ||
                       cert.fingerprint?.replace(/:/g, '').toLowerCase();

    if (fingerprint && config.trustedAlbCerts.includes(fingerprint)) {
      return { valid: true, method: 'mtls' };
    }

    return { valid: false, method: 'mtls', error: 'ALB certificate not in trusted list' };
  }

  // mTLS is mandatory when configured: never fall through to weaker methods
  if (config.requireMtls) {
    return { valid: false, method: 'none', error: 'mTLS required but not presented' };
  }

  // Method 2: Source IP allowlist (only when mTLS is not required)
  if (request.ip && config.trustedAlbCidrs.length > 0) {
    if (config.trustedAlbCidrs.some(cidr => ipInCidr(request.ip!, cidr))) {
      return { valid: true, method: 'ip' };
    }

    return { valid: false, method: 'ip', error: `Source IP ${request.ip} not in trusted CIDRs` };
  }

  // Method 3: Signed headers (future implementation)
  const signature = request.headers['x-alb-signature'];
  if (signature && config.albSigningKeys.length > 0) {
    // TODO: Implement signature verification
    // For now, fail closed if signature present but verification not implemented
    return { valid: false, method: 'signature', error: 'Signature verification not implemented' };
  }

  // No valid provenance method
  return { valid: false, method: 'none', error: 'No valid provenance validation method configured' };
}

/**
 * IPv4 CIDR matching. Anything that is not a well-formed IPv4 address and prefix
 * does not match (fail closed); IPv6 is not supported in this reference.
 */
function ipInCidr(ip: string, cidr: string): boolean {
  const [rangeIp, bitsStr] = cidr.split('/');
  const a = ipv4ToInt(ip);
  const b = ipv4ToInt(rangeIp);
  if (a === null || b === null) return false;
  if (bitsStr === undefined) return a === b;
  const bits = Number(bitsStr);
  if (!Number.isInteger(bits) || bits < 0 || bits > 32) return false;
  const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
  return ((a & mask) >>> 0) === ((b & mask) >>> 0);
}

function ipv4ToInt(ip: string): number | null {
  const m = ip.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (!m) return null;
  const parts = m.slice(1).map(Number);
  if (parts.some(n => n > 255)) return null;
  return ((parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]) >>> 0;
}

/**
 * Generate a request fingerprint for correlation/logging.
 */
export function generateRequestFingerprint(request: RequestLike): string {
  const components = [
    request.ip || 'unknown',
    request.headers['user-agent'] || 'unknown',
    request.headers['x-forwarded-for'] || 'direct',
  ].join('|');

  return createHash('sha256').update(components).digest('hex').substring(0, 16);
}

/**
 * Default provenance configuration for development.
 * Production should load from secure configuration (Secrets Manager, etc.)
 */
export function getDefaultProvenanceConfig(): ProvenanceConfig {
  return {
    trustedAlbCerts: process.env.ALB_TRUSTED_CERTS?.split(',').map(s => s.trim().toLowerCase()) || [],
    trustedAlbCidrs: process.env.ALB_TRUSTED_CIDRS?.split(',').map(s => s.trim()) || [],
    albSigningKeys: [],
    requireMtls: process.env.NODE_ENV === 'production',
  };
}