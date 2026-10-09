import { z } from 'zod';

/**
 * Header contract from ALB/VDI after mTLS termination and certificate validation.
 * All headers are injected by trusted infrastructure — application validates provenance.
 */

export const CacHeadersSchema = z.object({
  /** 10-digit DoD EDIPI — primary identity key */
  'x-edipi': z.string().regex(/^\d{10}$/),

  /** Full Subject DN from certificate */
  'x-cert-subject-dn': z.string().min(1),

  /** Issuer DN from certificate */
  'x-cert-issuer-dn': z.string().min(1),

  /** Certificate serial number (hex) */
  'x-cert-serial': z.string().regex(/^[0-9A-Fa-f]+$/),

  /** Validity start (RFC3339) */
  'x-cert-not-before': z.string().datetime({ offset: true }),

  /** Expiration (RFC3339) */
  'x-cert-not-after': z.string().datetime({ offset: true }),

  /** Certificate SHA-256 thumbprint (hex, 64 chars) */
  'x-cert-sha256': z.string().regex(/^[0-9a-f]{64}$/),

  /** Optional: Full certificate in URL-encoded PEM */
  'x-forwarded-client-cert': z.string().optional(),

  /** Optional: ALB signature for provenance verification */
  'x-alb-signature': z.string().optional(),
});

export type CacHeaders = z.infer<typeof CacHeadersSchema>;

/**
 * Parsed and validated certificate metadata for application use.
 */
export interface ParsedCertMetadata {
  edipi: string;
  subjectDn: string;
  issuerDn: string;
  serial: string;
  notBefore: Date;
  notAfter: Date;
  sha256: string;
  fascn?: string; // FASC-N from SAN if present
}

/**
 * Extract and validate certificate metadata from trusted headers.
 * Assumes header provenance has already been validated.
 */
export function parseCacHeaders(headers: Record<string, string | undefined>): ParsedCertMetadata {
  const parsed = CacHeadersSchema.parse(headers);

  // Extract EDIPI from Subject DN as fallback/cross-check
  // Subject DN format: CN=LAST.FIRST.EDIPI,OU=PKI,O=DoD,C=US
  const subjectEdipiMatch = parsed['x-cert-subject-dn'].match(/CN=[^,]+\.(\d{10})/);
  const subjectEdipi = subjectEdipiMatch?.[1];

  // Cross-check header EDIPI vs Subject DN EDIPI
  if (subjectEdipi && subjectEdipi !== parsed['x-edipi']) {
    throw new Error(`EDIPI mismatch: header=${parsed['x-edipi']} subject=${subjectEdipi}`);
  }

  // Extract FASC-N from Subject DN if present (format varies)
  const fascnMatch = parsed['x-cert-subject-dn'].match(/FASC-N=([^,]+)/);
  const fascn = fascnMatch?.[1];

  return {
    edipi: parsed['x-edipi'],
    subjectDn: parsed['x-cert-subject-dn'],
    issuerDn: parsed['x-cert-issuer-dn'],
    serial: parsed['x-cert-serial'].toUpperCase(),
    notBefore: new Date(parsed['x-cert-not-before']),
    notAfter: new Date(parsed['x-cert-not-after']),
    sha256: parsed['x-cert-sha256'].toLowerCase(),
    fascn,
  };
}

/**
 * Validate certificate is currently valid (not expired, not before valid).
 */
export function validateCertValidity(metadata: ParsedCertMetadata): { valid: boolean; reason?: string } {
  const now = new Date();

  if (now < metadata.notBefore) {
    return { valid: false, reason: 'CERT_NOT_YET_VALID' };
  }

  if (now > metadata.notAfter) {
    return { valid: false, reason: 'CERT_EXPIRED' };
  }

  return { valid: true };
}

/**
 * Check if certificate is expiring soon (for proactive renewal notices).
 */
export function isCertExpiringSoon(metadata: ParsedCertMetadata, daysThreshold = 30): boolean {
  const threshold = new Date();
  threshold.setDate(threshold.getDate() + daysThreshold);
  return metadata.notAfter < threshold;
}