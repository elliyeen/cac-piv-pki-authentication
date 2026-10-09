import { describe, it, expect, beforeEach, vi } from 'vitest';
import { parseCacHeaders, validateCertValidity, isCertExpiringSoon } from '../lib/cac/headers';

describe('CAC Header Parsing', () => {
  const validHeaders = {
    'x-edipi': '1234567890',
    'x-cert-subject-dn': 'CN=DOE.JOHN.1234567890,OU=PKI,O=DoD,C=US',
    'x-cert-issuer-dn': 'CN=DOD ID CA-XX,OU=PKI,O=DoD,C=US',
    'x-cert-serial': '0A1B2C3D4E5F',
    'x-cert-not-before': '2024-01-15T08:00:00Z',
    'x-cert-not-after': '2026-01-15T08:00:00Z',
    'x-cert-sha256': 'a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456',
  };

  it('parses valid headers correctly', () => {
    const result = parseCacHeaders(validHeaders);

    expect(result.edipi).toBe('1234567890');
    expect(result.subjectDn).toBe('CN=DOE.JOHN.1234567890,OU=PKI,O=DoD,C=US');
    expect(result.issuerDn).toBe('CN=DOD ID CA-XX,OU=PKI,O=DoD,C=US');
    expect(result.serial).toBe('0A1B2C3D4E5F');
    expect(result.notBefore).toEqual(new Date('2024-01-15T08:00:00Z'));
    expect(result.notAfter).toEqual(new Date('2026-01-15T08:00:00Z'));
    expect(result.sha256).toBe('a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456');
  });

  it('extracts FASC-N from Subject DN when present', () => {
    const headersWithFascn = {
      ...validHeaders,
      'x-cert-subject-dn': 'CN=DOE.JOHN.1234567890,FASC-N=12345678901234567890123456789012,OU=PKI,O=DoD,C=US',
    };

    const result = parseCacHeaders(headersWithFascn);
    expect(result.fascn).toBe('12345678901234567890123456789012');
  });

  it('throws on EDIPI mismatch between header and Subject DN', () => {
    const mismatchedHeaders = {
      ...validHeaders,
      'x-edipi': '1234567890',
      'x-cert-subject-dn': 'CN=DOE.JANE.9999999999,OU=PKI,O=DoD,C=US',
    };

    expect(() => parseCacHeaders(mismatchedHeaders)).toThrow('EDIPI mismatch');
  });

  it('rejects invalid EDIPI format', () => {
    const invalidHeaders = { ...validHeaders, 'x-edipi': 'not-a-number' };
    expect(() => parseCacHeaders(invalidHeaders)).toThrow();
  });

  it('rejects missing required headers', () => {
    const incompleteHeaders = { ...validHeaders };
    delete incompleteHeaders['x-edipi'];
    expect(() => parseCacHeaders(incompleteHeaders)).toThrow();
  });
});

describe('Certificate Validity Validation', () => {
  const now = new Date('2025-06-15T12:00:00Z');
  const validMetadata = {
    edipi: '1234567890',
    subjectDn: 'CN=DOE.JOHN.1234567890,OU=PKI,O=DoD,C=US',
    issuerDn: 'CN=DOD ID CA-XX,OU=PKI,O=DoD,C=US',
    serial: '0A1B2C3D4E5F',
    notBefore: new Date('2024-01-15T08:00:00Z'),
    notAfter: new Date('2026-01-15T08:00:00Z'),
    sha256: 'a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456',
  };

  it('returns valid for current certificate', () => {
    const result = validateCertValidity(validMetadata, now);
    expect(result.valid).toBe(true);
  });

  it('rejects expired certificate', () => {
    const expired = { ...validMetadata, notAfter: new Date('2024-01-15T08:00:00Z') };
    const result = validateCertValidity(expired, now);
    expect(result.valid).toBe(false);
    expect(result.reason).toBe('CERT_EXPIRED');
  });

  it('rejects not-yet-valid certificate', () => {
    const future = { ...validMetadata, notBefore: new Date('2026-01-15T08:00:00Z') };
    const result = validateCertValidity(future, now);
    expect(result.valid).toBe(false);
    expect(result.reason).toBe('CERT_NOT_YET_VALID');
  });
});

describe('Certificate Expiry Warning', () => {
  const baseMetadata = {
    edipi: '1234567890',
    subjectDn: 'CN=DOE.JOHN.1234567890,OU=PKI,O=DoD,C=US',
    issuerDn: 'CN=DOD ID CA-XX,OU=PKI,O=DoD,C=US',
    serial: '0A1B2C3D4E5F',
    notBefore: new Date('2024-01-15T08:00:00Z'),
    sha256: 'a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456',
  };

  it('returns true when cert expires within threshold', () => {
    const expiringSoon = { ...baseMetadata, notAfter: new Date('2025-07-01T00:00:00Z') };
    const result = isCertExpiringSoon(expiringSoon, 30);
    expect(result).toBe(true);
  });

  it('returns false when cert expires after threshold', () => {
    const notExpiring = { ...baseMetadata, notAfter: new Date('2026-01-15T08:00:00Z') };
    const result = isCertExpiringSoon(notExpiring, 30);
    expect(result).toBe(false);
  });
});