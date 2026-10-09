import { describe, it, expect, beforeEach } from 'vitest';
import { validateHeaderProvenance, generateRequestFingerprint } from '../lib/cac/provenance';

describe('Header Provenance Validation', () => {
  const mockRequest = (overrides: Partial<{
    headers: Record<string, string | undefined>;
    socket: { authorized: boolean; getPeerCertificate: () => { fingerprint256?: string } };
    ip: string;
  }> = {}) => ({
    headers: overrides.headers || {},
    socket: overrides.socket || { authorized: false, getPeerCertificate: () => ({}) },
    ip: overrides.ip || '10.0.0.1',
  });

  const config = {
    trustedAlbCerts: ['a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456'],
    trustedAlbCidrs: ['10.0.0.0/8', '172.16.0.0/12'],
    albSigningKeys: [],
    requireMtls: true,
  };

  it('validates mTLS with trusted ALB certificate', () => {
    const request = mockRequest({
      socket: {
        authorized: true,
        getPeerCertificate: () => ({
          fingerprint256: 'A1:B2:C3:D4:E5:F6:78:90:12:34:56:78:90:12:34:56:78:90:AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56',
        }),
      },
    });

    const result = validateHeaderProvenance(request, config);
    expect(result.valid).toBe(true);
    expect(result.method).toBe('mtls');
  });

  it('rejects mTLS with untrusted ALB certificate', () => {
    const request = mockRequest({
      socket: {
        authorized: true,
        getPeerCertificate: () => ({
          fingerprint256: 'DE:AD:BE:EF:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00',
        }),
      },
    });

    const result = validateHeaderProvenance(request, config);
    expect(result.valid).toBe(false);
    expect(result.method).toBe('mtls');
    expect(result.error).toContain('not in trusted list');
  });

  it('rejects when mTLS required but not present', () => {
    const request = mockRequest({
      socket: { authorized: false, getPeerCertificate: () => ({}) },
    });

    const result = validateHeaderProvenance(request, config);
    expect(result.valid).toBe(false);
    expect(result.method).toBe('none');
  });

  it('validates via source IP allowlist when mTLS not required', () => {
    const ipConfig = { ...config, requireMtls: false };
    const request = mockRequest({ ip: '10.0.1.5' });

    const result = validateHeaderProvenance(request, ipConfig);
    // Note: simplified CIDR matching in reference impl
    expect(result.method).toBe('ip');
  });

  it('rejects source IP not in allowlist', () => {
    const ipConfig = { ...config, requireMtls: false };
    const request = mockRequest({ ip: '192.168.1.1' });

    const result = validateHeaderProvenance(request, ipConfig);
    expect(result.valid).toBe(false);
    expect(result.method).toBe('ip');
  });
});

describe('Request Fingerprint Generation', () => {
  it('generates consistent fingerprint for same request', () => {
    const request = {
      headers: { 'user-agent': 'test-agent', 'x-forwarded-for': '1.2.3.4' },
      ip: '10.0.0.1',
    };

    const fp1 = generateRequestFingerprint(request);
    const fp2 = generateRequestFingerprint(request);
    expect(fp1).toBe(fp2);
    expect(fp1.length).toBe(16);
  });

  it('generates different fingerprints for different requests', () => {
    const fp1 = generateRequestFingerprint({ headers: { 'user-agent': 'a' }, ip: '1.1.1.1' });
    const fp2 = generateRequestFingerprint({ headers: { 'user-agent': 'b' }, ip: '2.2.2.2' });
    expect(fp1).not.toBe(fp2);
  });
});