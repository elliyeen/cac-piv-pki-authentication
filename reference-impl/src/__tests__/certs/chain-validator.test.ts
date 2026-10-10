import { describe, it, expect, beforeAll } from 'vitest';
import { PemConverter } from '@peculiar/x509';
import {
  validateCertificateChain,
  extractEdipi,
  extractFascn,
  getThumbprint,
  isPivProfile,
} from '../../lib/certs/chain-validator';
import { CrlCache } from '../../lib/certs/crl-client';
import { createRoot, createIntermediate, createLeaf, createCrl, Issued } from '../../testing/synthetic-pki';

const pem = (c: Issued) => c.cert.toString('pem');
const DAY = 24 * 3600 * 1000;

describe('Certificate chain validation (synthetic PKI)', () => {
  let root: Issued;
  let inter: Issued;
  let otherRoot: Issued;

  beforeAll(async () => {
    root = await createRoot();
    inter = await createIntermediate(root);
    otherRoot = await createRoot('CN=UNTRUSTED ROOT,O=Elsewhere,C=US');
  });

  it('accepts leaf -> intermediate -> trusted root', async () => {
    const leaf = await createLeaf(inter);
    const r = await validateCertificateChain(pem(leaf), [root.cert], { intermediates: [pem(inter)] });
    expect(r.errors).toEqual([]);
    expect(r.valid).toBe(true);
    expect(r.chain).toHaveLength(3);
  });

  it('rejects a leaf from an untrusted root', async () => {
    const leaf = await createLeaf(otherRoot);
    const r = await validateCertificateChain(pem(leaf), [root.cert]);
    expect(r.valid).toBe(false);
    expect(r.errors.join(' ')).toMatch(/No path to a trusted anchor/);
  });

  it('rejects a forged leaf that claims the right issuer name but is signed by another key', async () => {
    const leaf = await createLeaf(inter, { signingKey: otherRoot.keys.privateKey });
    const r = await validateCertificateChain(pem(leaf), [root.cert], { intermediates: [pem(inter)] });
    expect(r.valid).toBe(false);
  });

  it('rejects an expired leaf', async () => {
    const now = new Date();
    const leaf = await createLeaf(inter, { notBefore: new Date(now.getTime() - 400 * DAY), notAfter: new Date(now.getTime() - DAY) });
    const r = await validateCertificateChain(pem(leaf), [root.cert], { intermediates: [pem(inter)] });
    expect(r.valid).toBe(false);
    expect(r.errors.join(' ')).toMatch(/expired/);
  });

  it('rejects a not-yet-valid leaf', async () => {
    const now = new Date();
    const leaf = await createLeaf(inter, { notBefore: new Date(now.getTime() + DAY), notAfter: new Date(now.getTime() + 300 * DAY) });
    const r = await validateCertificateChain(pem(leaf), [root.cert], { intermediates: [pem(inter)] });
    expect(r.valid).toBe(false);
    expect(r.errors.join(' ')).toMatch(/not yet valid/);
  });

  it('validates against an explicit clock', async () => {
    const leaf = await createLeaf(inter);
    const future = new Date(Date.now() + 2000 * DAY);
    const r = await validateCertificateChain(pem(leaf), [root.cert], { intermediates: [pem(inter)], currentTime: future });
    expect(r.valid).toBe(false);
  });

  it('rejects a chain whose issuer is not a CA', async () => {
    const notCa = await createIntermediate(root, { name: 'CN=NOT A CA,O=Synthetic Test,C=US', serial: '09', isCa: false });
    const leaf = await createLeaf(notCa);
    const r = await validateCertificateChain(pem(leaf), [root.cert], { intermediates: [pem(notCa)] });
    expect(r.valid).toBe(false);
    expect(r.errors.join(' ')).toMatch(/not a CA/);
  });

  it('enforces path length constraints', async () => {
    const strictRoot = await createRoot('CN=STRICT ROOT,O=Synthetic Test,C=US');
    // pathLen 0 on the intermediate means no CA may follow it
    const i1 = await createIntermediate(strictRoot, { name: 'CN=I1,O=Synthetic Test,C=US', serial: '11', pathLen: 0 });
    const i2 = await createIntermediate(i1, { name: 'CN=I2,O=Synthetic Test,C=US', serial: '12', pathLen: 0 });
    const leaf = await createLeaf(i2);
    const r = await validateCertificateChain(pem(leaf), [strictRoot.cert], { intermediates: [pem(i1), pem(i2)] });
    expect(r.valid).toBe(false);
    expect(r.errors.join(' ')).toMatch(/Path length/);
  });

  it('rejects a leaf without the Client Authentication EKU', async () => {
    const leaf = await createLeaf(inter, { clientAuthEku: false });
    const r = await validateCertificateChain(pem(leaf), [root.cert], { intermediates: [pem(inter)] });
    expect(r.valid).toBe(false);
    expect(r.errors.join(' ')).toMatch(/EKU/);
  });

  it('rejects garbage input without throwing', async () => {
    const r = await validateCertificateChain('not a certificate', [root.cert]);
    expect(r.valid).toBe(false);
  });

  describe('revocation', () => {
    it('fails closed when revocation checking is requested without a CRL client', async () => {
      const leaf = await createLeaf(inter);
      const r = await validateCertificateChain(pem(leaf), [root.cert], { intermediates: [pem(inter)], checkRevocation: true });
      expect(r.valid).toBe(false);
      expect(r.errors[0]).toMatch(/no CRL client/);
    });

    it('rejects a certificate listed on a signed CRL and accepts one that is not', async () => {
      const revoked = await createLeaf(inter, { serial: '5EAD01', edipi: '1111111111' });
      const good = await createLeaf(inter, { serial: '3EEF02', edipi: '2222222222' });
      const crls: Record<string, Uint8Array> = {
        'http://crl.test/inter.crl': await createCrl(inter, ['5EAD01']),
        'http://crl.test/root.crl': await createCrl(root, []),
      };
      const cache = new CrlCache({
        fetchImpl: async url => new Response(crls[String(url)] as BodyInit),
      });
      const crlClient = {
        isRevoked: (c: Issued['cert'], issuer: Issued['cert']) =>
          cache.isRevoked(c, issuer.subject === inter.cert.subject ? 'http://crl.test/inter.crl' : 'http://crl.test/root.crl', issuer),
      };
      const opts = { intermediates: [pem(inter)], checkRevocation: true, crlClient };

      const bad = await validateCertificateChain(pem(revoked), [root.cert], opts);
      expect(bad.valid).toBe(false);
      expect(bad.errors.join(' ')).toMatch(/Certificate revoked/);

      const ok = await validateCertificateChain(pem(good), [root.cert], opts);
      expect(ok.errors).toEqual([]);
      expect(ok.valid).toBe(true);
    });

    it('rejects a CRL whose signature does not verify against the issuer', async () => {
      const forged = await createCrl(otherRoot, ['5EAD01']);
      const cache = new CrlCache({ fetchImpl: async () => new Response(forged as BodyInit) });
      const leaf = await createLeaf(inter);
      await expect(cache.isRevoked(leaf.cert, 'http://crl.test/inter.crl', inter.cert)).rejects.toThrow(/CRL unavailable/);
    });

    it('fails closed when the CRL cannot be retrieved', async () => {
      const cache = new CrlCache({ fetchImpl: async () => { throw new Error('offline'); } });
      const leaf = await createLeaf(inter);
      const crlClient = { isRevoked: (c: Issued['cert'], issuer: Issued['cert']) => cache.isRevoked(c, 'http://crl.test/x.crl', issuer) };
      const r = await validateCertificateChain(pem(leaf), [root.cert], { intermediates: [pem(inter)], checkRevocation: true, crlClient });
      expect(r.valid).toBe(false);
      expect(r.errors.join(' ')).toMatch(/Revocation status unavailable/);
    });
  });

  describe('identity extraction', () => {
    it('extracts EDIPI, PIV-I policy and thumbprint', async () => {
      const leaf = await createLeaf(inter, { edipi: '9876543210' });
      expect(extractEdipi(leaf.cert)).toBe('9876543210');
      expect(isPivProfile(leaf.cert)).toBe(true);
      expect(getThumbprint(leaf.cert)).toMatch(/^[0-9a-f]{64}$/);
      expect(extractFascn(leaf.cert)).toBeNull();
    });

    it('does not report PIV-I for a CA certificate', () => {
      expect(isPivProfile(inter.cert)).toBe(false);
      expect(PemConverter.isPem(pem(inter))).toBe(true);
    });
  });
});
