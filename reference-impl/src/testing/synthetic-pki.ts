/**
 * Synthetic PKI for tests and demos. Everything here is generated at run time from
 * throwaway keys. No real DoD, federal or customer certificate material is involved.
 */
import * as x509 from '@peculiar/x509';

export const ALG = { name: 'ECDSA', namedCurve: 'P-256', hash: 'SHA-256' } as const;
const PIV_I_POLICY = '2.16.840.1.101.3.2.1.3.13';
const DAY = 24 * 3600 * 1000;

export interface Issued {
  cert: x509.X509Certificate;
  keys: CryptoKeyPair;
}

const newKeys = () => crypto.subtle.generateKey(ALG, true, ['sign', 'verify']) as Promise<CryptoKeyPair>;

export async function createRoot(name = 'CN=SYNTHETIC ROOT CA,O=Synthetic Test,C=US', now = new Date()): Promise<Issued> {
  const keys = await newKeys();
  const cert = await x509.X509CertificateGenerator.createSelfSigned({
    serialNumber: '01',
    name,
    notBefore: new Date(now.getTime() - DAY),
    notAfter: new Date(now.getTime() + 3650 * DAY),
    signingAlgorithm: ALG,
    keys,
    extensions: [
      new x509.BasicConstraintsExtension(true, 2, true),
      new x509.KeyUsagesExtension(x509.KeyUsageFlags.keyCertSign | x509.KeyUsageFlags.cRLSign, true),
    ],
  });
  return { cert, keys };
}

export async function createIntermediate(
  parent: Issued,
  opts: { name?: string; serial?: string; pathLen?: number; isCa?: boolean; now?: Date } = {}
): Promise<Issued> {
  const now = opts.now ?? new Date();
  const keys = await newKeys();
  const cert = await x509.X509CertificateGenerator.create({
    serialNumber: opts.serial ?? '02',
    subject: opts.name ?? 'CN=SYNTHETIC INTERMEDIATE CA,O=Synthetic Test,C=US',
    issuer: parent.cert.subject,
    notBefore: new Date(now.getTime() - DAY),
    notAfter: new Date(now.getTime() + 1825 * DAY),
    signingAlgorithm: ALG,
    publicKey: keys.publicKey,
    signingKey: parent.keys.privateKey,
    extensions: [
      new x509.BasicConstraintsExtension(opts.isCa ?? true, opts.pathLen ?? 0, true),
      new x509.KeyUsagesExtension(x509.KeyUsageFlags.keyCertSign | x509.KeyUsageFlags.cRLSign, true),
    ],
  });
  return { cert, keys };
}

export interface LeafOptions {
  edipi?: string;
  serial?: string;
  notBefore?: Date;
  notAfter?: Date;
  clientAuthEku?: boolean;
  /** Claim this issuer name but sign with `signingKey` (for forgery tests). */
  issuerName?: string;
  signingKey?: CryptoKey;
  now?: Date;
}

export async function createLeaf(issuer: Issued, opts: LeafOptions = {}): Promise<Issued> {
  const now = opts.now ?? new Date();
  const edipi = opts.edipi ?? '1234567890';
  const keys = await newKeys();
  const extensions: x509.Extension[] = [
    new x509.BasicConstraintsExtension(false, undefined, true),
    new x509.KeyUsagesExtension(x509.KeyUsageFlags.digitalSignature, true),
    new x509.CertificatePolicyExtension([PIV_I_POLICY]),
    new x509.SubjectAlternativeNameExtension([{ type: 'email', value: `${edipi}@mil` }]),
  ];
  if (opts.clientAuthEku !== false) {
    extensions.push(new x509.ExtendedKeyUsageExtension([x509.ExtendedKeyUsage.clientAuth], false));
  }
  const cert = await x509.X509CertificateGenerator.create({
    serialNumber: opts.serial ?? 'A1B2C3',
    subject: `CN=DOE.JOHN.${edipi},OU=PKI,O=Synthetic Test,C=US`,
    issuer: opts.issuerName ?? issuer.cert.subject,
    notBefore: opts.notBefore ?? new Date(now.getTime() - 30 * DAY),
    notAfter: opts.notAfter ?? new Date(now.getTime() + 330 * DAY),
    signingAlgorithm: ALG,
    publicKey: keys.publicKey,
    signingKey: opts.signingKey ?? issuer.keys.privateKey,
    extensions,
  });
  return { cert, keys };
}

export async function createCrl(
  issuer: Issued,
  revokedSerials: string[],
  now = new Date()
): Promise<Uint8Array> {
  const crl = await x509.X509CrlGenerator.create({
    issuer: issuer.cert.subject,
    thisUpdate: new Date(now.getTime() - DAY),
    nextUpdate: new Date(now.getTime() + DAY),
    entries: revokedSerials.map(serialNumber => ({ serialNumber, revocationDate: new Date(now.getTime() - DAY) })),
    signingAlgorithm: ALG,
    signingKey: issuer.keys.privateKey,
  });
  return new Uint8Array(crl.rawData);
}
