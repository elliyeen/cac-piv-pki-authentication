#!/usr/bin/env tsx
/**
 * Synthetic Certificate Generation for Testing
 * Generates PIV-I-like certificates for testing without using real PKI material.
 * All certificates are self-signed or signed by a synthetic root CA.
 */

import { createHash, randomBytes, sign, verify, generateKeyPairSync, KeyPairKeyObjectResult } from 'crypto';
import { X509Certificate, CertificateBuilder, AttributeTypeAndValue } from '@peculiar/x509';
import { writeFileSync, mkdirSync, existsSync } from 'fs';
import { join } from 'path';

// Configuration
const FIXTURES_DIR = join(__dirname, '..', '..', 'test-fixtures', 'certs');
const CRL_DIR = join(__dirname, '..', '..', 'test-fixtures', 'crls');

interface CertOptions {
  subject: string;
  issuer: string;
  serialNumber: string;
  notBefore: Date;
  notAfter: Date;
  keyUsage?: string[];
  extKeyUsage?: string[];
  certificatePolicies?: string[];
  subjectAltName?: string[];
  isCA?: boolean;
  pathLenConstraint?: number;
}

interface KeyPair {
  privateKey: KeyPairKeyObjectResult;
  publicKey: KeyPairKeyObjectResult;
}

/**
 * Generate RSA key pair
 */
function generateKeyPair(): KeyPair {
  const { privateKey, publicKey } = generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });
  return { privateKey, publicKey };
}

/**
 * Build X.509 certificate using @peculiar/x509
 */
function buildCertificate(
  options: CertOptions,
  issuerKeyPair: KeyPair,
  subjectKeyPair: KeyPair
): X509Certificate {
  const builder = new CertificateBuilder({
    version: 2, // X.509 v3
    serialNumber: options.serialNumber,
    issuer: { name: options.issuer },
    subject: { name: options.subject },
    notBefore: options.notBefore,
    notAfter: options.notAfter,
    publicKey: subjectKeyPair.publicKey,
  });

  // Basic Constraints
  if (options.isCA) {
    builder.basicConstraints = { cA: true, pathLenConstraint: options.pathLenConstraint ?? 0 };
  } else {
    builder.basicConstraints = { cA: false };
  }

  // Key Usage
  if (options.keyUsage) {
    builder.keyUsage = options.keyUsage.reduce((acc, ku) => {
      acc[ku] = true;
      return acc;
    }, {} as Record<string, boolean>);
  }

  // Extended Key Usage
  if (options.extKeyUsage) {
    builder.extKeyUsage = options.extKeyUsage;
  }

  // Certificate Policies
  if (options.certificatePolicies) {
    builder.certificatePolicies = options.certificatePolicies.map(oid => ({ policyIdentifier: oid }));
  }

  // Subject Alternative Name
  if (options.subjectAltName) {
    builder.subjectAltName = options.subjectAltName.map(san => {
      if (san.includes('@')) return { type: 'rfc822Name', value: san };
      if (san.startsWith('FASC-N=')) return { type: 'otherName', value: san };
      return { type: 'dNSName', value: san };
    });
  }

  // Subject Key Identifier
  const spki = subjectKeyPair.publicKey.export({ type: 'spki', format: 'der' });
  const ski = createHash('sha1').update(spki).digest();
  builder.subjectKeyIdentifier = Buffer.from(ski).toString('hex');

  // Authority Key Identifier
  const issuerSpki = issuerKeyPair.publicKey.export({ type: 'spki', format: 'der' });
  const aki = createHash('sha1').update(issuerSpki).digest();
  builder.authorityKeyIdentifier = {
    keyIdentifier: Buffer.from(aki).toString('hex'),
    authorityCertIssuer: [{ type: 'directoryName', value: options.issuer }],
    authorityCertSerialNumber: options.serialNumber,
  };

  // Sign certificate
  const cert = builder.sign(issuerKeyPair.privateKey, 'SHA256');
  return cert;
}

/**
 * Generate synthetic root CA
 */
function generateRootCA(): { cert: X509Certificate; keyPair: KeyPair } {
  const keyPair = generateKeyPair();
  const now = new Date();
  const tenYears = new Date(now.getTime() + 10 * 365 * 24 * 3600 * 1000);

  const cert = buildCertificate({
    subject: 'CN=SYNTHETIC ROOT CA,O=Elliyeen Test,C=US',
    issuer: 'CN=SYNTHETIC ROOT CA,O=Elliyeen Test,C=US', // Self-signed
    serialNumber: '01',
    notBefore: now,
    notAfter: tenYears,
    keyUsage: ['keyCertSign', 'cRLSign'],
    isCA: true,
    pathLenConstraint: 1,
  }, keyPair, keyPair);

  return { cert, keyPair };
}

/**
 * Generate synthetic intermediate CA
 */
function generateIntermediateCA(root: { cert: X509Certificate; keyPair: KeyPair }): { cert: X509Certificate; keyPair: KeyPair } {
  const keyPair = generateKeyPair();
  const now = new Date();
  const fiveYears = new Date(now.getTime() + 5 * 365 * 24 * 3600 * 1000);

  const cert = buildCertificate({
    subject: 'CN=SYNTHETIC INTERMEDIATE CA,O=Elliyeen Test,C=US',
    issuer: root.cert.subject,
    serialNumber: '02',
    notBefore: now,
    notAfter: fiveYears,
    keyUsage: ['keyCertSign', 'cRLSign'],
    isCA: true,
    pathLenConstraint: 0,
  }, root.keyPair, keyPair);

  return { cert, keyPair };
}

/**
 * Generate PIV-I-like end-entity certificate
 */
function generatePivCert(
  intermediate: { cert: X509Certificate; keyPair: KeyPair },
  edipi: string,
  options: { expired?: boolean; revoked?: boolean; malformed?: string } = {}
): { cert: X509Certificate; keyPair: KeyPair } {
  const keyPair = generateKeyPair();
  const now = new Date();

  let notBefore = new Date(now.getTime() - 365 * 24 * 3600 * 1000); // 1 year ago
  let notAfter = new Date(now.getTime() + 365 * 24 * 3600 * 1000); // 1 year from now

  if (options.expired) {
    notAfter = new Date(now.getTime() - 24 * 3600 * 1000); // Expired 1 day ago
    notBefore = new Date(now.getTime() - 2 * 365 * 24 * 3600 * 1000);
  }

  const cert = buildCertificate({
    subject: `CN=DOE.JOHN.${edipi},OU=PKI,O=DoD,C=US`,
    issuer: intermediate.cert.subject,
    serialNumber: createHash('sha256').update(edipi).digest('hex').substring(0, 16).toUpperCase(),
    notBefore,
    notAfter,
    keyUsage: ['digitalSignature', 'keyEncipherment', 'keyAgreement'],
    extKeyUsage: ['1.3.6.1.5.5.7.3.2', '2.16.840.1.101.3.2.1.3.13'], // Client Auth + PIV-I
    certificatePolicies: ['2.16.840.1.101.3.2.1.3.13'], // PIV-I policy OID
    subjectAltName: [
      `${edipi}@mil`,
      `FASC-N=12345678901234567890123456789012`,
    ],
    isCA: false,
  }, intermediate.keyPair, keyPair);

  return { cert, keyPair };
}

/**
 * Generate malformed/negative test certificates
 */
function generateNegativeCerts(intermediate: { cert: X509Certificate; keyPair: KeyPair }): Array<{ name: string; cert: X509Certificate; keyPair: KeyPair }> {
  const certs: Array<{ name: string; cert: X509Certificate; keyPair: KeyPair }> = [];

  // Self-signed (no chain to root)
  const selfSignedKeyPair = generateKeyPair();
  const selfSigned = buildCertificate({
    subject: 'CN=SELF SIGNED,O=Elliyeen Test,C=US',
    issuer: 'CN=SELF SIGNED,O=Elliyeen Test,C=US',
    serialNumber: 'DEADBEEF',
    notBefore: new Date(),
    notAfter: new Date(Date.now() + 365 * 24 * 3600 * 1000),
    keyUsage: ['digitalSignature'],
    isCA: false,
  }, selfSignedKeyPair, selfSignedKeyPair);
  certs.push({ name: 'self-signed', cert: selfSigned, keyPair: selfSignedKeyPair });

  // Wrong EKU (no client auth)
  const wrongEkuKeyPair = generateKeyPair();
  const wrongEku = buildCertificate({
    subject: 'CN=WRONG EKU,O=Elliyeen Test,C=US',
    issuer: intermediate.cert.subject,
    serialNumber: 'WRONGEKU',
    notBefore: new Date(),
    notAfter: new Date(Date.now() + 365 * 24 * 3600 * 1000),
    keyUsage: ['digitalSignature'],
    extKeyUsage: ['1.3.6.1.5.5.7.3.1'], // Server Auth only
    isCA: false,
  }, intermediate.keyPair, wrongEkuKeyPair);
  certs.push({ name: 'wrong-eku', cert: wrongEku, keyPair: wrongEkuKeyPair });

  // Path length exceeded (intermediate -> intermediate -> leaf)
  const extraIntermediateKeyPair = generateKeyPair();
  const extraIntermediate = buildCertificate({
    subject: 'CN=EXTRA INTERMEDIATE,O=Elliyeen Test,C=US',
    issuer: intermediate.cert.subject,
    serialNumber: 'EXTRAINT',
    notBefore: new Date(),
    notAfter: new Date(Date.now() + 365 * 24 * 3600 * 1000),
    keyUsage: ['keyCertSign', 'cRLSign'],
    isCA: true,
    pathLenConstraint: 0, // Path length 0 - no more intermediates
  }, intermediate.keyPair, extraIntermediateKeyPair);

  const pathLenKeyPair = generateKeyPair();
  const pathLenExceeded = buildCertificate({
    subject: 'CN=PATH LEN EXCEEDED,O=Elliyeen Test,C=US',
    issuer: extraIntermediate.subject,
    serialNumber: 'PATHLENX',
    notBefore: new Date(),
    notAfter: new Date(Date.now() + 365 * 24 * 3600 * 1000),
    keyUsage: ['digitalSignature'],
    extKeyUsage: ['1.3.6.1.5.5.7.3.2'],
    isCA: false,
  }, extraIntermediateKeyPair, pathLenKeyPair);
  certs.push({ name: 'path-len-exceeded', cert: pathLenExceeded, keyPair: pathLenKeyPair });

  return certs;
}

/**
 * Generate synthetic CRL
 */
function generateCrl(
  issuer: { cert: X509Certificate; keyPair: KeyPair },
  revokedSerials: string[]
): string {
  // Simplified CRL generation - in reality use proper ASN.1
  // For reference implementation, we create a PEM-formatted placeholder
  const now = new Date();
  const nextUpdate = new Date(now.getTime() + 24 * 3600 * 1000);

  const crlEntries = revokedSerials.map(serial => ({
    serialNumber: serial,
    revocationDate: new Date(now.getTime() - 30 * 24 * 3600 * 1000), // 30 days ago
    reason: 0, // unspecified
  }));

  // This is a placeholder - real CRL would be DER-encoded
  const crlPem = `-----BEGIN X509 CRL-----
MIIB... (placeholder CRL for ${revokedSerials.length} revoked certs)
Issuer: ${issuer.cert.subject}
This Update: ${now.toISOString()}
Next Update: ${nextUpdate.toISOString()}
Revoked Certificates:
${crlEntries.map(e => `  Serial: ${e.serialNumber}, Date: ${e.revocationDate.toISOString()}`).join('\n')}
-----END X509 CRL-----`;

  return crlPem;
}

/**
 * Save certificate to file
 */
function saveCert(name: string, cert: X509Certificate): void {
  const pem = cert.toString('pem');
  writeFileSync(join(FIXTURES_DIR, `${name}.pem`), pem);
  console.log(`Saved ${name}.pem`);
}

/**
 * Save private key to file (for testing only)
 */
function saveKey(name: string, keyPair: KeyPair): void {
  const pem = keyPair.privateKey.export({ type: 'pkcs8', format: 'pem' });
  writeFileSync(join(FIXTURES_DIR, `${name}.key`), pem);
  console.log(`Saved ${name}.key`);
}

/**
 * Main generation function
 */
async function main() {
  console.log('Generating synthetic certificates...');

  // Create directories
  mkdirSync(FIXTURES_DIR, { recursive: true });
  mkdirSync(CRL_DIR, { recursive: true });

  // Generate root CA
  const root = generateRootCA();
  saveCert('root-ca', root.cert);
  saveKey('root-ca', root.keyPair);

  // Generate intermediate CA
  const intermediate = generateIntermediateCA(root);
  saveCert('intermediate-ca', intermediate.cert);
  saveKey('intermediate-ca', intermediate.keyPair);

  // Generate valid PIV-I certificate
  const validEdipi = '9999999999';
  const valid = generatePivCert(intermediate, validEdipi);
  saveCert('valid-piv', valid.cert);
  saveKey('valid-piv', valid.keyPair);

  // Generate expired certificate
  const expired = generatePivCert(intermediate, '8888888888', { expired: true });
  saveCert('expired-piv', expired.cert);
  saveKey('expired-piv', expired.keyPair);

  // Generate revoked certificate (serial will be in CRL)
  const revoked = generatePivCert(intermediate, '7777777777');
  saveCert('revoked-piv', revoked.cert);
  saveKey('revoked-piv', revoked.keyPair);

  // Generate negative test certificates
  const negativeCerts = generateNegativeCerts(intermediate);
  for (const nc of negativeCerts) {
    saveCert(`malformed-${nc.name}`, nc.cert);
    saveKey(`malformed-${nc.name}`, nc.keyPair);
  }

  // Generate CRL with revoked serial
  const revokedSerial = revoked.cert.serialNumber;
  const crlPem = generateCrl(intermediate, [revokedSerial]);
  writeFileSync(join(CRL_DIR, 'crl.pem'), crlPem);
  console.log('Saved crl.pem');

  // Generate headers fixture
  const headersFixture = {
    'x-edipi': validEdipi,
    'x-cert-subject-dn': valid.cert.subject,
    'x-cert-issuer-dn': valid.cert.issuer,
    'x-cert-serial': valid.cert.serialNumber,
    'x-cert-not-before': valid.cert.notBefore.toISOString(),
    'x-cert-not-after': valid.cert.notAfter.toISOString(),
    'x-cert-sha256': createHash('sha256').update(valid.cert.raw).digest('hex'),
  };
  writeFileSync(join(__dirname, '..', '..', 'test-fixtures', 'headers', 'valid-headers.json'), JSON.stringify(headersFixture, null, 2));
  console.log('Saved valid-headers.json');

  console.log('\n✅ Synthetic certificate generation complete!');
  console.log(`Fixtures saved to: ${FIXTURES_DIR}`);
  console.log(`CRLs saved to: ${CRL_DIR}`);
}

// Run if executed directly
if (import.meta.url === `file://${process.argv[1]}`) {
  main().catch(console.error);
}