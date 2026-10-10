import {
  X509Certificate,
  BasicConstraintsExtension,
  CertificatePolicyExtension,
  ExtendedKeyUsageExtension,
  KeyUsageFlags,
  KeyUsagesExtension,
  SubjectAlternativeNameExtension,
} from '@peculiar/x509';
import { createHash } from 'crypto';

/**
 * Certificate chain validation for environments requiring in-app PKI validation.
 * Reference implementation. Production deployments may use platform validation (Option B, see ADR-0001).
 *
 * Scope: signature, validity period, CA constraints, leaf EKU and CRL-based revocation.
 * Not implemented: OCSP, name constraints, policy mapping, AIA chasing.
 */

const OID_CLIENT_AUTH = '1.3.6.1.5.5.7.3.2';
const OID_PIV_I_POLICY = '2.16.840.1.101.3.2.1.3.13';

/** Trust anchors are certificates the deployment has chosen to trust explicitly. */
export type TrustAnchor = X509Certificate;

export interface CrlClient {
  /** `issuer` is the certificate that signed `cert`; its CRL is the one that applies. */
  isRevoked(cert: X509Certificate, issuer: X509Certificate): Promise<boolean>;
}

export interface ValidationOptions {
  /** Additional, untrusted certificates used only to build the path. */
  intermediates?: string[];
  checkRevocation?: boolean;
  crlClient?: CrlClient;
  currentTime?: Date;
  maxDepth?: number;
}

export interface ValidationResult {
  valid: boolean;
  errors: string[];
  /** Leaf first, trust anchor last (when a path was found). */
  chain: X509Certificate[];
}

const sameCert = (a: X509Certificate, b: X509Certificate) =>
  Buffer.from(a.rawData).equals(Buffer.from(b.rawData));

async function findIssuer(
  cert: X509Certificate,
  candidates: X509Certificate[],
  now: Date
): Promise<X509Certificate | undefined> {
  for (const candidate of candidates) {
    if (candidate.subject !== cert.issuer) continue;
    // Signature check decides; a matching name alone is never enough.
    if (await cert.verify({ publicKey: candidate, signatureOnly: true }).catch(() => false)) {
      return candidate;
    }
  }
  return undefined;
}

/**
 * Validate an X.509 certificate chain against explicitly configured trust anchors.
 * Fails closed: any error, missing anchor or misconfiguration yields `valid: false`.
 */
export async function validateCertificateChain(
  certPem: string,
  trustAnchors: TrustAnchor[],
  options: ValidationOptions = {}
): Promise<ValidationResult> {
  const errors: string[] = [];
  const now = options.currentTime ?? new Date();
  const maxDepth = options.maxDepth ?? 10;

  if (options.checkRevocation && !options.crlClient) {
    return { valid: false, errors: ['Revocation checking requested but no CRL client configured'], chain: [] };
  }

  let leaf: X509Certificate;
  let pool: X509Certificate[];
  try {
    leaf = new X509Certificate(certPem);
    pool = (options.intermediates ?? []).map(pem => new X509Certificate(pem));
  } catch (e) {
    return { valid: false, errors: [`Unparseable certificate: ${(e as Error).message}`], chain: [] };
  }

  // Build the path: leaf -> ... -> trust anchor
  const chain: X509Certificate[] = [leaf];
  let current = leaf;
  let anchored = false;
  for (let depth = 0; depth < maxDepth; depth++) {
    const anchor = await findIssuer(current, trustAnchors, now);
    if (anchor) {
      chain.push(anchor);
      anchored = true;
      break;
    }
    const intermediate = await findIssuer(current, pool.filter(c => !chain.some(x => sameCert(x, c))), now);
    if (!intermediate) break;
    chain.push(intermediate);
    current = intermediate;
  }
  if (!anchored) {
    errors.push(`No path to a trusted anchor for issuer: ${current.issuer}`);
    return { valid: false, errors, chain };
  }

  // Validity period for every certificate, including the anchor
  for (const cert of chain) {
    if (now < cert.notBefore) errors.push(`Certificate not yet valid: ${cert.subject}`);
    if (now > cert.notAfter) errors.push(`Certificate expired: ${cert.subject}`);
  }

  // CA constraints for every issuer in the path (everything after the leaf)
  for (let i = 1; i < chain.length; i++) {
    const ca = chain[i];
    const bc = ca.getExtension(BasicConstraintsExtension);
    if (!bc || !bc.ca) {
      errors.push(`Issuer is not a CA (basicConstraints): ${ca.subject}`);
    } else if (bc.pathLength !== undefined) {
      // CAs strictly between the leaf and this CA
      const below = i - 1;
      if (below > bc.pathLength) errors.push(`Path length constraint exceeded at ${ca.subject}`);
    }
    const ku = ca.getExtension(KeyUsagesExtension);
    if (!ku || !(ku.usages & KeyUsageFlags.keyCertSign)) {
      errors.push(`CA certificate missing keyCertSign: ${ca.subject}`);
    }
  }

  // Leaf must be an end-entity authorised for client authentication
  const leafBc = leaf.getExtension(BasicConstraintsExtension);
  if (leafBc?.ca) errors.push(`Leaf certificate is a CA: ${leaf.subject}`);
  const eku = leaf.getExtension(ExtendedKeyUsageExtension);
  if (!eku || !eku.usages.some(u => String(u) === OID_CLIENT_AUTH)) {
    errors.push('Leaf certificate missing required EKU (Client Authentication)');
  }

  // Revocation (CRL only). Every non-anchor certificate is checked.
  if (options.checkRevocation && options.crlClient) {
    for (let i = 0; i < chain.length - 1; i++) {
      const cert = chain[i];
      let revoked: boolean;
      try {
        revoked = await options.crlClient.isRevoked(cert, chain[i + 1]);
      } catch (e) {
        errors.push(`Revocation status unavailable for ${cert.subject}: ${(e as Error).message}`);
        continue;
      }
      if (revoked) errors.push(`Certificate revoked: ${cert.subject} (serial: ${cert.serialNumber})`);
    }
  }

  return { valid: errors.length === 0, errors, chain };
}

function sanValues(cert: X509Certificate): string[] {
  const san = cert.getExtension(SubjectAlternativeNameExtension);
  return san ? san.names.items.map(n => `${n.type}:${n.value}`) : [];
}

/** Extract EDIPI (10 digits) from the Subject CN, falling back to a SAN entry like `1234567890@mil`. */
export function extractEdipi(cert: X509Certificate): string | null {
  const fromSubject = cert.subject.match(/CN=[^,]+\.(\d{10})(?:,|$)/);
  if (fromSubject) return fromSubject[1];
  for (const v of sanValues(cert)) {
    const m = v.match(/(?:^|:)(\d{10})@/);
    if (m) return m[1];
  }
  return null;
}

/** Extract a FASC-N from the Subject or a SAN entry. */
export function extractFascn(cert: X509Certificate): string | null {
  const fromSubject = cert.subject.match(/FASC-N=([^,]+)/);
  if (fromSubject) return fromSubject[1];
  for (const v of sanValues(cert)) {
    const m = v.match(/FASC-N=([^,\s]+)/);
    if (m) return m[1];
  }
  return null;
}

/** SHA-256 thumbprint of the DER encoding. */
export function getThumbprint(cert: X509Certificate): string {
  return createHash('sha256').update(Buffer.from(cert.rawData)).digest('hex');
}

/** True when the certificate asserts the PIV-I certificate policy. */
export function isPivProfile(cert: X509Certificate): boolean {
  const policies = cert.getExtension(CertificatePolicyExtension)?.policies ?? [];
  return policies.includes(OID_PIV_I_POLICY);
}
