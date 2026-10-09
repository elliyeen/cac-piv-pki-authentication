import { X509Certificate } from '@peculiar/x509';
import { createHash } from 'crypto';

/**
 * Certificate chain validation for environments requiring in-app PKI validation.
 * Reference implementation — production deployments may use platform validation (Option B).
 */

export interface TrustAnchor {
  subject: string;
  publicKey: CryptoKey;
  cert: X509Certificate;
}

export interface ValidationResult {
  valid: boolean;
  errors: string[];
  chain: X509Certificate[];
  leaf: X509Certificate;
}

/**
 * Validate an X.509 certificate chain against configured trust anchors.
 * Implements RFC 5280 path validation.
 */
export async function validateCertificateChain(
  certPem: string,
  trustAnchors: TrustAnchor[],
  options: {
    checkRevocation?: boolean;
    crlClient?: CrlClient;
    ocspClient?: OcspClient;
    currentTime?: Date;
  } = {}
): Promise<ValidationResult> {
  const errors: string[] = [];
  const chain: X509Certificate[] = [];

  try {
    // Parse leaf certificate
    const leaf = new X509Certificate(certPem);
    chain.push(leaf);

    // Build chain (simplified - in production use a proper path builder)
    let current = leaf;
    let depth = 0;
    const maxDepth = 10; // Prevent infinite loops

    while (depth < maxDepth) {
      // Find issuer in trust anchors
      const issuer = trustAnchors.find(ta => ta.subject === current.issuer);

      if (issuer) {
        chain.push(issuer.cert);
        break;
      }

      // In a real implementation, you'd fetch intermediate certs from AIA extension
      // For this reference, we assume the chain is complete in the input or trust anchors
      errors.push(`No trust anchor found for issuer: ${current.issuer}`);
      break;
    }

    // Validate each certificate in chain
    for (let i = 0; i < chain.length - 1; i++) {
      const cert = chain[i];
      const issuer = chain[i + 1];

      // Verify signature
      try {
        const verified = await cert.verify(issuer.publicKey);
        if (!verified) {
          errors.push(`Signature verification failed for ${cert.subject}`);
        }
      } catch (e) {
        errors.push(`Signature verification error for ${cert.subject}: ${e}`);
      }

      // Check validity period
      const now = options.currentTime || new Date();
      if (now < cert.notBefore) {
        errors.push(`Certificate not yet valid: ${cert.subject}`);
      }
      if (now > cert.notAfter) {
        errors.push(`Certificate expired: ${cert.subject}`);
      }

      // Check key usage for CA certs (except leaf)
      if (i > 0) {
        const keyUsage = cert.extensions?.keyUsage;
        if (keyUsage && !keyUsage.keyCertSign) {
          errors.push(`CA certificate missing keyCertSign: ${cert.subject}`);
        }
        const basicConstraints = cert.extensions?.basicConstraints;
        if (basicConstraints && basicConstraints.pathLenConstraint !== undefined) {
          if (i - 1 > basicConstraints.pathLenConstraint) {
            errors.push(`Path length constraint exceeded at ${cert.subject}`);
          }
        }
      }

      // Check extended key usage for leaf
      if (i === 0) {
        const eku = cert.extensions?.extKeyUsage;
        const requiredEkus = ['1.3.6.1.5.5.7.3.2']; // Client Auth
        const pivEku = '2.16.840.1.101.3.2.1.3.13'; // PIV-I
        if (eku && !eku.some(o => requiredEkus.includes(o) || o === pivEku)) {
          errors.push(`Leaf certificate missing required EKU (Client Auth or PIV-I)`);
        }
      }
    }

    // Revocation checking (if enabled)
    if (options.checkRevocation && options.crlClient) {
      for (const cert of chain) {
        const revoked = await options.crlClient.isRevoked(cert);
        if (revoked) {
          errors.push(`Certificate revoked: ${cert.subject} (serial: ${cert.serialNumber})`);
        }
      }
    }

    return {
      valid: errors.length === 0,
      errors,
      chain,
      leaf,
    };
  } catch (e) {
    return {
      valid: false,
      errors: [`Chain validation failed: ${e}`],
      chain: [],
      leaf: new X509Certificate(certPem), // Will throw if invalid PEM
    };
  }
}

/**
 * Extract EDIPI from certificate Subject DN or Subject Alternative Name.
 */
export function extractEdipi(cert: X509Certificate): string | null {
  // Try Subject DN first: CN=LAST.FIRST.EDIPI,OU=PKI,O=DoD,C=US
  const subjectMatch = cert.subject.match(/CN=[^,]+\.(\d{10})/);
  if (subjectMatch) return subjectMatch[1];

  // Try Subject Alternative Name (otherName with Microsoft UPN or similar)
  try {
    const san = cert.extensions?.subjectAltName;
    if (san) {
      // Parse GeneralNames - simplified
      const sanStr = san.toString();
      const upnMatch = sanStr.match(/(\d{10})@/);
      if (upnMatch) return upnMatch[1];
    }
  } catch {
    // Ignore SAN parsing errors
  }

  return null;
}

/**
 * Extract FASC-N from certificate.
 */
export function extractFascn(cert: X509Certificate): string | null {
  // FASC-N in Subject DN: FASC-N=XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
  const fascnMatch = cert.subject.match(/FASC-N=([^,]+)/);
  if (fascnMatch) return fascnMatch[1];

  // Or in SAN
  try {
    const san = cert.extensions?.subjectAltName;
    if (san) {
      const sanStr = san.toString();
      const fascnMatch = sanStr.match(/FASC-N=([^,\s]+)/);
      if (fascnMatch) return fascnMatch[1];
    }
  } catch {
    // Ignore
  }

  return null;
}

/**
 * Get certificate SHA-256 thumbprint.
 */
export function getThumbprint(cert: X509Certificate): string {
  const der = cert.raw;
  const hash = createHash('sha256').update(der).digest('hex');
  return hash;
}

/**
 * Check if certificate matches PIV-I profile.
 */
export function isPivProfile(cert: X509Certificate): boolean {
  const policyOid = '2.16.840.1.101.3.2.1.3.13';
  const certPolicies = cert.extensions?.certificatePolicies;

  if (certPolicies) {
    return certPolicies.some(p => p.policyIdentifier === policyOid);
  }

  // Fallback: check EKU for PIV-I
  const eku = cert.extensions?.extKeyUsage;
  if (eku) {
    return eku.includes(policyOid);
  }

  return false;
}

/**
 * CRL Client interface for revocation checking.
 */
export interface CrlClient {
  isRevoked(cert: X509Certificate): Promise<boolean>;
  fetchCrl(url: string): Promise<Uint8Array>;
}

/**
 * OCSP Client interface for revocation checking.
 */
export interface OcspClient {
  check(cert: X509Certificate, issuer: X509Certificate): Promise<'good' | 'revoked' | 'unknown'>;
}