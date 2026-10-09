# ADR 0001: Header-Based Identity Propagation vs In-Application mTLS

**Status:** Accepted  
**Date:** 2026-10-08  
**Deciders:** Lead FDE, Security Architect, App Integration Lead  
**Technical Story:** CAC/PKI authentication integration architecture decision

---

## Context

The target application is deployed behind an Application Load Balancer (ALB) in AWS GovCloud, fronted by VDI/AppStream sessions where users authenticate with CAC/PIV smart cards. The infrastructure team has confirmed that mTLS termination and certificate validation (chain, revocation, expiry) occur at the VDI/AppStream/ALB layer.

We must decide how the application receives and trusts the authenticated user identity.

---

## Decision

**Adopt header-based identity propagation** where the ALB injects validated identity headers (`x-edipi`, `x-cert-*`) after mTLS termination, and the application:

1. **Validates header provenance** — Confirms headers originate from trusted ALB (via mTLS between ALB→App, source IP allowlist, or signed headers)
2. **Extracts EDIPI** — Primary identity key from `x-edipi` header
3. **Parses certificate metadata** — Subject DN, Issuer DN, serial, validity, thumbprint from `x-cert-*` headers
4. **Enforces session policy** — 15-minute sliding window, CSRF, secure cookies
5. **Coordinates dual auth** — CAC primary, password fallback scoped to non-CAC accounts only

**Do not implement in-application mTLS termination or certificate validation.**

---

## Alternatives Considered

### Option A: In-Application mTLS Termination
- Application terminates mTLS, validates full certificate chain, performs CRL/OCSP checking
- **Pros:** Defense-in-depth, independent of ALB configuration, full PKI control
- **Cons:** 15-day timeline, CRL/OCSP infrastructure required, network egress to DISA, duplicate validation, larger ATO boundary, more code to maintain
- **Verdict:** Rejected — timeline and operational burden unjustified when upstream validation is confirmed

### Option B: Header-Based (Selected)
- Trust validated headers from ALB after provenance verification
- **Pros:** 8-12 day timeline, no CRL/OCSP infrastructure in app, simpler ATO boundary, less PKI code surface, aligns with zero-trust header propagation patterns
- **Cons:** Depends on ALB/VDI configuration correctness, header contract stability required
- **Verdict:** Accepted — risk mitigated by header provenance validation

### Option C: Hybrid (ALB validates + App re-validates critical fields)
- ALB does full validation, App re-checks expiry and EDIPI
- **Pros:** Defense-in-depth for critical fields only
- **Cons:** Partial duplication, complexity without full independence
- **Verdict:** Consider if vendor confirms ALB validation but team wants expiry double-check

---

## Consequences

### Positive
- **Faster delivery** — 8-12 days vs 15 days
- **Smaller attack surface** — No PKI validation code in application
- **Simpler ATO** — Platform owns PKI validation controls (IA-5, SC-23); app owns session/auth controls (IA-2, SC-12)
- **Operational simplicity** — No CRL fetching, caching, OCSP logic to maintain
- **Standard pattern** — Header-based identity propagation is well-established (OIDC, SAML, mTLS→header)

### Negative
- **Trust dependency** — Application security depends on ALB/VDI correct configuration
- **Header contract coupling** — Changes to header names/format require coordinated deployment
- **Provenance verification required** — Must implement robust header trust validation (not just trust all headers)

### Neutral
- **Audit logging** — Application still logs all auth events with certificate metadata from headers
- **Revocation** — Handled upstream; application sees only valid/revoked result via header presence

---

## Implementation Requirements

### Header Provenance Validation (Mandatory)
```typescript
// Pseudo-code for trust validation
function validateHeaderProvenance(request: Request): boolean {
  // Option 1: mTLS between ALB and App (preferred)
  if (request.socket?.authorized && request.socket.getPeerCertificate()) {
    return verifyALBCert(request.socket.getPeerCertificate());
  }
  
  // Option 2: Source IP allowlist (fallback)
  const albIPs = config.trustedALBCIDRs;
  if (albIPs.some(cidr => ipInCIDR(request.ip, cidr))) {
    return true;
  }
  
  // Option 3: Signed headers (if implemented)
  if (request.headers['x-alb-signature']) {
    return verifyALBSignature(request.headers);
  }
  
  return false; // Fail closed
}
```

### Header Contract (Stable Interface)
| Header | Required | Description |
|--------|----------|-------------|
| `x-edipi` | Yes | 10-digit DoD EDIPI |
| `x-cert-subject-dn` | Yes | Full Subject DN |
| `x-cert-issuer-dn` | Yes | Issuer DN |
| `x-cert-serial` | Yes | Certificate serial (hex) |
| `x-cert-not-before` | Yes | Validity start (RFC3339) |
| `x-cert-not-after` | Yes | Expiration (RFC3339) |
| `x-cert-sha256` | Yes | Cert SHA-256 thumbprint |

---

## Validation

- **FDE03 Gate:** Vendor confirms ALB/VDI performs mTLS termination + validation (Q1)
- **FDE07 Gate:** Architecture sign-off includes header provenance validation design
- **Red Team RT-01:** Header spoofing attempts blocked by provenance validation
- **UAT:** End-to-end test with valid CAC → ALB → App flow in COSMOS staging

---

## References

- NIST SP 800-53 Rev 5: SC-23 (Session Authenticity), IA-2 (Identification & Authentication)
- DoD CAC/PIV Implementation Guide
- AWS ALB mTLS Documentation
- Zero Trust Architecture (NIST SP 800-207) — Header-based identity propagation pattern