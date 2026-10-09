# NIST 800-53 Rev 5 Control Mapping

**Elliyeen CAC/PIV PKI Authentication Reference Implementation**  
**Mapping:** Application-layer controls only (platform controls owned by ALB/VDI)

---

## Control Implementation Summary

| Control | Title | Implementation Status | Evidence Location |
|---------|-------|----------------------|-------------------|
| **AC-2** | Account Management | ✅ Implemented | `reference-impl/src/lib/auth/`, `schemas/DATABASE_SCHEMA_IMPACT.md` |
| **AC-3** | Access Enforcement | ✅ Implemented | `reference-impl/src/lib/cac/provenance.ts`, session middleware |
| **AC-12** | Session Termination | ✅ Implemented | `reference-impl/src/lib/auth/session.ts` (15-min sliding, absolute 12h) |
| **AC-17** | Remote Access | ✅ Implemented | CAC/PIV multi-factor via VDI + certificate |
| **AU-2** | Audit Events | ✅ Implemented | `reference-impl/src/lib/auth/` audit logging, `AuthAuditLog` model |
| **AU-3** | Audit Content | ✅ Implemented | Structured JSON: timestamp, EDIPI, event, success/failure, correlation ID |
| **AU-6** | Audit Review | ⚠️ Partial | CloudWatch Logs integration documented, review process org-defined |
| **AU-9** | Audit Protection | ⚠️ Partial | CloudWatch encryption, IAM policies (platform) |
| **AU-12** | Audit Generation | ✅ Implemented | All auth events logged with correlation IDs |
| **CM-7** | Least Functionality | ✅ Implemented | Minimal header surface, fail-closed defaults, no debug endpoints |
| **IA-2** | Identification & Authentication (MFA) | ✅ Implemented | CAC cert + PIN (via VDI), app enforces CAC primary |
| **IA-5** | Authenticator Management | ⚠️ Platform | Certificate lifecycle, revocation at ALB/VDI layer |
| **IA-8** | Non-Local Authentication | ✅ Implemented | Header-based identity propagation with provenance validation |
| **SC-12** | Cryptographic Key Establishment | ✅ Implemented | TLS 1.2+, approved ciphers, JWT HS256 for sessions |
| **SC-13** | Cryptographic Protection | ✅ Implemented | AES-256 for data at rest (platform), TLS for transit |
| **SC-23** | Session Authenticity | ✅ Implemented | 15-min sliding, CSRF, secure cookies, rotation, revocation |
| **SC-28** | Protection of Information at Rest | ⚠️ Platform | RDS encryption, Secrets Manager (platform) |
| **SC-39** | Process Isolation | ⚠️ Platform | Container/VPC isolation (platform) |
| **SI-7** | Software Integrity | ✅ Implemented | CodeQL SAST, dependency audit, container scan in CI |
| **SI-10** | Information Input Validation | ✅ Implemented | Zod schemas at all boundaries, header validation |

---

## Detailed Control Evidence

### AC-2: Account Management
**Implementation:** Prisma schema with `User` model extensions for CAC fields (`edipi`, `cacEnabled`, `authMethod`). Account creation via auto-link on first CAC login or admin provisioning. Deactivation via `cacEnabled` flag.
**Evidence:** `schemas/DATABASE_SCHEMA_IMPACT.md`, `reference-impl/prisma/schema.prisma`

### AC-3: Access Enforcement
**Implementation:** Header provenance validation (`provenance.ts`) enforces ALB trust before processing identity. Session validation on every request (`session.ts`). Role enforcement via EDIPI lookup (not header claims).
**Evidence:** `reference-impl/src/lib/cac/provenance.ts`, `reference-impl/src/lib/auth/session.ts`

### AC-12: Session Termination
**Implementation:** 15-minute sliding window (STIG V-259700), 12-hour absolute timeout, immediate revocation on logout/cert-revocation/admin-action. CSRF protection via double-submit cookie.
**Evidence:** `reference-impl/src/lib/auth/session.ts`, `adr/0003-session-timeout.md`

### AU-2/AU-3: Audit Events & Content
**Implementation:** `AuthAuditLog` model captures: timestamp, userId, EDIPI, ipAddress, userAgent, eventType, success, failureReason, sessionId, certThumbprint, metadata (JSON). All auth decisions logged.
**Event Types:** `CAC_LOGIN_SUCCESS`, `CAC_LOGIN_FAILED`, `CAC_LOGOUT`, `CAC_SESSION_EXPIRED`, `CAC_SESSION_REVOKED`, `PASSWORD_LOGIN_SUCCESS`, `PASSWORD_LOGIN_FAILED`, `PASSWORD_FALLBACK_ATTEMPT`, `PASSWORD_FALLBACK_DENIED`, `EDIPI_MISMATCH`, `CERT_EXPIRED`, `CERT_REVOKED`, `CRL_CHECK_FAILED`, `CRL_UNAVAILABLE`, `HEADER_SPOOF_ATTEMPT`, `ACCOUNT_LINK_CREATED`, `ACCOUNT_LINK_FAILED`, `ROLE_MISMATCH`
**Evidence:** `schemas/DATABASE_SCHEMA_IMPACT.md`, `reference-impl/src/lib/auth/`

### CM-7: Least Functionality
**Implementation:** No debug endpoints in production. Header contract strictly defined (7 required headers). Fail-closed defaults: invalid provenance → reject, missing CRL → fail closed after max staleness, unknown EDIPI → reject. No wildcard CORS.
**Evidence:** `reference-impl/src/lib/cac/headers.ts`, `reference-impl/src/lib/cac/provenance.ts`, `reference-impl/src/lib/certs/crl-client.ts`

### IA-2: MFA
**Implementation:** CAC provides "something you have" (cert) + "something you know" (PIN) at VDI. Application enforces CAC as primary for `cacEnabled` users. Password fallback scoped to `cacEnabled=false` only.
**Evidence:** `reference-impl/src/lib/auth/session.ts`, `adr/0004-dual-auth-scoping.md`

### IA-8: Non-Local Authentication
**Implementation:** Header-based identity propagation with provenance validation (mTLS ALB→App, source IP allowlist, signed headers). Zero-trust: never trust headers without provenance proof.
**Evidence:** `reference-impl/src/lib/cac/provenance.ts`, `adr/0001-header-based-auth.md`

### SC-12: Cryptographic Key Establishment
**Implementation:** TLS 1.2+ enforced at ALB. Session cookies signed with HS256 (jose library). CSRF tokens 256-bit random. Certificate validation uses approved algorithms (RSA-2048, SHA-256).
**Evidence:** `reference-impl/src/lib/auth/session.ts`, `reference-impl/src/lib/certs/chain-validator.ts`

### SC-23: Session Authenticity
**Implementation:** 
- Sliding 15-min timeout with server-side enforcement
- Secure cookies: `HttpOnly`, `Secure`, `SameSite=Strict`
- CSRF double-submit cookie pattern
- Session token rotation on each request
- Immediate revocation capability
- Concurrent session limit (configurable, default 3)
**Evidence:** `reference-impl/src/lib/auth/session.ts`, `adr/0003-session-timeout.md`

### SI-7: Software Integrity
**Implementation:** CI/CD pipeline with:
- CodeQL SAST (security-and-quality queries)
- TruffleHog secret scanning (full history)
- npm audit (high+ severity)
- Trivy container scanning (critical/high)
- License compliance check
**Evidence:** `.github/workflows/security.yml`

### SI-10: Input Validation
**Implementation:** Zod schemas for all external inputs:
- `CacHeadersSchema` — validates all 7 required headers + formats
- Session cookie validation via JWT verification
- CSRF token timing-safe comparison
- CRL parsing with bounds checking
**Evidence:** `reference-impl/src/lib/cac/headers.ts`, `reference-impl/src/lib/auth/session.ts`, `reference-impl/src/lib/cac/provenance.ts`

---

## Platform Controls (Not Implemented in Application)

| Control | Owner | Notes |
|---------|-------|-------|
| **IA-5** (full) | ALB/VDI | Certificate lifecycle, CRL/OCSP, trust anchor management |
| **SC-13** (at rest) | AWS | RDS encryption, EBS encryption, Secrets Manager |
| **SC-28** | AWS | Encryption at rest |
| **SC-39** | AWS | VPC, Security Groups, container isolation |
| **AU-6, AU-9** | AWS/Org | CloudWatch Logs encryption, log review process |

---

## STIG Mapping (DoD)

| STIG ID | Title | Application Coverage |
|---------|-------|---------------------|
| **V-259700** | Session Timeout | ✅ AC-12 / SC-23 — 15-min sliding implemented |
| **V-222385** | PKI Certificate Revocation | ⚠️ Platform — CRL/OCSP at ALB/VDI |
| **V-222386** | Certificate Validation | ⚠️ Platform — Chain validation at ALB/VDI |
| **V-222387** | Certificate Expiration | ✅ App — Header `x-cert-not-after` validated |
| **V-222388** | Certificate Trust | ⚠️ Platform — Trust anchors at ALB/VDI |

---

## ATO Boundary

```
┌─────────────────────────────────────────────────────────────┐
                    PLATFORM ATO BOUNDARY
  ┌─────────────────────────────────────────────────────────┐
  │  VDI/AppStream + ALB                                    │
  │  • mTLS Termination (SC-23, IA-5)                       │
  │  • Certificate Chain Validation (IA-5)                  │
  │  • CRL/OCSP Revocation Checking (IA-5, SI-7)            │
  │  • Trust Anchor Management (IA-5)                       │
  │  • Header Injection (x-edipi, x-cert-*)                 │
  └─────────────────────────────────────────────────────────┘
                              │
                              ▼ Trust Boundary (Provenance Validation)
  ┌─────────────────────────────────────────────────────────┐
  │  APPLICATION ATO BOUNDARY                                │
  │  • Header Provenance Validation (IA-8, AC-3)            │
  │  • EDIPI Extraction & Account Mapping (AC-2)            │
  │  • Session Management (AC-12, SC-23)                    │
  │  • Dual Auth Coordination (IA-2)                        │
  │  • Audit Logging (AU-2, AU-3, AU-12)                    │
  │  • Input Validation (SI-10)                             │
  │  • Least Functionality (CM-7)                           │
  └─────────────────────────────────────────────────────────┘
```

**Separation Rationale:** Platform owns PKI validation controls (IA-5, SC-23 for cert validation). Application owns session, audit, and identity propagation controls (AC-12, SC-23 for sessions, AU-2/3, IA-2, IA-8). Clean separation reduces application ATO scope.

---

## Evidence Package (Generated at CI End)

| Artifact | Control Coverage |
|----------|------------------|
| Test coverage report (lcov/HTML) | All implemented controls |
| CodeQL SARIF | SI-7, CM-7 |
| TruffleHog results | SI-7, CM-7 |
| npm audit (CycloneDX SBOM) | SI-7 |
| Trivy container scan | SI-7, SC-28 |
| ADRs (0001-0005) | Architecture decisions for all controls |
| Threat model (STRIDE) | AC-3, IA-8, SC-23 |
| Test results (JUnit XML) | All functional controls |