# 5-Minute Technical Walkthrough

**Elliyeen LLC — CAC/PIV PKI Authentication Reference Implementation**  
**Audience:** Technical interview, architecture review, capability demonstration  
**Presenter:** Lead FDE / Security Architect  
**Format:** Live demo + narrative (5 minutes total)

---

## Timing Breakdown

| Segment | Duration | Content |
|---------|----------|---------|
| 1. Problem & Context | 30s | Why CAC/PIV, zero-trust, GovCloud |
| 2. Architecture & Trust Boundaries | 60s | Header-based propagation, ALB→App trust |
| 3. Certificate Validation Deep-Dive | 90s | Chain, CRL, OCSP, PIV-I profile |
| 4. Security Testing & Red Teaming | 60s | Negative tests, RT-01..RT-08 |
| 5. DevSecOps Pipeline | 30s | CI/CD with security gates |
| 6. Compliance & ATO Readiness | 30s | NIST 800-53, STIG mapping |
| **Total** | **5:00** | |

---

## Segment 1: Problem & Context (30s)

> **"The challenge: Integrate CAC/PIV smart card authentication into a Next.js application running in AWS GovCloud (COSMOS), where users authenticate via VDI/AppStream with physical CAC cards."**

**Key points:**
- DoD mandate: CAC/PIV for all privileged access
- Existing infrastructure: ALB + VDI/AppStream handles mTLS termination
- Our scope: Trust validated headers, extract EDIPI, enforce sessions, audit everything
- Constraint: 12-day delivery, ATO-compliant, red-team validated

**Visual:** Show architecture diagram (diagrams/architecture.svg) — trace path: CAC → Reader → VDI → ALB → App → DB

---

## Segment 2: Architecture & Trust Boundaries (60s)

> **"Critical architectural decision: We don't do certificate validation in the application. The ALB/VDI terminates mTLS, validates the full chain, checks CRL/OCSP, and injects trusted headers. Our application validates *header provenance* — proving the headers came from the trusted ALB — then extracts identity."**

**Trust boundary diagram:**
```
[User+CAC] → [VDI/AppStream: mTLS + CRL/OCSP] → [ALB: Header Injection] 
    │                                                          │
    │                  TRUST BOUNDARY                          │
    ▼                                                          ▼
[App: Header Provenance Validation] → [EDIPI Extract] → [Session + Audit]
```

**Header provenance validation (show code in `reference-impl/src/lib/cac/header-trust.ts`):**
- mTLS between ALB→App (preferred) — verify ALB cert
- Source IP allowlist (fallback)
- Signed headers (future)

**Why this matters:** Smaller ATO boundary (platform owns PKI controls), faster delivery, less PKI code surface.

---

## Segment 3: Certificate Validation Deep-Dive (90s)

> **"Even though we trust headers, the reference implementation includes a complete X.509 validation library for environments where in-app validation is required."**

**Show `reference-impl/src/lib/certs/`:**

1. **Chain Validation (`chain-validator.ts`):**
   - Root → Intermediate → Leaf with pathLenConstraint
   - Trust anchor store (configurable DISA roots)
   - KeyUsage, ExtendedKeyUsage, CertificatePolicies (PIV-I OID: 2.16.840.1.101.3.2.1.3.13)

2. **CRL Processing (`crl-client.ts`):**
   - RFC 5280 compliant parsing
   - 24h TTL + stale-while-revalidate (ADR-0002)
   - Background refresh at 80% TTL
   - Fail-closed with 48h max staleness

3. **OCSP Fallback (`ocsp-client.ts`):**
   - Nonce support for replay protection
   - Response validation (signature, thisUpdate/nextUpdate)
   - Caching with configurable TTL

4. **PIV-I Profile (`piv-profile.ts`):**
   - FASC-N extraction from Subject Alternative Name
   - EDIPI mapping (Subject DN: CN=LAST.FIRST.EDIPI)
   - Certificate Policy OID validation

**Demo:** Run `pnpm test:certs` — shows valid/expired/revoked/malformed test results.

**Synthetic fixtures:** `test-fixtures/certs/` — generated at build time, no real certs.

---

## Segment 4: Security Testing & Red Teaming (60s)

> **"Security testing isn't a checkbox — it's integrated into CI and mapped to adversarial scenarios."**

**Test structure (`reference-impl/src/__tests__/security/`):**

| Suite | Scenarios | Maps To |
|-------|-----------|---------|
| `negative-certs.test.ts` | Expired, not-yet-valid, revoked, self-signed, wrong EKU, pathLen exceeded | TC-03, TC-04 |
| `revocation.test.ts` | Valid CRL, stale CRL, CRL unreachable (fail-closed), OCSP failure | TC-05, RT-04, RT-05 |
| `header-spoofing.test.ts` | Missing headers, forged EDIPI, mismatched cert/header, replay | RT-01, RT-09 |
| `session-attacks.test.ts` | Fixation, hijacking, IDOR, timeout bypass, concurrent limits | RT-06, RT-07 |
| `red-team.test.ts` | RT-01 through RT-08 from delivery plan | All RT-\* |

**Run live:** `pnpm test:security` — shows all passing with coverage.

**Key insight:** Red team scenarios (RT-01..RT-08) are *first-class test cases*, not afterthoughts. Each has a corresponding unit/integration test that must pass for CI to succeed.

---

## Segment 5: DevSecOps Pipeline (30s)

> **"Every push runs through security gates before merge — no exceptions."**

**Show `.github/workflows/`:**

1. **CI (`ci.yml`):** Lint → Typecheck → Unit Tests (80% coverage gate) → Security Tests → Build
2. **Security (`security.yml`):** CodeQL SAST → TruffleHog Secret Scan → npm Audit (high+) → Trivy Container Scan → License Check
3. **Deploy Preview (`deploy-preview.yml`):** PR preview on Vercel for stakeholder review

**Security gates (all required):**
- ✅ Zero critical/high CodeQL findings
- ✅ Zero secrets detected (trufflehog scans full history)
- ✅ Zero critical CVEs in production dependencies
- ✅ 80%+ test coverage on changed files
- ✅ All security test suites pass

**Show GitHub Actions UI** — green checks on recent PR.

---

## Segment 6: Compliance & ATO Readiness (30s)

> **"Built for ATO from day one — every control mapped, evidence generated automatically."**

**Show `docs/CONTROLS.md` — NIST 800-53 Rev 5 mapping:**

| Control | Implementation Evidence |
|---------|------------------------|
| IA-2 (MFA) | CAC cert + PIN via VDI; app enforces CAC primary |
| IA-5 (Authenticator Mgmt) | Cert lifecycle, revocation checking, rotation |
| SC-23 (Session Authenticity) | 15-min sliding, CSRF, secure cookies, rotation |
| AU-2/3 (Audit) | Structured JSON logs: timestamp, EDIPI, event, success/failure, correlation ID |
| SC-12 (Crypto) | TLS 1.2+, cert-based key exchange, approved ciphers |
| CM-7 (Least Functionality) | Minimal header surface, fail-closed defaults |

**Evidence package (generated at CI end):**
- Test coverage report (lcov + HTML)
- SAST results (SARIF)
- Secret scan results
- Dependency audit (CycloneDX SBOM)
- Container scan (Trivy)
- Architecture decision records (5 ADRs)

**ATO boundary:** Platform (ALB/VDI) owns IA-5, SC-23 (PKI validation); Application owns IA-2, SC-12, AU-2/3 (session, audit, crypto use). Clean separation.

---

## Closing (10s)

> **"This reference implementation demonstrates end-to-end FDE capability: architecture, PKI engineering, security testing, DevSecOps, and compliance — all in a clean-room, publication-ready codebase. Ready to adapt to your GovCloud environment with your specific requirements."**

**Hand off:** `docs/WALKTHROUGH.md` (this doc), `adr/` (decisions), `reference-impl/` (runnable code), `.github/workflows/` (pipeline).

---

## Demo Commands Reference

```bash
# Full test suite with coverage
pnpm test:coverage

# Security-focused tests only
pnpm test:security

# Certificate validation tests
pnpm test:certs

# Generate synthetic certificates
pnpm run certs:generate

# Start dev server (Next.js)
pnpm dev

# Lint + typecheck
pnpm lint && pnpm typecheck

# Build for production
pnpm build
```

---

## Talking Points for Q&A

| Topic | Key Message |
|-------|-------------|
| **Why not mTLS in app?** | ALB/VDI already does it; duplicate validation increases ATO boundary, timeline, maintenance. Header provenance validation is zero-trust pattern. |
| **What if ALB is compromised?** | Defense-in-depth: mTLS ALB→App, source IP allowlist, signed headers. Application fails closed if provenance invalid. |
| **Revocation latency?** | 24h TTL + stale-while-revalidate. OCSP fallback for high-value. Manual cache invalidation API for emergency. |
| **Session fixation?** | New session token on auth, secure HttpOnly SameSite=Strict cookies, CSRF double-submit, concurrent limit. |
| **Scalability?** | Redis cache for session lookups, async DB writes, stateless header validation. Tested to 10k concurrent. |
| **Portability?** | Clean-room TypeScript, no AWS SDK in auth path, configurable trust anchors, standard Next.js. |