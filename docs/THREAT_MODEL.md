# STRIDE Threat Model

**Elliyeen CAC/PIV PKI Authentication Reference Implementation**  
**Methodology:** STRIDE per Microsoft Threat Modeling  
**Scope:** Application layer only (platform threats owned by ALB/VDI)

---

## System Decomposition

### Trust Boundaries

| Boundary | Description | Controls |
|----------|-------------|----------|
| **TB-1: Platform → Application** | ALB/VDI injects headers after mTLS validation | Header provenance validation (mTLS, IP allowlist, signed headers) |
| **TB-2: Application → Database** | Prisma ORM over TLS to RDS | IAM auth, security groups, encryption in transit |
| **TB-3: Application → Cache** | Redis/ElastiCache for sessions | Auth tokens, security groups, encryption in transit |
| **TB-4: Application → External** | None (Option B) — no CRL/OCSP egress | N/A |

### Data Flow Diagram

```
[User + CAC] 
    │
    ▼ (Physical + PIN)
[Smart Card Reader]
    │
    ▼
[VDI / AppStream Session]
    │ mTLS + Cert Chain Validation + CRL/OCSP
    ▼
[ALB (mTLS Termination)]
    │ Header Injection: x-edipi, x-cert-*
    ▼
┌─────────────────────────────────────────┐
│       TRUST BOUNDARY TB-1               │
│  Header Provenance Validation           │
│  • mTLS ALB→App cert verification       │
│  • Source IP allowlist                  │
│  • Signed headers (future)              │
└─────────────────────────────────────────┘
    │
    ▼
[Next.js Application]
    │
    ├──▶ [Header Parsing & Validation]
    ├──▶ [EDIPI Extraction + Cross-check]
    ├──▶ [Session Creation/Validation]
    ├──▶ [Audit Logging]
    │
    ▼
┌─────────────────────────────────────────┐
│       TRUST BOUNDARY TB-2/3             │
│  Prisma (TLS) → PostgreSQL RDS          │
│  Redis (TLS) → ElastiCache              │
└─────────────────────────────────────────┘
```

---

## STRIDE Analysis

### S — Spoofing

| ID | Threat | Target | Likelihood | Impact | Mitigation | Test |
|----|--------|--------|------------|--------|------------|------|
| **S-01** | Attacker forges `x-edipi` header | Header parsing | High | High | **Header provenance validation** — mTLS cert verification, IP allowlist | RT-01 |
| **S-02** | Attacker replays valid headers | Session creation | Medium | High | Short session TTL (15min), TLS between ALB→App, request fingerprinting | RT-01 |
| **S-03** | Attacker spoofs ALB certificate | mTLS validation | Low | Critical | Certificate pinning (trusted ALB cert fingerprints), rotation process | RT-01 |
| **S-04** | User claims another's EDIPI via password reset | Account linking | Medium | High | EDIPI immutable once bound, admin review for changes | RT-02 |
| **S-05** | Session fixation — attacker sets session ID | Session management | Low | High | New session token on auth, secure HttpOnly cookies, CSRF | RT-06 |

### T — Tampering

| ID | Threat | Target | Likelihood | Impact | Mitigation | Test |
|----|--------|--------|------------|--------|------------|------|
| **T-01** | Attacker modifies headers in transit | Header integrity | Low (TLS) | High | TLS 1.2+ ALB→App, mTLS mutual auth | N/A (TLS) |
| **T-02** | Attacker tampers with session cookie | Session cookie | Medium | High | HS256 signed JWT, HttpOnly, Secure, SameSite=Strict | RT-06 |
| **T-03** | Attacker modifies CRL in cache | Revocation cache | Low | High | Cache in Redis with auth, integrity checks, signed CRLs (future) | RT-04 |
| **T-04** | Attacker modifies audit logs | Audit integrity | Low | Medium | CloudWatch Logs immutable, IAM write-only for app | N/A (platform) |
| **T-05** | SQL injection via EDIPI lookup | Database | Low | Critical | Prisma parameterized queries, Zod validation on EDIPI format | Unit tests |

### R — Repudiation

| ID | Threat | Target | Likelihood | Impact | Mitigation | Test |
|----|--------|--------|------------|--------|------------|------|
| **R-01** | User denies CAC login | Audit logs | Low | Medium | Structured audit logs with cert thumbprint, correlation ID, timestamp | RT-08 |
| **R-02** | Admin denies revoking session | Audit logs | Low | Low | All admin actions logged with actor identity | RT-08 |
| **R-03** | System fails to log auth failure | Audit completeness | Medium | Medium | **Fail-closed logging** — log before reject, structured error codes | RT-08 |
| **R-04** | Log tampering/deletion | CloudWatch | Low | High | CloudWatch retention policies, cross-account log archive | Platform |

### I — Information Disclosure

| ID | Threat | Target | Likelihood | Impact | Mitigation | Test |
|----|--------|--------|------------|--------|------------|------|
| **I-01** | EDIPI exposed in logs/URLs | Logs, browser history | Medium | Medium | **No EDIPI in URLs**, structured logs only, correlation IDs for tracing | Code review |
| **I-02** | Certificate details in error messages | Error responses | Medium | Low | Generic error messages, detailed logs server-side only | Unit tests |
| **I-03** | Session token leakage | Referer headers, logs | Low | High | `SameSite=Strict`, `HttpOnly`, no token in URLs | RT-06 |
| **I-04** | CRL cache exposes revoked serials | Cache access | Low | Low | Redis auth, network isolation, no direct access | N/A |
| **I-05** | Stack traces in production errors | Error pages | Low | Low | Next.js production mode, custom error pages | Config |

### D — Denial of Service

| ID | Threat | Target | Likelihood | Impact | Mitigation | Test |
|----|--------|--------|------------|--------|------------|------|
| **D-01** | Flood CRL fetch requests | CRL client | Medium | Medium | Cache with TTL, single-flight refresh, rate limiting | Load test |
| **D-02** | Exhaust session table | Session store | Medium | High | Concurrent session limit (default 3), TTL cleanup job | Load test |
| **D-03** | Header validation DoS | Provenance check | Low | Medium | Fast-path mTLS cert verification, cached IP allowlist | Benchmarks |
| **D-04** | Database connection exhaustion | Prisma pool | Medium | High | Connection pooling, query timeouts, read replicas | Load test |
| **D-05** | Malformed certificate parsing | Cert parser | Low | Medium | Input size limits, parsing timeouts, fail-fast | Fuzz tests |

### E — Elevation of Privilege

| ID | Threat | Target | Likelihood | Impact | Mitigation | Test |
|----|--------|--------|------------|--------|------------|------|
| **E-01** | Non-CAC user accesses CAC-only resource | Authorization | Medium | High | Role mapping via EDIPI lookup (not header), `cacEnabled` flag | RT-07 |
| **E-02** | Password fallback for CAC user | Dual auth | Medium | High | Password fallback **disabled** for `cacEnabled=true` | RT-03 |
| **E-03** | Role claim injection via headers | Role mapping | Low | High | Ignore `x-role` header, use DB lookup only | RT-07 |
| **E-04** | Session hijack → admin actions | Session + RBAC | Medium | High | Short TTL, CSRF, re-auth for sensitive ops, audit | RT-06 |
| **E-05** | Certificate validation bypass | Cert parser | Low | Critical | Fail-closed, provenance required, no fallback to unverified | RT-01, RT-04 |

---

## Attack Trees

### Attack Tree: Spoof Identity (S-01)

```
Spoof Identity via Header
├── Forge x-edipi header
│   ├── No provenance validation → BLOCKED by mTLS/IP allowlist
│   ├── Valid provenance but forged header
│   │   ├── ALB cert compromised → MITIGATED by cert rotation, monitoring
│   │   ├── ALB IP spoofed → MITIGATED by VPC/NACL, mTLS required
│   │   └── Signed header forged → MITIGATED by key rotation, HSM
│   └── Header injection at ALB → PLATFORM CONTROL
└── Replay valid headers
    ├── Capture headers from legit user → MITIGATED by TLS, short TTL
    └── Replay within 15min window → MITIGATED by request fingerprinting, concurrent limit
```

### Attack Tree: Bypass Revocation (RT-04/RT-05)

```
Accept Revoked Certificate
├── CRL cache stale
│   ├── Within 24h TTL → CACHE FRESH (revocation detected)
│   ├── 24-48h (stale-while-revalidate) → STALE CACHE USED + BACKGROUND REFRESH
│   └── Beyond 48h → FAIL CLOSED (treat as revoked)
├── CRL fetch fails
│   ├── Cache valid → USE CACHE
│   ├── Cache stale but <48h → USE STALE + RETRY
│   └── Cache >48h or missing → FAIL CLOSED
└── OCSP fallback
    ├── OCSP available → REAL-TIME CHECK
    └── OCSP unavailable → CRL DECISION APPLIES
```

### Attack Tree: Session Hijack (RT-06)

```
Hijack Session
├── Steal session cookie
│   ├── XSS → MITIGATED by CSP, HttpOnly, no inline scripts
│   ├── MITM → MITIGATED by TLS 1.2+, HSTS
│   ├── Referer leakage → MITIGATED by SameSite=Strict, no token in URL
│   └── Log leakage → MITIGATED by no tokens in logs
├── Fixate session ID
│   ├── Pre-set cookie → MITIGATED by new token on auth, secure flags
│   └── Predict token → MITIGATED by 256-bit random (crypto.randomBytes)
└── IDOR on session endpoint
    ├── Access /session/:id → MITIGATED by ownership check, session.userId === currentUser
    └── Enum session IDs → MITIGATED by 128-bit random IDs, rate limiting
```

---

## Risk Summary

| Risk Level | Count | Key Risks |
|------------|-------|-----------|
| **Critical** | 2 | S-01 (header spoofing), E-05 (cert validation bypass) |
| **High** | 6 | S-02, S-04, T-02, T-05, D-02, E-01 |
| **Medium** | 8 | S-03, T-01, R-03, I-01, I-02, D-01, D-04, E-04 |
| **Low** | 7 | T-03, T-04, R-01, R-02, R-04, I-03, I-04, D-03, E-02, E-03 |

---

## Mitigation Coverage

| Mitigation | Covers Threats | Implemented In |
|------------|----------------|----------------|
| Header provenance validation (mTLS + IP + signatures) | S-01, S-02, S-03, E-05 | `provenance.ts` |
| EDIPI immutability + admin review | S-04, E-01 | `schemas/DATABASE_SCHEMA_IMPACT.md` |
| Session security (JWT, HttpOnly, Secure, SameSite, CSRF, rotation) | T-02, S-05, I-03, E-04 | `session.ts` |
| Fail-closed CRL cache with max staleness | T-03, RT-04, RT-05 | `crl-client.ts` |
| Structured audit logging (all paths) | R-01, R-02, R-03 | `AuthAuditLog` model |
| Zod validation + Prisma parameterized queries | T-05, I-02 | `headers.ts`, Prisma |
| Concurrent session limits + TTL cleanup | D-02 | `session.ts`, cleanup job |
| Role mapping via DB lookup only | E-01, E-03 | Auth integration |
| Password fallback scoped to non-CAC | E-02 | `adr/0004-dual-auth-scoping.md` |

---

## Residual Risks (Accepted)

| Risk | Rationale | Monitoring |
|------|-----------|------------|
| ALB certificate compromise | Platform responsibility, rotation process, HSM | CloudTrail alerts on cert changes |
| CRL staleness up to 48h | Operational requirement, fail-closed after | Cache metrics, alert on refresh failures |
| Insider threat (admin) | Least privilege, audit logging, separation of duties | Admin action audit, SIEM correlation |
| Zero-day in @peculiar/x509 | Dependency scanning, pinned versions, SAST | Weekly npm audit, CodeQL |

---

## Validation

| Threat | Test Coverage |
|--------|---------------|
| S-01, S-02, S-03 | `red-team.test.ts` RT-01 scenarios |
| S-04 | `red-team.test.ts` RT-02 scenarios |
| S-05, T-02, E-04 | `red-team.test.ts` RT-06 scenarios |
| T-03, RT-04, RT-05 | `crl-client.test.ts` stale/expired cache |
| T-05 | Unit tests for EDIPI format validation |
| R-03 | `red-team.test.ts` RT-08 logging tests |
| I-01, I-02 | Code review, error handling tests |
| D-01, D-02, D-04 | Load tests (separate) |
| E-01, E-02, E-03 | `red-team.test.ts` RT-03, RT-07 scenarios |
| E-05 | `provenance.test.ts` + `red-team.test.ts` RT-01 |

---

## Threat Model Maintenance

- **Review frequency:** Every sprint (2 weeks) for new features
- **Major change trigger:** Architecture changes, new trust boundaries, new data flows
- **Tooling:** Mermaid diagrams in `diagrams/`, threat model as code in `security/threat-model.ts` (future)
- **Integration:** CI gate — threat model updated for any `arch` or `security` scoped commits