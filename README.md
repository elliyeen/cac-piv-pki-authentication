# CAC/PIV PKI Authentication: Reference Implementation

[![CI](https://github.com/elliyeen/cac-piv-pki-authentication/actions/workflows/ci.yml/badge.svg)](https://github.com/elliyeen/cac-piv-pki-authentication/actions/workflows/ci.yml)
[![Security](https://github.com/elliyeen/cac-piv-pki-authentication/actions/workflows/security.yml/badge.svg)](https://github.com/elliyeen/cac-piv-pki-authentication/actions/workflows/security.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

A clean-room TypeScript library and test suite for the application side of smart-card (CAC/PIV) authentication: validating X.509 certificate chains, checking revocation, trusting only headers that provably came from your load balancer, and managing sessions that can actually be revoked.

> **This is a sanitized, educational reference built from public standards.** It uses synthetic certificates generated at run time with throwaway keys. It contains no customer data, no real certificates, and no restricted information. It is not a production system, has not been through any authorization process, and makes no claim about deployment in any government environment.

## Status

| Area | State |
|---|---|
| Certificate chain validation | **Implemented and tested** (synthetic PKI). Signature, validity, CA constraints, path length, client-auth EKU. |
| CRL revocation | **Implemented and tested.** Signed-CRL parsing, cache with bounded staleness, fail-closed by default. |
| Header provenance (mTLS / source IP) | **Implemented and tested.** IPv4 only. Signed-header method is not implemented and fails closed. |
| Sessions (idle and absolute timeout, CSRF, revocation) | **Implemented and tested** against an in-memory store. |
| OCSP | **Planned.** Not implemented. |
| Web app, database, account linking, role mapping, audit logging | **Not in this repository.** Five tests for these are `it.todo`. |
| Platform deployment (ALB / VDI) | **Described in ADRs only.** |

Run `pnpm test` to see the current counts rather than trusting this table.

## Try it (about five minutes)

Prerequisites: Node.js 20+ and pnpm 9+. No database or Docker needed.

```bash
git clone https://github.com/elliyeen/cac-piv-pki-authentication.git
cd cac-piv-pki-authentication/reference-impl
pnpm install
pnpm typecheck
pnpm test        # unit, security and certificate suites
pnpm demo        # accept/reject walkthrough, fully offline
```

`pnpm demo` generates a synthetic root, an intermediate and six cards, then validates each one:

```
ACCEPT  valid card
REJECT  expired card                         - Certificate expired
REJECT  revoked card (on CRL)                - Certificate revoked
REJECT  card from untrusted issuer           - No path to a trusted anchor
REJECT  forged card (right issuer name,      - No path to a trusted anchor
        wrong key)
REJECT  no client-auth usage                 - missing required EKU
```

To write the same material to disk for inspection with other tools:

```bash
pnpm certs:generate   # writes ../test-fixtures/ (git-ignored)
openssl verify -CAfile ../test-fixtures/certs/root-ca.pem \
  -untrusted ../test-fixtures/certs/intermediate-ca.pem \
  ../test-fixtures/certs/leaf-valid.pem
```

OpenSSL agrees with the validator on the valid, expired and untrusted-issuer cases.

## Architecture

```
Client (CAC/PIV) -> VDI / ALB (terminates mTLS, validates the card) -> Application
                                                                        |
                          trusts x-edipi / x-cert-* headers ONLY if provenance checks pass
```

The primary design (ADR-0001) puts certificate validation at the platform layer and has the application verify header provenance. The in-app chain validator exists for environments where the application must validate certificates itself.

### Trust boundary and fail-closed rules

- If `requireMtls` is set, a request without a trusted ALB client certificate is rejected. It never falls through to IP matching.
- If revocation checking is requested without a CRL client, validation fails.
- If a CRL cannot be fetched and nothing usable is cached, the check errors (default) or, only when explicitly configured, passes.
- A session cookie alone is not proof of a live session. The server-side store decides.

## Layout

```
reference-impl/src/lib/certs/   chain-validator.ts, crl-client.ts
reference-impl/src/lib/cac/     headers.ts, provenance.ts
reference-impl/src/lib/auth/    session.ts
reference-impl/src/testing/     synthetic-pki.ts (test and demo PKI)
reference-impl/src/__tests__/   security/ (red-team), certs/
scripts/                        demo.ts, generate-certs.ts
adr/                            decision records
docs/                           threat model, control mapping, walkthrough
```

## Engineering decisions

| ADR | Decision |
|---|---|
| [0001](adr/0001-header-based-auth.md) | Header-based identity propagation instead of in-app mTLS |
| [0002](adr/0002-crl-caching-strategy.md) | CRL cache: 24h TTL, stale-while-revalidate, bounded staleness |
| [0003](adr/0003-session-timeout.md) | 15-minute sliding session window |

## Known limitations

- No OCSP, name constraints, policy mapping or AIA chasing.
- CRL signature verification happens only when the issuer certificate is supplied. The validator always supplies it.
- The CRL cache is in memory. A multi-instance deployment needs a shared cache.
- IPv6 source ranges are not supported.
- The security tests marked `it.todo` need an application layer this repository does not have.
- Documents under `docs/` other than the walkthrough describe design intent. Statuses in them are not verified against this code.

## Security

CodeQL runs on pushes and pull requests. There is no secret scanning, container scanning or dependency audit configured in this repository's workflows today.

## License

MIT. See [LICENSE](LICENSE).

*This repository demonstrates engineering approach for discussion. A real deployment needs customer-specific requirements, review and authorization.*
