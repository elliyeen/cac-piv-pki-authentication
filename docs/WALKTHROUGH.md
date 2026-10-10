# Five-Minute Walkthrough

A talk track for explaining this project, structured as Observe, Define, Design, Build, Verify, Operate, Improve. Every statement is limited to what the repository demonstrates. Run `pnpm demo` and `pnpm test` from `reference-impl/` to follow along.

## Observe (30s): the problem

An existing web application must accept CAC/PIV smart-card sign-in. The obvious risks: trusting an identity header anyone can forge, accepting expired or revoked certificates, and sessions that survive logout.

## Define (30s): constraints and acceptance criteria

- Identity is trusted only when it provably came from the platform layer.
- Anything that cannot be confirmed fails closed.
- Each rejection reason is observable and tested.
- No real certificates or personal data anywhere in the repo.

## Design (60s): trust boundary and alternatives

ADR-0001 compares validating certificates in the application against validating at the load balancer or VDI and verifying header provenance in the application. The latter is the primary design because it keeps PKI code and the authorization boundary smaller. The in-app validator is included for environments that need it.

## Build (60s): what exists

Show `reference-impl/src/lib/`:

- `certs/chain-validator.ts`: path building by signature, validity, CA and path-length constraints, client-auth EKU, revocation.
- `certs/crl-client.ts`: signed CRL parsing, cache with bounded staleness, fail-closed default.
- `cac/provenance.ts`: mTLS and source-IP provenance, IPv4 CIDR.
- `auth/session.ts`: signed cookies, idle and absolute timeouts, CSRF, server-side revocation.

Run `pnpm demo` and walk through the six outcomes.

## Verify (90s): evidence and honesty

- `pnpm test`: unit, security and certificate suites. Certificate tests use a synthetic PKI generated in memory, including a forged certificate (right issuer name, wrong key) and a forged CRL.
- OpenSSL cross-check: `pnpm certs:generate` then `openssl verify` agrees on valid, expired and untrusted-issuer cases.
- Bugs this process found: logout did not revoke sessions, the CRL parser returned an empty list, `requireMtls` fell through to IP matching. Each has a regression test. See the PR that fixed them.
- Not covered: five red-team scenarios (account takeover, password fallback, role mapping, audit logging) are `it.todo` because they need an application layer.

## Operate (30s)

Not demonstrated here. What a real deployment needs: a shared CRL cache, alerting on CRL fetch failures, certificate and trust-anchor rotation, and log retention. These are discussion topics, not features.

## Improve (30s): next measurable steps

1. OCSP with signed-response validation.
2. A thin application layer so the `it.todo` scenarios become real tests.
3. Shared CRL cache and metrics.
4. Dependency audit and secret scanning in CI.

## Questions to expect

| Question | Answer grounded in this repo |
|---|---|
| Why not validate in the application? | ADR-0001: larger boundary and more code. The library exists for when you must. |
| What if the load balancer is compromised? | Provenance checks reduce but do not remove that risk. Signed headers are not implemented. |
| How stale can revocation data be? | Configurable; default 24h TTL and 48h maximum, then fail closed. |
| Is this production ready? | No. It is a reference with known limitations listed in the README. |
