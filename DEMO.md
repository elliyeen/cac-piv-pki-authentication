# Demo

An offline walkthrough of the certificate checks. It generates a synthetic root, an intermediate and six "cards" with throwaway keys, validates each, and prints the verdict. No network, no database, no real credentials.

```bash
cd reference-impl
pnpm install
pnpm demo
```

## Output (executed 2026-10-19 at commit `67e8148`)

```
> tsx ../scripts/demo.ts

ACCEPT  valid card                                 EDIPI 1234567890 sha256:2855f8fd21bc
REJECT  expired card                               EDIPI 2222222222 sha256:cc088e492675
          - Certificate expired: CN=DOE.JOHN.2222222222, OU=PKI, O=Synthetic Test, C=US
REJECT  revoked card (on CRL)                      EDIPI 3333333333 sha256:f98618a6fa0d
          - Certificate revoked: CN=DOE.JOHN.3333333333, OU=PKI, O=Synthetic Test, C=US (serial: 1a0003)
REJECT  card from untrusted issuer                 EDIPI 4444444444 sha256:d84ff346e00c
          - No path to a trusted anchor for issuer: CN=UNTRUSTED ROOT, O=Elsewhere, C=US
REJECT  forged card (right issuer name, wrong key) EDIPI 5555555555 sha256:605e700baf76
          - No path to a trusted anchor for issuer: CN=SYNTHETIC INTERMEDIATE CA, O=Synthetic Test, C=US
REJECT  no client-auth usage                       EDIPI 6666666666 sha256:513d72bf2f94
          - Leaf certificate missing required EKU (Client Authentication)
```

## What it shows

One card is accepted; expired, revoked (on a signed CRL), untrusted-issuer, forged (right issuer name, wrong key) and missing-client-authentication cards are each rejected for a specific reason.

## What it does not show

Real cards or PINs, a gateway or load balancer, sessions, a UI or a database. These are synthetic results, not acceptance of anything. See the [architecture](docs/architecture/README.md) for what is implemented, simulated and planned.
