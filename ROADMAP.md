# Roadmap

Status of this **public reference** only. Nothing here is a commitment, a schedule or a claim about any deployment.

| Area | Status | Notes |
|---|---|---|
| Certificate chain validation (synthetic PKI) | Implemented, tested | Signature, validity, CA constraints, path length, client-auth EKU |
| CRL revocation, fail-closed | Implemented, tested | Signed-CRL parsing, bounded staleness |
| Header provenance: mTLS pin | Implemented, tested | |
| Header provenance: IPv4 allowlist | Implemented, tested, **weaker mode** | A network position does not authenticate who set a header |
| Sessions: idle/absolute timeout, CSRF, revocation | Implemented, tested | In-memory store only |
| Audit event builder and sink | Planned | Not in the committed code; no audit logging exists in this repository today |
| OCSP | Planned | |
| Authenticated gateway assertion (signed identity, freshness, replay protection) | Planned | Replaces network-position provenance for non-mTLS deployments. The IPv4 allowlist mode is expected to be demoted or removed once this exists. |
| Durable session store and audit sink reference | Planned | Interfaces only today |
| Account linking, role mapping, password fallback | Planned | Five `it.todo` tests mark the gap |
| Example web UI and database schema | Planned | |

## Private engineering lab

A private downstream lab exercises a gateway, application and database end to end with synthetic credentials. Its source, configuration and results are **not published** and are **not evidence for this repository**. Lessons that apply here are reflected above (for example, that network position alone is not sufficient provenance).

## Not in scope, ever, for this repository

Real credentials or certificates, customer configuration, deployment to any government environment, and any authorization, STIG or ATO claim.
