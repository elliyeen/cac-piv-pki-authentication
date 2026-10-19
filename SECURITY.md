# Security policy

This repository is an educational reference that uses only synthetic certificates and keys generated at run time. It is not a production system.

## Reporting a vulnerability

Please use GitHub's private vulnerability reporting: **Security → Report a vulnerability** on this repository. Do not open a public issue for a suspected vulnerability.

Include the affected file or function, a minimal reproduction using synthetic data, and the impact you expect.

## Please do not send

Real certificates, private keys, PINs, EDIPIs or any government or customer data. If you believe you have found real credentials in this repository, report that privately as well so it can be removed and rotated.

## Scope

In scope: the code in `reference-impl/` and the scripts in `scripts/`. Out of scope: any deployment of this code, third-party dependencies (report those upstream), and claims about compliance or authorization, which this repository does not make.

## Known limitations

Documented in the [threat model](docs/THREAT_MODEL.md), [controls](docs/CONTROLS.md) and [roadmap](ROADMAP.md): the IPv4-allowlist provenance mode is weaker by design, OCSP is not implemented, and the session store is in-memory.
