# Evidence

Only results that were executed are listed. Re-run them yourself; do not rely on this page.

## Executed 2026-10-19

- **Commit:** `67e81489042417355710d257e135a701167ea912` (`master`), clean checkout, Node 24, pnpm 9
- **Environment:** local macOS workstation, no network services, synthetic keys generated at run time

| Command (from `reference-impl/`) | Result |
|---|---|
| `pnpm install --frozen-lockfile --ignore-scripts` | success |
| `pnpm typecheck` | 0 errors |
| `pnpm test` | **60 passed, 5 todo** (6 test files) |
| `pnpm test:coverage` | 94.01% statements/lines, 81.09% branches, 93.33% functions |
| `pnpm demo` | 1 accepted, 5 rejected as expected (see [DEMO](DEMO.md)) |

The 5 `it.todo` tests are account identity immutability/linking, password fallback and role mapping: not implemented here.

## What this does not show

- Real CAC/PIV cards, real certificate authorities, a real load balancer, VDI or any customer environment.
- Throughput, latency or capacity. No ATO, STIG or compliance claim follows.
- Anything about the private lab (not published, not verifiable from this repository).

## Project log

| Date | Event | Link |
|---|---|---|
| 2026-10-08 | Repository initialized | commit `3c1ccb0` |
| 2026-10-10 | CI/CodeQL/Dependabot hardening | [PR #1](https://github.com/elliyeen/cac-piv-pki-authentication/pull/1) |
| 2026-10-10 | Reference implementation builds, typechecks and passes tests | [PR #2](https://github.com/elliyeen/cac-piv-pki-authentication/pull/2) |
| 2026-10-10 | README, walkthrough and setup match the code | [PR #3](https://github.com/elliyeen/cac-piv-pki-authentication/pull/3) |
| 2026-10-19 | Architecture diagrams, roadmap, evidence, demo and security pages (this change) | this pull request |

Open Dependabot pull requests (#10 to #14) were not reviewed or merged as part of this change.
