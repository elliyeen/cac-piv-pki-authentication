# Contributing

Thank you for contributing to the Elliyeen CAC/PIV PKI Authentication Reference Implementation!

---

## Code of Conduct

This project follows the [Contributor Covenant Code of Conduct](https://www.contributor-covenant.org/version/2/1/code_of_conduct/). By participating, you agree to uphold this code.

---

## How to Contribute

### Reporting Issues

- **Security vulnerabilities:** See [SECURITY.md](SECURITY.md) — do not create public issues
- **Bugs:** Use the "Bug Report" template — include reproduction steps, expected vs actual behavior
- **Feature requests:** Use the "Feature Request" template — describe the use case and proposed solution
- **Documentation:** Typos, clarity improvements, missing topics — PRs welcome directly

### Pull Request Process

1. **Fork** the repository
2. **Create a branch:** `feat/description`, `fix/description`, `docs/description`, `test/description`
3. **Make changes** with:
   - Clear commit messages (conventional commits: `feat:`, `fix:`, `docs:`, `test:`, `refactor:`, `chore:`)
   - Tests for new functionality
   - Updated documentation if behavior changes
4. **Run locally:**
   ```bash
   pnpm install
   pnpm lint
   pnpm typecheck
   pnpm test:coverage
   pnpm test:security
   ```
5. **Push and open PR** against `main`
6. **CI must pass** — all checks (lint, typecheck, tests, security, coverage)
7. **Address review feedback** — maintainers will review within 2 business days
8. **Merge** — squash merge by maintainer after approval

---

## Development Setup

### Prerequisites

- Node.js 20+ (LTS)
- pnpm 9+

### Installation

```bash
git clone https://github.com/elliyeen/cac-piv-pki-authentication.git
cd cac-piv-pki-authentication/reference-impl
pnpm install
pnpm typecheck
pnpm test
pnpm demo
```

### Project Structure

```
reference-impl/src/lib/   certs/, cac/, auth/
reference-impl/src/testing/   synthetic PKI helper
reference-impl/src/__tests__/ security/, certs/
scripts/                  demo and fixture generation
adr/                      Architecture Decision Records
docs/                     threat model, control mapping, walkthrough
.github/workflows/        CI and CodeQL
```

---

## Coding Standards

### TypeScript

- **Strict mode** — `strict: true` in tsconfig.json
- **No `any`** — Use `unknown` and type guards
- **Explicit return types** for public functions
- **Zod schemas** for all external input validation

### Testing

- **Unit tests:** `*.test.ts` alongside source files
- **Integration tests:** `reference-impl/src/__tests__/integration/`
- **Security tests:** `reference-impl/src/__tests__/security/`
- **Coverage threshold:** 80% lines, branches, functions, statements
- **Test naming:** `describe('Component', () => { it('should behavior when condition', () => { }) })`

### Security

- **Never commit secrets** — Use environment variables
- **Validate all inputs** — Zod schemas at boundaries
- **Fail closed** — Default deny, explicit allow
- **Audit logging** — All auth decisions logged with correlation IDs

### Documentation

- **ADRs** for architectural decisions (see `adr/`)
- **JSDoc** for public APIs
- **README** updates for new features
- **Walkthrough** updates for significant changes

---

## Commit Convention

```
<type>(<scope>): <subject>

<body>

<footer>
```

**Types:**
- `feat` — New feature
- `fix` — Bug fix
- `docs` — Documentation only
- `refactor` — Code change, no behavior change
- `test` — Test addition/modification
- `chore` — Maintenance, deps, build
- `security` — Security-related change
- `arch` — Architecture decision/change

**Scopes:** `cac`, `certs`, `auth`, `session`, `audit`, `ci`, `docs`, `tests`, `deps`

**Examples:**
```
feat(cac): add header provenance validation via mTLS

Implements ALB certificate verification for header trust.
Resolves RT-01 (header spoofing) by validating ALB cert chain.

Closes #42
```

```
fix(certs): handle CRL nextUpdate in past

CRL parser now treats nextUpdate < now as stale and triggers refresh.
Previously caused false-positive revocation checks.

Fixes #15
```

---

## Review Criteria

Maintainers evaluate PRs on:

1. **Correctness** — Solves the stated problem, handles edge cases
2. **Security** — No new vulnerabilities, follows fail-closed, validates inputs
3. **Tests** — New code covered, security tests pass, no flaky tests
4. **Performance** — No regressions, reasonable complexity
5. **Documentation** — Updated for behavior changes, ADR if architectural
6. **Style** — Passes lint, typecheck, follows conventions

---

## Release Process

1. **Version bump** — `pnpm version patch|minor|major` (maintainer only)
2. **Changelog** — Auto-generated from conventional commits
3. **Tag** — `vX.Y.Z` pushed to main
4. **GitHub Release** — Notes from changelog
5. **Docker image** — Built and pushed (if configured)

---

## Questions?

Open a discussion or email engineering@elliyeen.com