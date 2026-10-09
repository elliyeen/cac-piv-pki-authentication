# ADR 0003: 15-Minute Sliding Session Window (STIG V-259700)

**Status:** Accepted  
**Date:** 2026-10-08  
**Deciders:** Lead FDE, Security Architect, App Integration Lead

---

## Context

DoD STIG V-259700 requires session timeout enforcement for authentication sessions. The application must implement session management that:
- Enforces maximum idle timeout
- Prevents session fixation
- Supports secure logout
- Provides audit trail

---

## Decision

**Implement 15-minute sliding window session timeout with server-side enforcement.**

### Session Configuration

```typescript
const SESSION_CONFIG = {
  idleTimeoutMinutes: 15,           // STIG V-259700 baseline
  slidingWindow: true,              // Reset on each authenticated request
  absoluteTimeoutHours: 12,         // Hard limit regardless of activity
  csrfProtection: true,             // Double-submit cookie pattern
  secureCookies: true,              // Secure, HttpOnly, SameSite=Strict
  cookieName: 'cac_session',        // Distinct from Better Auth session
  cookiePath: '/',
  cookieDomain: undefined,          // Host-only (no subdomain sharing)
};
```

### Session Lifecycle

| Event | Action |
|-------|--------|
| Successful CAC auth | Create `CacSession` record, issue secure cookie, set `expiresAt = now() + 15min` |
| Authenticated request | Validate session exists, not revoked, not expired; update `lastActivity = now()`, `expiresAt = now() + 15min` |
| Idle > 15min | Session expired — next request rejected, user must re-authenticate |
| Absolute timeout (12h) | Session force-expired — user must re-authenticate |
| User logout | Session record `revokedAt = now()`, cookie cleared, audit log `CAC_LOGOUT` |
| Cert revoked (async) | Background job marks affected sessions `revokedAt = now()` |
| Concurrent session limit | Max 3 concurrent CAC sessions per user (configurable) |

### Storage

- **Primary:** PostgreSQL (`CacSession` table) — authoritative, survives restarts
- **Cache:** Redis (ElastiCache) — session lookups, TTL = session expiry + 5min buffer
- **Invalidation:** Database write-through; Redis invalidated on revoke/expiry

---

## Alternatives Considered

| Approach | Pros | Cons | Verdict |
|----------|------|------|---------|
| **Sliding 15min (selected)** | STIG compliant, UX reasonable, standard | Requires DB write on each request | ✅ |
| **Fixed 15min (no sliding)** | Simpler, fewer writes | Poor UX — user logged out during active work | ❌ |
| **30min sliding** | Better UX | Exceeds STIG baseline, requires waiver | ❌ |
| **JWT stateless** | No DB writes | Cannot revoke mid-session, larger cookies, no absolute timeout | ❌ |
| **Redis-only** | Fast | Data loss on Redis restart, no audit trail | ❌ |

---

## Consequences

### Positive
- **STIG compliant** — Directly satisfies V-259700
- **Revocable** — Immediate invalidation on logout, revocation, admin action
- **Auditable** — Full session lifecycle in `CacSession` + `AuthAuditLog`
- **Secure** — CSRF protection, secure cookies, concurrent session limits

### Negative
- **DB write per request** — `lastActivity` + `expiresAt` update on each authenticated request
- **Mitigation:** Async write-behind (batch updates every 30s), Redis read-through

### Risks
- **Clock skew** — Use server time only; reject client-provided timestamps
- **Timezone** — All times UTC in database, convert only for display

---

## Validation

- **Unit tests:** Timeout calculation, sliding reset, absolute limit, revocation
- **Integration tests:** Full login → activity → idle → expiry flow
- **Load test:** 10k concurrent sessions — verify DB/Redis performance
- **Red Team RT-06:** Session fixation, hijacking, IDOR attempts
- **UAT:** 15-min idle timeout verified in COSMOS staging

---

## References

- STIG V-259700 (Session Timeout)
- NIST SP 800-53 Rev 5 AC-12 (Session Termination)
- OWASP Session Management Cheat Sheet
- Better Auth Session Management Documentation