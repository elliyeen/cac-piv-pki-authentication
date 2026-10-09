# ADR 0002: CRL Caching Strategy — 24h TTL + Stale-While-Revalidate

**Status:** Accepted  
**Date:** 2026-10-08  
**Deciders:** CAC/PKI Security Lead, Security Architect

---

## Context

Certificate Revocation Lists (CRLs) from DISA PKI must be fetched and checked for certificate revocation status. The application (in Option A) or the ALB/VDI (in Option B) needs a caching strategy that balances:
- Freshness (revoked certs detected quickly)
- Availability (CRL endpoint unreachable)
- Performance (per-request fetch is unacceptable)
- Compliance (STIG/SRG requirements)

---

## Decision

**Adopt 24-hour TTL with stale-while-revalidate (background refresh at 80% TTL = 19.2 hours).**

### Cache Behavior

| Scenario | Behavior |
|----------|----------|
| Cache miss / first fetch | Synchronous fetch, block until complete (max 5s timeout) |
| Cache hit, TTL < 80% | Return cached CRL immediately |
| Cache hit, TTL ≥ 80% | Return cached CRL + trigger async background refresh |
| Cache hit, TTL expired (stale) | Return stale CRL + trigger sync refresh (fail-open if refresh fails) |
| Refresh fails (network error) | Continue serving stale CRL up to 48h max staleness |
| Refresh fails (HTTP error) | Log alert, continue serving stale CRL up to 48h |

### Configuration

```typescript
const CRL_CACHE_CONFIG = {
  ttlHours: 24,
  staleWhileRevalidatePercent: 80,  // Refresh at 19.2h
  maxStalenessHours: 48,            // Hard limit on stale data
  fetchTimeoutMs: 5000,             // Per-request timeout
  concurrentRefreshLimit: 1,        // Single refresh per CRL URL
  refreshJitterMs: 300000,          // ±5 min jitter to prevent thundering herd
};
```

---

## Alternatives Considered

| Strategy | Pros | Cons | Verdict |
|----------|------|------|---------|
| **No cache (per-request)** | Always fresh | Unacceptable latency, DISA rate limits, availability risk | ❌ |
| **Short TTL (1h)** | Fresher data | High fetch volume, thundering herd, more failures | ❌ |
| **24h TTL, no stale-while-revalidate** | Simple | Synchronous refresh at expiry = latency spikes | ❌ |
| **24h TTL + stale-while-revalidate (selected)** | Balance of freshness/perf/availability | Slightly more complex | ✅ |
| **OCSP only (no CRL)** | Real-time | OCSP responder availability, privacy, DoD requires CRL | ❌ |

---

## Consequences

### Positive
- **Predictable performance** — 99%+ requests served from cache
- **Availability** — Graceful degradation during DISA CRL outages
- **Compliance** — Meets STIG requirement for revocation checking with reasonable freshness
- **Operational** — Alerts on refresh failures, metrics on cache hit rate

### Negative
- **Revocation detection window** — Up to 24h (or 48h during outages) for revoked certs
- **Complexity** — Background refresh logic, staleness tracking, metrics

### Mitigations
- **OCSP fallback** for high-value transactions (optional future enhancement)
- **Revocation event monitoring** — Alert on CRL changes (new revocations)
- **Manual cache invalidation** — Admin API to force refresh on known revocation

---

## Validation

- **Unit tests:** Cache hit/miss, TTL expiry, background refresh, failure scenarios
- **Integration test:** Simulated DISA CRL endpoint with controlled responses
- **Load test:** 1000 req/s with cache warm — verify <5ms p99 latency
- **Chaos test:** Kill CRL endpoint — verify stale serving continues for 48h

---

## References

- RFC 5280 Section 6.3 (CRL Processing)
- RFC 7525 (TLS Best Practices) — CRL caching recommendations
- STIG V-222385 (PKI Certificate Revocation)
- NIST SP 800-53 Rev 5 SC-23 (Session Authenticity)