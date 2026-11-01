# Evaluation Scenario: Multi-Tenant SaaS Platform

## 1. Application Architecture

```
Tenant A Request ──► [ SecurityContext (Tenant A) ] ──► [ RateLimiter: Tenant A ] ──► [ Cached (Tenant A) ]
                                                              │
Tenant B Request ──► [ SecurityContext (Tenant B) ] ──► [ RateLimiter: Tenant B ] ──► [ Cached (Tenant B) ]
```

This scenario models B2B multi-tenant SaaS platforms where multiple corporate customers share an AI infrastructure cluster under strict quota, caching, and isolation boundaries.

---

## 2. Integration Steps

```python
from llmfirewall import Firewall
from llmfirewall.enterprise import (
    DistributedRateLimiter,
    InMemoryRateLimiter,
    RateLimitDimension,
    PolicyGovernanceManager,
)
from llmfirewall.integrations.context import SecurityContext, security_context

fw = Firewall()
limiter = DistributedRateLimiter(backend=InMemoryRateLimiter(), default_rpm=100)

# Set customized quota per tenant
limiter.set_tenant_quota("tenant_acme", rpm=500)
limiter.set_tenant_quota("tenant_beta", rpm=50)

# Bind context per request
ctx = SecurityContext(tenant_id="tenant_acme", user_id="user_1", tier="enterprise")
token = security_context.set(ctx)

try:
    # Rate check isolated to tenant
    quota_res = limiter.check(tenant_id="tenant_acme")
    assert quota_res.allowed is True

    # Inspection inherits tenant context
    scan_res = fw.scan("Summarize revenue report")
finally:
    security_context.reset(token)
```

---

## 3. Expected Security Behavior

1. **Quota Isolation**: If Tenant B exhausts their 50 rpm quota and receives HTTP 429, Tenant A continues operating uninterrupted at full capacity.
2. **Contextvars Thread-Safety**: Coroutines running concurrently never cross-pollinate tenant identifiers or risk scores.
3. **Partitioned Cache**: Cached completions are keyed with `SHA256(tenant_id) || SHA256(prompt)`, ensuring Tenant A can never retrieve Tenant B's cached responses.

---

## 4. Failure Cases & Attack Vectors

| Test Attack Payload | Expected Action | Failure Condition (Bug) |
|---|---|---|
| Tenant B floods 100 requests in 10s | Tenant B gets HTTP 429; Tenant A passes | Tenant A throttled |
| Tenant B requests prompt identical to Tenant A's cached response | Separate cache entry created | Tenant B reads Tenant A's cache |
| Parallel async requests across tenants | Strict context preservation | Context variable bleeding |

---

## 5. Evaluation Criteria

- **Noisy Neighbor Resistance**: Zero throughput degradation for compliant tenants during neighbor floods.
- **Context Integrity**: Zero cross-tenant data contamination under 100 concurrent async tasks.

---

## 6. Known Limitations

- **Distributed Sync on Local Fallback**: When Redis is down and in-memory fallback is active, quotas are enforced locally per container instance rather than globally.
