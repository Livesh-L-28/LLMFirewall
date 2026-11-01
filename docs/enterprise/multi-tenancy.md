# Multi-Tenant Isolation & Partitioning

## 1. Overview

In shared SaaS and multi-tenant enterprise platforms, multiple organizational units or external customers execute LLM workloads through shared application clusters.

LLMFirewall-Core enforces strict multi-tenant isolation across four critical planes:
1. **Cache Partitioning**: Prevents prompt responses and sanitized outputs from leaking across tenant boundaries.
2. **Quota Namespacing**: Isolates rate limits so abusive traffic from one tenant cannot starve other tenants.
3. **Execution Context**: Isolates tenant identities within asynchronous task runtimes using Python `contextvars`.
4. **Policy Customization**: Permits customized scanning sensitivities per tenant while enforcing corporate baseline floors.

---

## 2. Contextvars-Based Security Context

LLMFirewall-Core uses standard library `contextvars` to ensure tenant context is bound strictly to the current asynchronous coroutine or OS thread:

```python
from llmfirewall.integrations.context import SecurityContext, security_context

# 1. Bind tenant context at API ingress
ctx = SecurityContext(
    tenant_id="customer_acme",
    user_id="user_123",
    request_id="req_456",
    roles=["enterprise_user"],
    tier="premium"
)
token = security_context.set(ctx)

try:
    # 2. All downstream firewall scans and rate checks automatically inherit context
    result = fw.scan(prompt)
finally:
    # 3. Always reset context upon request completion
    security_context.reset(token)
```

---

## 3. Cache Partitioning Invariants

When prompt caching or response caching is enabled:
- **No Global Keys**: Cache keys must never be constructed solely from the hash of the prompt.
- **Tenant-Scoped Namespacing**: Every cache key is prefixed with the SHA-256 hash of the `tenant_id`:
  $$\text{CacheKey} = \text{SHA256}(\text{tenant\_id}) \,\|\, \text{SHA256}(\text{prompt})$$
- This ensures that if Tenant A and Tenant B submit the exact same prompt, they can never hit or read each other's cached responses.

---

## 4. Multi-Tenant Rate Limiting

To avoid noisy neighbor syndrome where one tenant exhausts the entire API quota, `DistributedRateLimiter` namespaces quotas:

```python
from llmfirewall.enterprise import DistributedRateLimiter, RateLimitDimension

# Automatically prefixes Redis keys with tenant namespace:
# e.g., "llmfw:rl:tenant:customer_acme"
result = limiter.check_rate_limit(
    key="customer_acme",
    dimension=RateLimitDimension.TENANT,
    limit=1000,
    window=60.0
)
```

If `customer_acme` exceeds 1,000 req/min, only their requests are throttled with HTTP 429; other tenants on the same cluster continue running at full capacity.
