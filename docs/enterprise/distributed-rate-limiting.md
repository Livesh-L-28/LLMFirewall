# Distributed Rate Limiting & Abuse Prevention

## 1. Overview

LLMFirewall-Core includes a high-throughput, distributed rate-limiting subsystem designed for multi-tenant LLM APIs. It defends against:
- High-frequency brute-force jailbreak enumeration.
- Denial of Wallet (DoW) attacks consuming LLM token budgets.
- Distributed denial-of-service against prompt inspection pipelines.

---

## 2. Architecture & Algorithms

The rate limiting engine provides three interchangeable implementations:

### 2.1 `InMemoryRateLimiter`
- Standard in-process sliding window token bucket.
- Thread-safe via standard Python mutex locking (`threading.Lock`).
- Memory-bounded: Stale timestamps older than window size are purged on evaluation.
- Zero dependencies: Works out of the box with zero external infrastructure.

### 2.2 `RedisRateLimiter`
- Distributed sliding window evaluation backed by Redis sorted sets (`ZSET`).
- Uses atomic Lua scripting to prevent distributed race conditions:
  ```lua
  local key = KEYS[1]
  local now = tonumber(ARGV[1])
  local window = tonumber(ARGV[2])
  local limit = tonumber(ARGV[3])
  local clearBefore = now - window
  redis.call('ZREMRANGEBYSCORE', key, 0, clearBefore)
  local currentRequests = redis.call('ZCARD', key)
  if currentRequests < limit then
    redis.call('ZADD', key, now, now .. '-' .. math.random())
    redis.call('EXPIRE', key, math.ceil(window))
    return {1, limit - currentRequests - 1, 0}
  else
    return {0, 0, math.ceil(window)}
  end
  ```
- Evaluates `[is_allowed, remaining_quota, retry_after_seconds]` in a single network round-trip.

### 2.3 `DistributedRateLimiter`
- Coordinates tiered multi-dimensional evaluation:
  1. `TENANT` dimension: Protects organizational tenant budgets.
  2. `USER` dimension: Prevents individual abusive actors from monopolizing tenant quota.
  3. `HASHED_KEY` dimension: Enforces per-credential isolation without logging plain API keys.
- Integrates with `FailurePolicy`: Automatically falls back to local in-memory limiting if Redis experiences an outage.

---

## 3. Production Usage Recipe

```python
from llmfirewall.enterprise import (
    DistributedRateLimiter,
    RedisRateLimiter,
    InMemoryRateLimiter,
    RateLimitDimension,
    FailurePolicy,
)

# 1. Initialize distributed Redis backend (optional: requires redis package)
import redis

redis_client = redis.Redis(host="localhost", port=6379, db=0)
redis_limiter = RedisRateLimiter(client=redis_client, prefix="llmfw:rl:")

# 2. Wrap in resilient multi-dimensional coordinator
limiter = DistributedRateLimiter(
    primary_limiter=redis_limiter,
    fallback_limiter=InMemoryRateLimiter(),
    failure_policy=FailurePolicy.FAIL_OPEN,
    default_limit=100,      # 100 requests
    default_window=60.0,    # per 60 seconds
)

# 3. Check quota in request lifecycle
result = limiter.check_rate_limit(
    key="customer_acme_corp",
    dimension=RateLimitDimension.TENANT,
    limit=500,
    window=60.0,
)

if not result.allowed:
    # Reject request with standard RFC 6585 headers
    headers = {
        "Retry-After": str(result.retry_after),
        "X-RateLimit-Limit": str(result.limit),
        "X-RateLimit-Remaining": "0",
        "X-RateLimit-Reset": str(int(result.reset_time)),
    }
    # Return HTTP 429 Too Many Requests
```

---

## 4. Key Security Invariants

1. **Deterministic Hashing**: User identifiers and API keys must be hashed (SHA-256) when generating Redis keys to prevent telemetry leakage in Redis monitoring logs.
2. **Atomic Window Expiration**: Every Redis key created receives an explicit TTL matching `math.ceil(window)` to prevent memory leaks in Redis.
3. **Graceful Degradation**: When Redis is down and `FailurePolicy.FAIL_OPEN` is set, local in-memory limits apply per-pod, ensuring continuous defense against single-host floods.
