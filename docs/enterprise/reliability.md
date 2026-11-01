# Reliability Engineering & Resilience Patterns

## 1. Overview

Enterprise LLM applications operate in distributed environments where external dependencies (Redis caches, Vault clusters, OpenTelemetry collectors, upstream LLM APIs) can experience transient latency spikes, network partitions, or outages.

`llmfirewall.enterprise.resilience` provides reliability primitives to keep applications stable:
- **`CircuitBreaker`**: Prevents cascading failures when downstream infrastructure degrades.
- **`retry_with_backoff`**: Exponential backoff with Full Jitter to mitigate thundering herds.
- **`FailurePolicy`**: Configurable fallback semantics (`FAIL_OPEN`, `FAIL_CLOSED`, `REJECT_TEMPORARILY`).

---

## 2. Circuit Breaker State Transitions

```
               Success
        ┌──────────────────┐
        │                  │
        ▼                  │
   ┌─────────┐      Failure threshold reached      ┌────────┐
   │ CLOSED  ├────────────────────────────────────►│  OPEN  │
   └─────────┘                                     └───┬────┘
        ▲                                              │
        │ Success                                      │ Recovery timeout elapsed
        │                                              ▼
   ┌────┴──────┐                             ┌─────────────┐
   │ HALF_OPEN │◄────────────────────────────┤ Testing one │
   └───────────┘                             │ request     │
        │                                    └─────────────┘
        │ Failure
        └──────────────────────────────────────────────┘
```

### 2.1 Circuit Breaker Usage Recipe

```python
from llmfirewall.enterprise import CircuitBreaker, CircuitBreakerOpenError

breaker = CircuitBreaker(
    name="redis-cache-breaker",
    failure_threshold=5,     # Trip after 5 consecutive failures
    recovery_timeout=30.0,   # Attempt recovery after 30 seconds
    half_open_max_trials=2,  # Require 2 consecutive successes to close
)

try:
    with breaker:
        # Perform remote call
        value = remote_service_call()
except CircuitBreakerOpenError:
    # Circuit is open: fast-fail without placing load on degraded dependency
    value = local_in_memory_fallback()
```

---

## 3. Retries with Full Jitter

To prevent the **Thundering Herd Problem** where multiple pods retry failed connections simultaneously, `retry_with_backoff` applies AWS-recommended Full Jitter:

$$\text{sleep} = \text{random}(0,\, \min(\text{max\_backoff},\, \text{base\_backoff} \times 2^{\text{attempt}}))$$

### 3.1 Retry Decorator Recipe

```python
from llmfirewall.enterprise import retry_with_backoff

@retry_with_backoff(
    max_retries=3,
    base_backoff=0.2,
    max_backoff=2.0,
    retryable_exceptions=(ConnectionError, TimeoutError),
    idempotent=True,  # Safety guard: verifies function is safe to re-execute
)
def fetch_tenant_policy(vault_client, tenant_id: str):
    return vault_client.get_policy(tenant_id)
```

---

## 4. Failure Policies in Enterprise Pipelines

When external security infrastructure fails, the application's response depends on its risk classification:

```python
from llmfirewall.enterprise import FailurePolicy

# 1. Consumer AI / Chatbot (Availability Priority)
# Log warning, bypass failing external rate-limiter, enforce local in-memory checks
policy = FailurePolicy.FAIL_OPEN

# 2. Banking / Healthcare / Defense (Security Priority)
# Terminate request immediately with SecurityBlockError
policy = FailurePolicy.FAIL_CLOSED

# 3. Asynchronous Pipeline / Message Queue (Consistency Priority)
# Instruct upstream broker (Kafka/RabbitMQ) to retry later
policy = FailurePolicy.REJECT_TEMPORARILY
```
