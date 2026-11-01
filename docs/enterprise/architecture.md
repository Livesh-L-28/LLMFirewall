# Enterprise Architecture Guide: LLMFirewall-Core

## 1. Executive Summary

LLMFirewall-Core is architected as an in-process, zero-network-dependency security perimeter for LLM applications, autonomous agents, and RAG pipelines. In enterprise production deployments, it integrates with distributed infrastructure (Redis, HashiCorp Vault, OpenTelemetry, Kubernetes) while preserving the core invariant: **the failure of external infrastructure components must never compromise application availability unless explicitly configured as fail-closed.**

---

## 2. Distributed Architecture Diagram

```
                 ┌────────────────────────────────────────────────────────┐
                 │                Untrusted User Traffic                  │
                 └───────────────────────────┬────────────────────────────┘
                                             │
                                             ▼
                               ┌───────────────────────────┐
                               │ Kubernetes Ingress / API  │
                               │ Gateway (Kong / Envoy)    │
                               └─────────────┬─────────────┘
                                             │
                                             ▼
   ┌──────────────────────────────────────────────────────────────────────────────────┐
   │ Pod / Container Boundary: LLMFirewall Application Pod                             │
   │                                                                                  │
   │   ┌──────────────────────────────────────────────────────────────────────────┐   │
   │   │ Security Context Middleware (Context Propagation & Tenant Identification)│   │
   │   └─────────────────────────────────────┬────────────────────────────────────┘   │
   │                                         │                                        │
   │                                         ▼                                        │
   │   ┌──────────────────────────────────────────────────────────────────────────┐   │
   │   │ Distributed Rate Limiter (Token Bucket / Sliding Window)                │   │
   │   └───────────────┬──────────────────────────────────────────┬───────────────┘   │
   │                   │ (Async)                                  │ (Fallback)        │
   │                   ▼                                          ▼                   │
   │   ┌───────────────────────────────┐          ┌───────────────────────────────┐   │
   │   │ Redis Cluster (Tier-1 Quotas) │          │ InMemoryRateLimiter (Local)   │   │
   │   └───────────────────────────────┘          └───────────────────────────────┘   │
   │                                         │                                        │
   │                                         ▼                                        │
   │   ┌──────────────────────────────────────────────────────────────────────────┐   │
   │   │ LLMFirewall Core Inspection Engine                                       │   │
   │   │ ├── Prompt Injection & Jailbreak (Multi-Tier Extended Engine)             │   │
   │   │ ├── PII Masking & Transformation Engine                                  │   │
   │   │ ├── Secret Scrubbing & High-Entropy Credential Detection                 │   │
   │   │ └── Policy Engine (Cryptographically Verified Tenant Policies)           │   │
   │   └─────────────────────────────────────┬────────────────────────────────────┘   │
   │                                         │                                        │
   │                                         ▼                                        │
   │   ┌──────────────────────────────────────────────────────────────────────────┐   │
   │   │ OpenTelemetry Bridge (Low-Cardinality Safe Spans & Metric Counters)      │   │
   │   └─────────────────────────────────────┬────────────────────────────────────┘   │
   │                                         │                                        │
   │                                         ▼                                        │
   │   ┌──────────────────────────────────────────────────────────────────────────┐   │
   │   │ Resilience Engine (CircuitBreaker / Retry with Full Jitter)              │   │
   │   └─────────────────────────────────────┬────────────────────────────────────┘   │
   └─────────────────────────────────────────┼────────────────────────────────────────┘
                                             │
                                             ▼
                 ┌────────────────────────────────────────────────────────┐
                 │ Downstream Model Provider (OpenAI, Anthropic, Ollama)  │
                 └────────────────────────────────────────────────────────┘
```

---

## 3. Trust Boundaries & Isolation

### 3.1 Perimeter Ingestion Boundary
- Untrusted user input is captured at the ASGI / WSGI / HTTP edge.
- The distributed rate limiter enforces quotas by `tenant_id`, `user_id`, or API key hash before CPU-heavy inspection begins.
- Inputs blocked at this boundary return HTTP 429 (rate-limited) or HTTP 403 (security-blocked) without contacting downstream LLM providers.

### 3.2 In-Process Inspection Boundary
- Text inspection occurs entirely in-process in memory.
- No prompt, completion, or PII text is ever transmitted over network connections to external inspection SaaS or cloud security aggregators.
- All regular expression engines operate with bounded lengths to prevent ReDoS.

### 3.3 Context Propagation Boundary
- Multi-service and agentic workflows use W3C `traceparent` and `x-security-context` headers to preserve security tenant IDs, risk tiers, and baseline rules across network hops.
- Subordinate microservices inherit tenant policy constraints without re-authenticating against central storage on every internal hop.

---

## 4. Failure Domains and Production Modes

LLMFirewall-Core implements three configurable enterprise failure modes via `FailurePolicy`:

| Failure Mode | Behavior on Infrastructure Outage | Production Recommendation |
| :--- | :--- | :--- |
| `FAIL_OPEN` | If Redis, Vault, or telemetry fails, log safe audit warning and allow inspection to continue using local in-memory fallback. | Recommended for consumer-facing apps where availability takes precedence. |
| `FAIL_CLOSED` | If an external dependency fails, raise `SecurityBlockError` and reject the request immediately. | Recommended for high-assurance finance, defense, and healthcare applications. |
| `REJECT_TEMPORARILY`| If external dependency fails, raise a retryable HTTP 503 error instructing upstream load balancers to retry. | Recommended for idempotent background processing and asynchronous pipelines. |

---

## 5. Zero-Retention Logging Principles

Enterprise compliance standards (GDPR Art. 32, HIPAA § 164.312, PCI-DSS Req 3) prohibit logging plain-text prompts containing sensitive user data. LLMFirewall-Core enforces zero-retention through:
1. `result.safe_dict()`: Removes prompt text, leaving only threat categories, confidence scores, and rule IDs.
2. `SafeAuditEvent`: Extracts only allowlisted, low-cardinality metadata (`action`, `severity`, `rule_id`, `direction`, `duration_ms`).
3. OpenTelemetry spans discard `prompt` and `completion` attributes, storing only boolean detection indicators.
