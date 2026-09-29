# LLMFirewall Production Deployment & Hardening Guide

This document describes the recommended reference architecture and best practices for deploying LLMFirewall in high-throughput, security-critical production environments.

---

## 1. Production Architecture Overview

LLMFirewall operates at the **Application Layer** (Layer 7), situated between user-facing endpoints and AI model integrations:

```text
                  Client Request
                        │
                        ▼
            ┌───────────────────────┐
            │ API Gateway / Ingress │ (TLS termination, DDoS, Rate Limiting)
            └───────────┬───────────┘
                        │
                        ▼
            ┌───────────────────────┐
            │ Authentication & IAM  │ (JWT/OAuth validation, RBAC, Tenant ID)
            └───────────┬───────────┘
                        │
                        ▼
            ┌───────────────────────┐
            │  FastAPI Application  │
            │  (FirewallMiddleware) │
            └───────────┬───────────┘
                        │
                        ▼
            ┌───────────────────────┐
            │      LLMFirewall      │
            │   (Input Inspection)  │ ──► [BLOCK] (403 Forbidden)
            └───────────┬───────────┘
                        │ (ALLOW / REDACT)
                        ▼
            ┌───────────────────────┐
            │   LLM / RAG / Agent   │
            └───────────┬───────────┘
                        │
                        ▼
            ┌───────────────────────┐
            │      LLMFirewall      │
            │  (Output Inspection)  │ ──► [BLOCK] (500 Error / Fallback message)
            └───────────┬───────────┘
                        │ (Safe Response)
                        ▼
                 Client Response
```

---

## 2. Security Boundaries & Responsibility Matrix

| Responsibility | Handled By | Details |
|:---|:---|:---|
| **TLS & Transport Encryption** | Reverse Proxy / Ingress | Encrypts traffic in transit; terminates SSL/TLS. |
| **Authentication & Identity** | Auth Gateway / OAuth | Validates user identity and JWT claims before reaching firewall. |
| **Rate Limiting & Anti-DDoS** | WAF / API Gateway | Enforces IP rate-limits and protects against L4/L7 volumetric floods. |
| **Input AI Security** | **LLMFirewall (Input)** | Detects prompt injections, jailbreaks, PII leakage, and credentials. |
| **Output AI Security** | **LLMFirewall (Output)** | Prevents credential extraction, leaked system prompts, and toxic output. |
| **SIEM & Auditing** | Audit Logger / Telemetry | Emits structured JSONL and metrics snapshots with zero raw prompt leakage. |

---

## 3. Recommended Production Configuration

In production, instantiate `Firewall` as a persistent singleton to leverage cached compiled regex rules and avoid per-request object creation overhead:

```python
from llmfirewall import (
    Firewall,
    FirewallConfig,
    DetectorConfig,
    PromptInjectionConfig,
    PIIConfig,
    SecretConfig,
    RiskConfig,
    PolicyConfig,
    AuditConfig,
    TelemetryConfig,
    InMemoryTelemetrySink,
)

# 1. Production Hardened Configuration
production_config = FirewallConfig(
    detectors=DetectorConfig(
        prompt_injection=PromptInjectionConfig(enabled=True),
        pii=PIIConfig(enabled=True, store_matched_text=False), # Zero PII storage in findings
        secrets=SecretConfig(enabled=True),
        fail_fast=False, # Isolate individual detector errors
    ),
    risk=RiskConfig(
        decay_factor=0.5,
        low_threshold=0.15,
        medium_threshold=0.40,
        high_threshold=0.70,
        critical_threshold=0.90,
    ),
    policy=PolicyConfig(
        auto_redact_on_warn=True,
    ),
    audit=AuditConfig(
        enabled=True,
        logger_name="llmfirewall.audit",
        min_level="INFO",
        structured_json=True,
        redact_sensitive_data=True,
    ),
    telemetry=TelemetryConfig(
        enabled=True,
        events_enabled=True,
        metrics_enabled=True,
        max_buffered_events=5000,
    ),
)

# 2. Singleton instance
telemetry_sink = InMemoryTelemetrySink(enable_events=True, enable_metrics=True, max_buffered_events=5000)
app_firewall = Firewall(config=production_config, telemetry_sink=telemetry_sink)
```

---

## 4. FastAPI Production Integration

```python
from fastapi import FastAPI, Depends, Request
from pydantic import BaseModel
from llmfirewall.integrations.fastapi import (
    FirewallMiddleware,
    scan_response,
    get_scan_result,
)

app = FastAPI(title="Secure AI Service")

# Attach FirewallMiddleware
app.add_middleware(
    FirewallMiddleware,
    firewall=app_firewall,
    paths=["/api/v1/chat", "/api/v1/generate"],
    max_inspection_bytes=1_000_000, # 1 MB maximum payload limit
    on_payload_too_large="block",
    blocked_status_code=403,
    fail_closed=True, # Return 500 on unexpected firewall failure
    scan_output=True, # Inspect responses before returning to client
)

class ChatRequest(BaseModel):
    prompt: str

@app.post("/api/v1/chat")
async def chat_endpoint(request: ChatRequest, scan_res=Depends(get_scan_result)):
    # Prompt is verified safe; run model inference
    llm_output = f"Response to: {request.prompt}"
    return {"reply": llm_output}
```

---

## 5. Production Checklist

- [ ] **Instance Reuse**: Ensure the `Firewall()` object is created once during application startup and reused across requests.
- [ ] **Payload Size Bounds**: Enforce a strict body limit (e.g. `max_inspection_bytes=1000000`).
- [ ] **Zero Retention of Raw PII**: Ensure `store_matched_text=False` in `PIIConfig`.
- [ ] **Failure Isolation**: Verify that telemetry export failures do not break production API endpoints.
- [ ] **Log Ingestion**: Direct audit logs (`llmfirewall.audit`) to a secure log collector (Datadog, Splunk, Elastic) via structured JSONL.
