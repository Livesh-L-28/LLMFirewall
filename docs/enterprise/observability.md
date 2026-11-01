# Enterprise Observability & OpenTelemetry Guide

## 1. Overview

LLMFirewall-Core provides native integration with OpenTelemetry distributed tracing and metrics without requiring hard runtime dependencies. If OpenTelemetry packages (`opentelemetry-api`, `opentelemetry-sdk`) are present, `OpenTelemetryBridge` automatically records low-cardinality telemetry and contextual trace spans. If absent, the bridge safely no-ops without exceptions.

---

## 2. Distributed Tracing & W3C Context Propagation

LLMFirewall-Core instruments every scan operation within an OpenTelemetry span:
- Span Name: `llmfirewall.scan`
- Span Kind: `INTERNAL`

### 2.1 Trace Context Extraction and Injection

To link upstream HTTP requests to downstream model calls across microservice boundaries, `OpenTelemetryBridge` provides standard W3C Trace Context propagation helpers:

```python
from llmfirewall.enterprise import OpenTelemetryBridge

bridge = OpenTelemetryBridge(service_name="llmfirewall-service")

# 1. Extract context from incoming carrier headers (e.g. from FastAPI or Envoy)
incoming_headers = {"traceparent": "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"}
context = bridge.extract_context(incoming_headers)

# 2. Execute firewall scan inside active span
with bridge.start_span("llmfirewall.input_scan", context=context) as span:
    result = fw.scan(user_input, direction="input")
    bridge.record_scan_result(span, result, tenant_id="tenant_alpha")

# 3. Inject trace context into outgoing headers destined for LLM provider or next agent hop
outgoing_headers = {}
bridge.inject_context(outgoing_headers)
```

---

## 3. Safe Metric Dimensions (Low-Cardinality)

Enterprise Prometheus systems fail if metric labels exhibit high cardinality. LLMFirewall-Core strictly enforces allowlisted, low-cardinality dimensions:

### 3.1 Standard Metrics

| Metric Name | Type | Description | Dimensions / Labels |
| :--- | :--- | :--- | :--- |
| `llmfirewall_scans_total` | Counter | Total number of scan requests evaluated. | `action`, `direction`, `status` |
| `llmfirewall_threats_detected_total` | Counter | Total threat findings identified. | `category`, `severity` |
| `llmfirewall_scan_duration_seconds` | Histogram | Latency distribution of firewall scans. | `action`, `direction` |
| `llmfirewall_rate_limit_rejections_total`| Counter | Total rate limit rejections. | `dimension` |

### 3.2 Prohibited Metric Labels
- Never include `user_id`, raw IP addresses, session IDs, or prompt hashes in Prometheus labels.
- `tenant_id` is only included if explicitly enabled in configuration and tenant counts are bounded (< 100).

---

## 4. Zero-Retention Safe Audit Logging

To comply with SOC 2, ISO 27001, and HIPAA audit requirements without violating data minimization mandates, `SafeAuditEvent` formats structured audit logs:

```python
from llmfirewall.enterprise import SafeAuditEvent

event = SafeAuditEvent.from_scan_result(
    result=scan_result,
    tenant_id="tenant_enterprise_1",
    request_id="req_981247192",
    client_ip="192.168.1.1",  # Hashed in safe_dict
)

logger.info("AUDIT_EVENT: %s", event.to_json())
```

### JSON Output Structure
```json
{
  "timestamp": 1730000000.123,
  "request_id": "req_981247192",
  "tenant_id": "tenant_enterprise_1",
  "action": "BLOCK",
  "direction": "input",
  "threat_categories": ["PROMPT_INJECTION"],
  "severities": ["HIGH"],
  "rule_ids": ["EXT_RULE_SYSTEM_OVERRIDE"],
  "execution_time_ms": 1.42,
  "has_threats": true
}
```
*Note: Neither raw prompt text nor scrubbed secret values appear in the audit event.*
