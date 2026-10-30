# Unified Security Event Correlation & Incident Timelines (Phase 4)

This document specifies the architecture, data models, causal ordering algorithms, privacy guarantees, and SIEM/SOC exporter specifications for **LLMFirewall Unified Security Event Correlation** (`llmfirewall-core` v1.2.0).

---

## 1. Unified Event Schema (Schema Version 2.0)

The canonical event model is `UnifiedSecurityEvent`, defined in `src/llmfirewall/correlation/models.py`. It provides complete causal attribution across prompt scanning, RAG document ingestion, tool sandboxing, policy evaluation, and multi-step agent reasoning.

### 1.1 Field Definitions & Specifications

| Field Name | Type | Required | Default | Description |
| :--- | :--- | :---: | :--- | :--- |
| `schema_version` | `str` | Yes | `"2.0"` | Canonical schema version string. |
| `event_id` | `str` | Yes | `evt-<uuid>` | Globally unique event identifier. |
| `timestamp` | `datetime` | Yes | UTC Now | Timezone-aware UTC timestamp of event generation. |
| `sequence_number` | `int` | Yes | `0` | Monotonically increasing integer establishing causal order within a correlation session. |
| `event_type` | `SecurityEventType`| Yes | - | Event taxonomy classification (`scan_request`, `threat_detected`, `tool_blocked`, etc.). |
| `severity` | `EventSeverity` | Yes | `INFO` | Operational severity (`DEBUG`, `INFO`, `WARNING`, `HIGH`, `CRITICAL`). |
| `correlation_id` | `str` | Yes | - | Primary correlating identifier linking events across a request or multi-turn workflow. |
| `request_id` | `str` | Yes | - | Single-request HTTP/RPC tracing identifier. |
| `trace_id` | `Optional[str]` | No | `None` | Distributed tracing span/trace ID. |
| `workflow_id` | `Optional[str]` | No | `None` | Multi-step agent workflow identifier (Phase 3). |
| `tenant_id` | `Optional[str]` | No | `None` | Authoritative tenant identifier enforcing isolation boundaries. |
| `agent_id` | `Optional[str]` | No | `None` | Authorized agent or persona identifier. |
| `component` | `str` | Yes | `"firewall"` | Subsystem emitting event (`prompt_scanner`, `rag_orchestrator`, `tool_enforcer`, etc.). |
| `action` | `Optional[Action]`| No | `None` | Resolved firewall action (`ALLOW`, `WARN`, `REDACT`, `BLOCK`). |
| `outcome` | `str` | Yes | `"UNKNOWN"` | Outcome classification (`ALLOWED`, `BLOCKED`, `REDACTED`, `QUARANTINED`, `FAILED`). |
| `safe_explanation` | `str` | Yes | `""` | Non-sensitive, deterministic plain-English rationale (zero raw prompts or secrets). |
| `risk_score` | `Optional[float]` | No | `None` | Aggregated numerical risk score in range `[0.0, 1.0]`. |
| `risk_level` | `Optional[Severity]`| No | `None` | Max severity of findings (`INFO`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`). |
| `threat_types` | `List[str]` | Yes | `[]` | Categorized threats (`PROMPT_INJECTION`, `SECRET`, `PII`, `RAG_POISONING`, etc.). |
| `detector_name` | `Optional[str]` | No | `None` | Specific detector responsible for identification. |
| `policy_id` | `Optional[str]` | No | `None` | Matching policy or rule identifier. |
| `policy_version` | `Optional[str]` | No | `None` | Matching policy version. |
| `tool_name` | `Optional[str]` | No | `None` | Tool name if associated with agent tool calling. |
| `tool_call_id` | `Optional[str]` | No | `None` | Unique execution identifier for tool invocations. |
| `parent_event_id` | `Optional[str]` | No | `None` | Direct causal parent event ID forming an explicit DAG. |
| `related_event_ids`| `List[str]` | Yes | `[]` | Auxiliary event IDs in the same incident cluster. |
| `error_type` | `Optional[str]` | No | `None` | Safe exception class name (scrubbed of raw message). |
| `duration_ms` | `float` | Yes | `0.0` | Execution latency in milliseconds. |
| `payload_hash` | `Optional[str]` | No | `None` | SHA-256 cryptographic digest of inspected content. |
| `payload_length` | `int` | Yes | `0` | Character or byte length of inspected payload. |
| `environment` | `str` | Yes | `"production"`| Runtime environment (`production`, `staging`, `development`). |
| `metadata` | `Dict[str, Any]`| Yes | `{}` | Recursively scrubbed non-sensitive contextual dictionary. |

### 1.2 Backward Compatibility with Schema v1.0 (`SecurityEvent`)

To maintain complete backward compatibility with Phase 24 integrations, `UnifiedSecurityEvent.from_security_event()` bridges legacy events into Schema v2.0 without data loss:

```python
from llmfirewall.observability.models import SecurityEvent
from llmfirewall.correlation.models import UnifiedSecurityEvent

# Legacy v1.0 Event
v1_event = SecurityEvent(...)

# Upgraded v2.0 Event with causal correlation
v2_event = UnifiedSecurityEvent.from_security_event(
    event=v1_event,
    correlation_id="corr-session-123",
    sequence_number=1,
)
assert v2_event.schema_version == "2.0"
```

---

## 2. Causal Ordering & Incident Timelines

### 2.1 The Concurrency & Clock Skew Problem

In asynchronous architectures, streaming token evaluation, and concurrent multi-step agent tool execution:
- Wall-clock timestamps (`datetime.now(timezone.utc)`) can collide within sub-millisecond intervals.
- Clock drift or out-of-order network arrival can invert event order.
- Merging independent parallel tool executions cannot be resolved by timestamp sorting alone.

### 2.2 The Causal DAG Solution

`EventCorrelationEngine` uses a hybrid topological and sequence-based causal resolution algorithm:
1. **Explicit Parent Linking**: Each event optionally declares its `parent_event_id`, forming a Directed Acyclic Graph (DAG).
2. **Monotonic Sequencing**: Ingestion assigns a monotonic `sequence_number` to guarantee total ordering within a correlation session.
3. **Topological Sort**: When generating a timeline, `EventCorrelationEngine._causal_sort()` resolves dependencies so parent events always precede child events regardless of arrival order.

### 2.3 Edge Case Handling

- **Missing Correlation IDs**: Falls back deterministically to `workflow_id`, `request_id`, or `trace_id`.
- **Duplicate Events**: Idempotently ignored via internal `_seen_events` set; duplicate event IDs never create duplicate timeline entries.
- **Out-of-Order Arrival**: If child arrives before parent, topological DAG sorting re-establishes the true causal progression.
- **Incomplete Traces & Sequence Gaps**: If an event references an unknown `parent_event_id` or sequence numbers skip numbers (e.g., from 1 to 4), the engine flags `is_incomplete=True` and populates `missing_events` with descriptive warnings.
- **Concurrent Ingestion**: Protected by reentrant threading locks (`threading.RLock`), supporting multi-threaded concurrent ingestion safely.
- **Expired State Pruning**: In-memory sessions automatically expire after `session_ttl_seconds` (default: 3600s), and the cache is capped at `max_active_sessions` (default: 1000) using Least-Recently-Used (LRU) eviction.

---

## 3. Privacy, Sanitization & Storage Safety

### 3.1 Deep Recursive Sanitization

Masking only the top-level `original_text` field is insufficient. Secrets, tokens, and credentials can hide in nested metadata dictionaries, trace step details, exception messages, and matched snippets.

The privacy sanitizer (`src/llmfirewall/correlation/sanitizer.py`) enforces:
1. **Automated Secret Matching**:
   - OpenAI API Keys (`sk-`, `sk-proj-`)
   - GitHub Personal Access Tokens (`ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_`)
   - AWS Access Key IDs (`AKIA[0-9A-Z]{16}`) and Secret Access Keys
   - Private Key blocks (`-----BEGIN ... PRIVATE KEY-----`)
   - Bearer tokens (`Bearer ey...`)
   - Database connection strings (`postgres://user:pass@host...`)
2. **Recursive Traversal**:
   - `sanitize_value()` traverses dictionaries, lists, tuples, sets, and custom objects to guarantee nested values are cleansed.
3. **Model-Level Field Validation**:
   - `UnifiedSecurityEvent` automatically runs `sanitize_string` on `safe_explanation` and `sanitize_metadata` on `metadata` during Pydantic initialization. It is structurally impossible to construct an event with raw secrets in these fields.

### 3.2 Multi-Tenant Isolation

- Every correlation session is bound to an immutable `tenant_id` upon its first event.
- Ingesting an event with a conflicting `tenant_id` into an existing session immediately raises `CrossTenantViolationError`.
- Batch correlation queries checking events across different tenant IDs raise `CrossTenantViolationError`.
- Tenant IDs are strictly segregated in memory and during exporter generation.

### 3.3 Fail-Safe Telemetry Invariant

Telemetry and event correlation operate under a **Fail-Safe** contract:
- If event storage or exporter generation fails, LLMFirewall catches the exception, logs diagnostic details, and allows core security scanning and blocking enforcement to proceed unhindered.
- Telemetry failures **never** cause security gating to fail open or fail unhandled.

---

## 4. SIEM / SOC Exporter Compatibility

LLMFirewall Core provides five native, zero-dependency timeline export adapters in `src/llmfirewall/correlation/exporters.py`:

### 4.1 ArcSight Common Event Format (CEF)

Multi-event output formatted according to ArcSight CEF standards:

```text
CEF:0|LLMFirewall|LLMFirewallCore|2.0|tool_blocked|Incident Correlation: tool_blocked|7|act=block dvc=production cs1=tool_enforcer cs1Label=DetectorName cs2=default-strict cs2Label=PolicyID cfp1=0.920 cfp1Label=RiskScore externalId=evt-cef-test-01 rt=1793033876000 cn1=3 cn1Label=SequenceNumber cs3=corr-export-std cs3Label=CorrelationID cs4=evt-step2 cs4Label=ParentEventID cs5=wf-export-01 cs5Label=WorkflowID cs6=tenant-prod-a cs6Label=TenantID
```

### 4.2 RFC 5424 Syslog Protocol

Structured data elements for syslog integration:

```text
<83>1 2026-10-26T22:30:00.000000Z localhost llmfirewall - tool_blocked [llmfirewall@41123 eventId="evt-01" correlationId="corr-123" sequence="3" action="block" detector="tool_enforcer" riskScore="0.920"] Security event tool_blocked seq=3 outcome=BLOCKED
```

### 4.3 OpenTelemetry (OTLP) LogRecords

Native JSON-compliant LogRecord attributes with trace correlation:

```json
{
  "resourceLogs": [
    {
      "resource": {
        "attributes": [
          {"key": "service.name", "value": {"stringValue": "llmfirewall"}},
          {"key": "service.version", "value": {"stringValue": "1.2.0"}},
          {"key": "correlation.id", "value": {"stringValue": "corr-123"}}
        ]
      },
      "scopeLogs": [
        {
          "scope": {"name": "llmfirewall.correlation", "version": "2.0"},
          "logRecords": [...]
        }
      ]
    }
  ]
}
```

### 4.4 Human-Readable Markdown Incident Report

Structured diagnostic document containing metadata, diagnostic summaries, trace integrity warnings, and chronological causal logs for SecOps analysts.

### 4.5 Machine-Readable JSON

Privacy-scrubbed JSON via `timeline.safe_dict()`, ensuring compliance with zero-retention logging policies.

---

## 5. Developer Usage Example

```python
from llmfirewall import Firewall, Action

fw = Firewall()

# Scan with automatic correlation
trace = fw.trace_decision(
    text_or_request="Analyze quarterly customer churn.",
    correlation_id="session-user-402",
    tenant_id="tenant-acme",
)

# Convert trace directly to incident timeline
timeline = trace.to_timeline()
print(timeline.to_markdown())

# Export to SIEM
from llmfirewall.correlation.exporters import export_timeline_cef
cef_data = export_timeline_cef(timeline)
```
