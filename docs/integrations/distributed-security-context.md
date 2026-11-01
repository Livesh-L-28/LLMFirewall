# Distributed Security Context & Trace Propagation

**LLMFirewall-Core v1.4.0** provides a framework-independent, thread-safe, and asynchronous-isolated distributed security context mechanism. It propagates cryptographic trace identifiers, tenant identity, session context, and audit metadata across distributed multi-agent systems, microservices, and LLM providers.

---

## 1. Architectural Model & Invariants

```text
Incoming Web Request (FastAPI / ASGI / Gateway)
   │  [Headers: traceparent, X-Tenant-ID, X-Session-ID]
   ▼
SecurityContext Scope (contextvars.ContextVar)
   ├── Trace ID:  00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01
   ├── Tenant ID: tenant-enterprise-01
   └── Session:   session-user-9821
        │
        ├──► OpenAI / Anthropic Wrapper (propagate trace & tenant in scan_prompt)
        ├──► LangGraph Multi-Agent Nodes (propagate in state['_security_context'])
        ├──► MCP Tool Sandboxing (validate tenant, enforce execution limits)
        └──► OpenTelemetry / SIEM Exporter (export safe attributes & scrubbed audit records)
```

### Core Invariants:
1. **Complete Async & Thread Isolation**: Context is managed via standard library `contextvars.ContextVar`. Concurrent `asyncio` tasks with different tenant identifiers never cross-contaminate state.
2. **Zero-Retention Safe Attributes**: The security context never stores, propagates, or serializes raw user prompts, passwords, or matched secrets. Only non-sensitive metadata, policy decisions, and rule IDs are retained.
3. **W3C Trace Context Conformance**: Seamlessly formats and parses standard `traceparent` headers conforming to the W3C Trace Context specification (`00-{trace_id}-{span_id}-01`).
4. **OpenTelemetry Bridge**: Automatically pulls active trace and span IDs from `opentelemetry.trace.get_current_span()` when OpenTelemetry is present.

---

## 2. SecurityContext Data Model

```python
from llmfirewall.integrations.context import SecurityContext

context = SecurityContext(
    trace_id="4bf92f3577b34da6a3ce929d0e0e4736",
    tenant_id="tenant-gold",
    session_id="session-user-42",
    agent_id="research_agent",
    policy_version="1.0",
)
```

### Key Fields:

| Field | Type | Description |
|:---|:---:|:---|
| `trace_id` | `str` | 32-hex character distributed trace identifier matching W3C Trace Context. |
| `request_id` | `str` | Unique request identifier (e.g. `req-a1b2c3d4e5f6`) for log correlation. |
| `tenant_id` | `str` | Tenant identifier for strict multi-tenant isolation. |
| `session_id` | `Optional[str]` | Conversational multi-turn session identifier. |
| `agent_id` | `Optional[str]` | Agent persona or service identifier. |
| `span_id` | `str` | 16-hex character local span identifier. |
| `parent_span_id` | `Optional[str]` | 16-hex character upstream parent span identifier. |
| `decision_metadata` | `Dict[str, Any]` | Non-sensitive firewall audit decisions (rule ID, action, risk score). |
| `correlation_metadata` | `Dict[str, Any]` | Custom application metadata (automatically scrubbed of sensitive keys). |

---

## 3. Scoping & Context Lifecycle

Use `security_context_scope` as a context manager around synchronous or asynchronous workflows. Previous context is automatically restored upon exit.

### Synchronous Usage:
```python
from llmfirewall.integrations.context import security_context_scope, get_current_context

with security_context_scope("tenant-prod", session_id="sess-100", agent_id="analyst") as ctx:
    # Any downstream scan, OpenAI call, or tool call automatically uses this context!
    active = get_current_context()
    assert active.tenant_id == "tenant-prod"
    assert active.session_id == "sess-100"

# Automatically restored to None (or previous outer context)
assert get_current_context() is None
```

### Asynchronous Concurrent Usage:
```python
import asyncio
from llmfirewall.integrations.context import security_context_scope, get_current_context

async def process_tenant_request(tenant_id: str, query: str):
    with security_context_scope(tenant_id) as ctx:
        await asyncio.sleep(0.01)  # Simulate non-blocking I/O
        # Context is strictly isolated to this async task
        assert get_current_context().tenant_id == tenant_id

# Run concurrent requests across multiple tenants:
await asyncio.gather(
    process_tenant_request("tenant-alpha", "Query 1"),
    process_tenant_request("tenant-beta", "Query 2"),
)
```

---

## 4. W3C Traceparent Header Interoperability

### Outgoing Requests (Header Injection):
```python
from llmfirewall.integrations.context import inject_w3c_traceparent

outgoing_headers = {"Content-Type": "application/json"}
outgoing_headers = inject_w3c_traceparent(outgoing_headers)
# Resulting headers:
# {
#   "Content-Type": "application/json",
#   "traceparent": "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
#   "x-llmfirewall-tenant-id": "tenant-gold"
# }
```

### Incoming Requests (Header Extraction):
```python
from llmfirewall.integrations.context import SecurityContext, extract_w3c_traceparent

traceparent_header = extract_w3c_traceparent(request.headers)
if traceparent_header:
    ctx = SecurityContext.from_w3c_traceparent(
        traceparent_header,
        tenant_id=request.headers.get("X-Tenant-ID", "default-tenant"),
    )
```

---

## 5. Integration Across LLM Frameworks

### In LangGraph Multi-Agent Workflows
`@guard_node` automatically preserves and validates the `_security_context` key inside the graph state dictionary:

```python
from llmfirewall.integrations.langgraph import guard_node

@guard_node(input_keys=["user_query"], output_keys=["agent_response"], tenant_id="tenant-gold")
def researcher_node(state: dict) -> dict:
    # State automatically contains state["_security_context"]
    # If state originates from mismatched tenant, raises SecurityViolation(HTTP 403)
    return {"agent_response": "Research complete."}
```

### In Model Context Protocol (MCP) Tool Sandboxing
`MCPToolGuard` attaches the active `SecurityContext` to tool call audit traces:

```python
from llmfirewall.integrations.mcp import MCPToolGuard

guard = MCPToolGuard()
# Automatically attaches active trace_id and tenant_id to security decision
decision = guard.intercept_tool_call("fetch_url", {"url": "https://api.internal.corp"})
```

---

## 6. Zero-Retention Safe Audit Telemetry

Generate standardized, SIEM-ready security audit events that never leak raw sensitive data:

```python
event = context.to_audit_event(
    action="block",
    rule_id="block_prompt_injection",
    integration="openai",
    risk_score=0.92,
)

print(event)
# {
#   "event_id": "evt-8f9213bc8910",
#   "timestamp": "2026-11-01T12:00:00Z",
#   "trace_id": "4bf92f3577b34da6a3ce929d0e0e4736",
#   "tenant_id": "tenant-gold",
#   "integration": "openai",
#   "action": "block",
#   "rule_id": "block_prompt_injection",
#   "risk_score": 0.92,
#   "safe_metadata": {...}
# }
```
