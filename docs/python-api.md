# Python API Reference

LLMFirewall provides a unified public API from the root `llmfirewall` package and `llmfirewall.integrations`.

For the complete API documentation with all parameter types and exception details, see the [Full API Reference](api.md).

---

## 1. Primary Entrypoints

### `Firewall`
The master orchestrator connecting threat detection, risk scoring, policy enforcement, agent sandboxing, and observability.

```python
from llmfirewall import Firewall, Action, SecurityBlockError

fw = Firewall()

# Direct scan (returns ScanResult)
result = fw.scan("Hello world! My email is user@example.com")
if result.is_allowed:
    # Always consume processed_text if PII/secrets were redacted!
    print("Action:", result.action)           # Action.REDACT
    print("Safe text:", result.processed_text) # "Hello world! My email is [REDACTED_EMAIL]"
else:
    print("Blocked:", result.reason)

# Explainable decision trace
trace = fw.trace_decision("My email is user@example.com")
print(trace.explanation)

# Safe logging (omits raw text and matched credentials)
safe_log = result.safe_dict()
```

### Decorator Guardrails
Wrap agent functions and tools with runtime policy enforcement:

```python
# Guard agent functions (raises SecurityBlockError on block)
@fw.protect(agent_id="copilot")
def run_agent(prompt: str) -> str:
    return "Agent response"

# Guard agent tools
safe_query = fw.protect_tool(db_query, tool_name="sql_query")
```

---

## 2. Decision Semantics

| Action | `is_allowed` | `is_blocked` | Downstream Text Action |
|--------|:------------:|:------------:|------------------------|
| `Action.ALLOW` | `True` | `False` | Forward original or `processed_text` |
| `Action.WARN` | `True` | `False` | Log telemetry warning; forward `processed_text` |
| `Action.REDACT` | `True` | `False` | **CRITICAL: Forward `result.processed_text`**, not original input |
| `Action.BLOCK` | `False` | `True` | Terminate request immediately; return error |

---

## 3. Web Framework & Streaming Integrations

```python
# Pure ASGI 3.0 Middleware (Zero third-party dependencies)
from llmfirewall.integrations import LLMFirewallASGIMiddleware
app = LLMFirewallASGIMiddleware(base_asgi_app)

# Boundary-aware streaming chunk guard
from llmfirewall.integrations import StreamingTextGuard
guard = StreamingTextGuard()
for safe_chunk in guard.protect_stream(token_stream):
    yield safe_chunk

# High-level client
from llmfirewall.integrations import LLMFirewallClient, AsyncLLMFirewallClient
client = LLMFirewallClient()
result = client.scan_prompt("User query")
```

---

## 4. Subsystem Properties on `Firewall`

Access specialized subsystems directly via properties:

- `fw.tool_security`: Agent tool call validation (`fw.check_tool_call()`).
- `fw.runtime`: Multi-turn stateful agent runtime sessions (`fw.create_session()`).
- `fw.rag`: RAG context orchestration and quarantine store (`fw.rag_quarantine`).
- `fw.event_store`: Observability and SIEM event store.
- `fw.cache`: High-performance scan result cache (`if enable_cache=True`).
- `fw.observe`: Operational security intelligence and analytics engine.
