# Developer Integrations 2.0

LLMFirewall Core v1.1.0 delivers **Developer Integrations 2.0**, offering native, zero-dependency ASGI middleware, ergonomic synchronous and asynchronous client adapters, and boundary-aware streaming inspection.

---

## 1. Pure ASGI 3.0 Middleware (`LLMFirewallASGIMiddleware`)

The `LLMFirewallASGIMiddleware` is a pure ASGI 3.0 compliant component with **zero external framework dependencies**. It operates directly on ASGI `scope`, `receive`, and `send` primitives, making it immediately compatible with **FastAPI, Starlette, Quart, Litestar, and custom ASGI servers**.

### Key Capabilities
- **Inbound Prompt Inspection**: Automatically inspects JSON and text request bodies before downstream app invocation.
- **Fail-Closed Blocking**: If a security policy is violated, immediately emits HTTP 403 Forbidden with standard JSON payload without triggering downstream LLMs or databases.
- **Streaming Output Inspection**: Intercepts `http.response.body` streams chunk-by-chunk using a rolling window to detect adversarial split payloads across chunk boundaries.
- **WebSocket Protection**: Secures duplex WebSocket connections, automatically closing violating sessions with standard WebSocket policy violation code `1008`.
- **Trace & Context Propagation**: Extracts `x-request-id`, `x-trace-id`, `x-user-id`, and `x-session-id` from incoming request headers and propagates security metadata (`x-llmfirewall-action`, `x-llmfirewall-risk-score`) into outgoing headers.
- **Path Exclusions**: Bypass endpoints like `/health`, `/metrics`, or static docs.

### FastAPI / Starlette Example

```python
from fastapi import FastAPI
from llmfirewall.integrations import LLMFirewallASGIMiddleware

app = FastAPI(title="Secured LLM Gateway")

# Attach pure ASGI middleware
app.add_middleware(
    LLMFirewallASGIMiddleware,
    exclude_paths={"/health", "/metrics", "/docs"},
    inspect_request=True,
    inspect_response=True,
    fail_closed=True,
)

@app.post("/v1/chat/completions")
async def chat(data: dict):
    # If this route is reached, prompt was already inspected and allowed!
    return {"reply": f"Response to: {data.get('prompt')}"}
```

---

## 2. High-Level Developer Clients (`LLMFirewallClient` & `AsyncLLMFirewallClient`)

Clean, Pythonic client wrappers for securing applications, pipelines, and agents.

### Synchronous Client (`LLMFirewallClient`)

```python
from llmfirewall.integrations import LLMFirewallClient, SecurityViolation

client = LLMFirewallClient()

# 1. Direct prompt & output validation
scan_res = client.scan_prompt("Summarize the quarterly revenue report.")
assert scan_res.action.value == "allow"

# 2. Protecting a function call
def call_gemini(prompt: str) -> str:
    return "Analysis complete."

safe_output = client.protect_call(call_gemini, prompt="Summarize this doc")

# 3. Multi-turn conversation sessions
with client.session(session_id="user-session-123") as session:
    res1 = session.scan_prompt("Hello, help me configure my server.")
    res2 = session.scan_prompt("Turn 2 follow up prompt.")
    print(f"Session turn count: {session.turn_count}")
```

### Asynchronous Client (`AsyncLLMFirewallClient`)

```python
import asyncio
from llmfirewall.integrations import AsyncLLMFirewallClient

async def main():
    client = AsyncLLMFirewallClient()

    # Async prompt scan (runs in non-blocking thread executor)
    res = await client.scan_prompt("Async prompt to inspect")
    print(f"Action: {res.action.value}")

    # Async multi-turn session
    async with client.session(session_id="async-session-888") as session:
        r1 = await session.scan_prompt("Analyze system security logs.")
        print(f"Turn {session.turn_count} status: {r1.action.value}")

asyncio.run(main())
```

---

## 3. Streaming Chunk Protection (`StreamingTextGuard`)

When LLMs stream tokens using Server-Sent Events (SSE) or WebSockets, malicious actors may split tokens across chunks to evade simple substring filters. `StreamingTextGuard` uses a **sliding window with configurable overlap** (default 128 chars) to inspect across chunk boundaries.

```python
from llmfirewall.integrations import StreamingTextGuard, SecurityViolation

guard = StreamingTextGuard(window_size=256, overlap_size=64)

def llm_token_generator():
    yield "The secret token is "
    yield "sk-proj-1234567890abcdefghijklmnopqrstuvwxyz1234567890abcdef"
    yield " please do not share."

try:
    for safe_chunk in guard.protect_stream(llm_token_generator()):
        print(safe_chunk, end="", flush=True)
except SecurityViolation as exc:
    print(f"\n[STREAM TERMINATED BY SECURITY POLICY]: {exc}")
```
