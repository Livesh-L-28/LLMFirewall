# LLMFirewall-Core Cross-Framework Compatibility Matrix

**Distribution**: `llmfirewall-core`
**Python Package**: `llmfirewall`
**Release Candidate**: `v1.4.0rc1` (Development Candidate)
**Stable Release**: `v1.3.2`

This document provides the authoritative, evidence-backed compatibility matrix across supported LLM providers, agent frameworks, protocols, and web runtimes.

---

## 1. Verified Framework Compatibility Matrix

| Integration | Supported Component | Verified Python Versions | Synchronous | Asynchronous | Streaming Guard | Test Status & Methodology | Installation Extra |
|:---|:---|:---:|:---:|:---:|:---:|:---|:---|
| **OpenAI** | `wrap_openai`, `OpenAIGuard` | 3.9, 3.10, 3.11, 3.12 | ✅ Yes | ✅ Yes (`AsyncOpenAI`) | ✅ Yes (Sliding window) | **Verified (Unit & Mock SDK)**<br/>Zero mandatory dependencies. Duck-typed mock suite tested offline. | None required (core) |
| **Anthropic** | `wrap_anthropic`, `AnthropicGuard` | 3.9, 3.10, 3.11, 3.12 | ✅ Yes | ✅ Yes (`AsyncAnthropic`) | ✅ Yes (Event deltas) | **Verified (Unit & Mock SDK)**<br/>Preserves structured content blocks (`tool_use`, `tool_result`). | None required (core) |
| **LangChain** | `FirewallRunnable`, `FirewallCallbackHandler` | 3.9, 3.10, 3.11, 3.12 | ✅ Yes | ✅ Yes (`ainvoke`, `abatch`) | ✅ Yes (`stream`, `astream`) | **Verified (LCEL Pipe & Callbacks)**<br/>Works with or without `langchain-core` installed. | `llmfirewall-core[langchain]` |
| **LangGraph** | `@guard_node`, `LangGraphStateGuard` | 3.9, 3.10, 3.11, 3.12 | ✅ Yes | ✅ Yes (`async def node`) | ✅ Yes | **Verified (Multi-Agent State Guard)**<br/>Enforces tenant isolation & state trace propagation. | None required (core) |
| **MCP** | `MCPToolGuard` | 3.9, 3.10, 3.11, 3.12 | ✅ Yes | ✅ Yes (`intercept_tool_call_async`) | N/A (JSON-RPC) | **Verified (Protocol Spec & RPC)**<br/>Pre-execution SSRF/traversal blocks, output scrubbing. | None required (core) |
| **FastAPI** | `FirewallMiddleware`, `get_scan_result` | 3.9, 3.10, 3.11, 3.12 | ✅ Yes | ✅ Yes (Native ASGI) | ✅ Yes (Streaming response) | **Verified (Live Runtime 0.141.1)**<br/>Tested with live Starlette ASGI test client. | `llmfirewall-core[fastapi]` |
| **Flask** | `FirewallExtension` | 3.9, 3.10, 3.11, 3.12 | ✅ Yes | ⚠️ WSGI sync | N/A | **Verified (Mock & Installed Tests)**<br/>Before/after request hooks; route decorators. | `llmfirewall-core[flask]` |
| **Django** | `FirewallMiddleware` | 3.9, 3.10, 3.11, 3.12 | ✅ Yes | ✅ Yes (ASGI compatible) | N/A | **Verified (Middleware Test Suite)**<br/>Django view protection and settings configuration. | `llmfirewall-core[django]` |
| **Pure ASGI** | `LLMFirewallASGIMiddleware` | 3.9, 3.10, 3.11, 3.12 | ✅ Yes | ✅ Yes (Pure ASGI 3.0) | ✅ Yes | **Verified (Zero-Dependency ASGI)**<br/>Zero extra framework dependencies required. | None required (core) |
| **OpenTelemetry**| `SecurityContext`, OTel Bridge | 3.9, 3.10, 3.11, 3.12 | ✅ Yes | ✅ Yes (ContextVars) | ✅ Yes | **Verified (OTel SDK Bridge)**<br/>Automatic W3C traceparent extraction & injection. | None required (core) |

---

## 2. Testing Methodology & Verification Scope

### In-Process vs. Live Cloud Testing
1. **Deterministic Mock Testing**:
   By default, all provider adapter test suites (`OpenAI`, `Anthropic`, `LangChain`, `LangGraph`, `MCP`) execute against duck-typed, deterministic mocks that emulate SDK interfaces without invoking external APIs or requiring API keys.
2. **Live Provider Testing**:
   Live tests require paid developer API keys (`OPENAI_API_KEY`, `ANTHROPIC_API_KEY`). They are never executed in automated CI builds to prevent test flakiness, billing costs, or credential leakage.
3. **Framework Extras Testing**:
   Web frameworks (`FastAPI`, `Flask`, `Django`) and AI orchestration libraries (`LangChain`, `LlamaIndex`) are tested in environments with their respective extras installed (`llmfirewall-core[extra]`). When an optional extra is not installed, the test suite skips the test cleanly (`pytest.skip`) without failing.

---

## 3. Scope Boundaries & Important Limitations

1. **In-Process Tool Inspection vs. OS Sandboxing**:
   `MCPToolGuard` and `@fw.protect_tool` inspect arguments for path traversal (`../../etc/shadow`), SSRF (`http://169.254.169.254/latest/meta-data`), and known dangerous shell commands. They operate **inside the Python process** and do not replace operating-system containers (e.g. Docker, gVisor, bubblewrap) for executing untrusted arbitrary native code.
2. **Streaming Guard Latency vs. Split-Token Security**:
   `StreamingTextGuard` uses a sliding overlap buffer (default: 64 to 256 characters) to prevent adversaries from splitting credentials across adjacent chunks (e.g. `AKIA` + `IOSFODNN7EXAMPLE`). The buffer introduces a minor time-to-first-token delay proportional to the window size, buffering initial tokens until the window boundary is safe to yield.
3. **SSRF & DNS Rebinding**:
   IP checks validate host strings and resolved IP addresses at request time. True mitigation against Time-of-Check to Time-of-Use (TOCTOU) DNS rebinding requires an egress proxy or network firewall.
