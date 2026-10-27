# AGENTS.md — AI Coding Agent Guide for LLMFirewall

This document is the authoritative instruction manual for AI coding agents (Claude, GPT, Gemini, Cursor, Copilot, Antigravity) discovering, integrating, modifying, or testing `llmfirewall-core`.

---

## 1. Package Identity & Repository Structure

- **Distribution Name (PyPI)**: `llmfirewall-core` (`pip install llmfirewall-core`)
- **Python Module**: `llmfirewall` (`import llmfirewall`)
- **CLI Binary**: `llmfirewall`
- **Current Version**: `1.3.1`
- **Minimal Core Dependencies**: `pydantic>=2.0.0`, `pyyaml>=6.0.0` (zero external network/database dependencies).

### Directory Layout

```text
/Users/livesh/LLMFirewall/
├── src/llmfirewall/             # Core library source code
│   ├── __init__.py             # Public top-level exports (Firewall, Action, Severity, etc.)
│   ├── firewall.py             # Firewall orchestrator class
│   ├── core/                   # Domain models (ScanResult, Action, Finding, RiskScore)
│   ├── detectors/              # Threat detectors (prompt_injection, pii, secrets)
│   ├── policy/                 # Policy-as-Code engine and rule evaluation
│   ├── protection/             # Runtime protection engine (@protect, @protect_tool, SecurityBlockError)
│   ├── rag/                    # RAG document ingestion & context quarantine
│   ├── tools/                  # Agent tool security & argument validators
│   └── integrations/           # Framework adapters & clients
│       ├── asgi.py             # Pure ASGI 3.0 middleware (Zero framework dependencies)
│       ├── stream.py           # StreamingTextGuard (sliding-window stream protection)
│       ├── client.py           # LLMFirewallClient & AsyncLLMFirewallClient
│       ├── fastapi/            # FastAPI FirewallMiddleware & dependency helpers
│       ├── flask.py            # Flask FirewallExtension
│       └── django.py           # Django FirewallMiddleware
├── docs/                       # Authoritative documentation
│   ├── api.md                  # Complete public API reference
│   ├── integrations/           # Verified framework integration recipes
│   └── policy-as-code.md       # Declarative JSON/YAML policy reference
└── tests/                      # Automated test suites (772 passed tests)
    └── test_integration_recipes.py # Runnable integration reference suite
```

---

## 2. Canonical Imports & Public APIs

Do **not** invent classes (e.g. `FirewallGuard`, `PromptFilter`, `SecurityPipeline`). Use only these verified imports:

### Core Orchestration
```python
from llmfirewall import (
    Firewall,              # Master orchestrator
    Action,                # Enum: ALLOW, WARN, REDACT, BLOCK
    Severity,              # Enum: INFO, LOW, MEDIUM, HIGH, CRITICAL
    SecurityBlockError,    # Exception raised by @fw.protect and fw.protect_tool
    ScanResult,            # Result model containing decision, findings, and safe text
    DecisionTrace,         # Explainable diagnostic trace model
)
```

### Framework & Developer Integrations
```python
from llmfirewall.integrations import (
    LLMFirewallASGIMiddleware,  # Pure ASGI 3.0 middleware (Zero extra dependencies)
    StreamingTextGuard,         # Token-boundary sliding-window stream guard
    LLMFirewallClient,          # High-level synchronous client
    AsyncLLMFirewallClient,     # High-level asynchronous client
    SecurityViolation,          # Exception raised by client adapters and stream guard
)
```

### Framework-Specific Extras (Optional)
```python
# FastAPI (requires: pip install "llmfirewall-core[fastapi]")
from llmfirewall.integrations.fastapi import (
    FirewallMiddleware,
    firewall_dependency,
    scan_response,
)

# Flask (requires: pip install "llmfirewall-core[flask]")
from llmfirewall.integrations.flask import FirewallExtension

# Django (requires: pip install "llmfirewall-core[django]")
from llmfirewall.integrations.django import FirewallMiddleware
```

---

## 3. Trust Boundaries & Placement Rules

When integrating LLMFirewall into an application, you must enforce checks at the correct architectural boundaries:

```text
Untrusted User Input
        │
        ▼ [BOUNDARY 1: Input Scan]
  fw.scan(prompt, direction="input")  ──► If blocked, DROP & return 403.
        │                             ──► If redacted, pass result.processed_text!
        ▼
   LLM / Agent Call (OpenAI, Anthropic, Ollama, LangChain, etc.)
   ├── Agent Tool Call ──► [BOUNDARY 2: Tool Sandboxing]
   │                         fw.check_tool_call(tool, args) OR @fw.protect_tool
   └── Streaming Chunks ──► [BOUNDARY 3: In-Flight Stream Guard]
                             StreamingTextGuard.protect_stream()
        │
        ▼ [BOUNDARY 4: Output Scan]
  fw.scan(generation, direction="output") ──► If blocked, do NOT return to user!
        │                                 ──► If redacted, return result.processed_text!
        ▼
  Sanitized Response to User
```

1. **Prompt Boundary (Input)**: Scan user inputs *before* invoking an LLM.
2. **Output Boundary (Generation)**: Scan model completions *before* returning to the client.
3. **Streaming Boundary**: Wrap token streams with `StreamingTextGuard` to prevent split-token jailbreaks across chunk boundaries.
4. **Tool Call Boundary**: Inspect tool names and parameters *before* tool execution using `fw.check_tool_call()` or `@fw.protect_tool`.
5. **RAG Context Boundary**: Treat retrieved external documents as untrusted data using `fw.rag` and `fw.context_orchestrator`.

---

## 4. Mandatory Security Invariants & Prohibited Shortcuts

Agents must adhere strictly to the following non-negotiable rules:

1. **The Redaction Invariant**:
   When `result.action == Action.REDACT`, `result.is_allowed` is `True`. **Never forward the original input text to downstream models.** You must forward `result.processed_text` (or `result.sanitized_text`).
2. **Never Bypass Block Decisions**:
   If `result.action == Action.BLOCK` (or `result.is_blocked` is `True`), terminate the request immediately. Do not log a warning and proceed.
3. **Zero-Retention Safe Logging**:
   Never log raw prompts or user inputs in exception handlers or audit logs. Always use `result.safe_dict()`, which automatically scrubs raw text and secret substrings.
4. **Correct Exception Handling**:
   - Runtime decorators (`@fw.protect`, `fw.protect_tool`) raise `SecurityBlockError`.
   - Client adapters (`LLMFirewallClient`, `StreamingTextGuard`) raise `SecurityViolation`.
   - Both inherit from `LLMFirewallError`. Catch `SecurityBlockError` or `SecurityViolation` explicitly and return HTTP 403.
5. **Preserve Asynchronous Concurrency**:
   In async frameworks (FastAPI, Starlette, Quart, aiohttp), use `AsyncLLMFirewallClient` or `LLMFirewallASGIMiddleware` so scan CPU operations run non-blockingly via executors.

---

## 5. Developer Workflow & Reusable Scaffolding

To integrate LLMFirewall into any Python application, follow this 7-step workflow:

```bash
# Step 1: Detect host framework and identify architectural trust boundaries
llmfirewall integrate detect

# Step 2: Review recommended recipe and canonical imports
llmfirewall integrate list

# Step 3: Scaffold verified boilerplate and companion tests (safe preview by default)
llmfirewall integrate scaffold --recipe <fastapi|asgi|streaming|tools|rag>

# Step 4: Write scaffold files safely into application (refuses to overwrite existing files without --force)
llmfirewall integrate scaffold --recipe fastapi --write-app app.py --write-test test_app.py

# Step 5: Run active enforcement and configuration validation
llmfirewall integrate validate

# Step 6: Execute automated integration tests
pytest -v

# Step 7: Zero-retention audit check
# Verify that application logs use result.safe_dict() instead of raw prompts
```

### Reporting Unsupported APIs vs Inventing Classes
If an application uses a framework or component not listed in canonical imports (e.g. Tornado, Falcon, Sanic, LiteLLM wrapper):
- **DO NOT invent classes or modules** (such as `LLMFirewallTornado`, `PromptFilter`, `FirewallGuard`).
- **Explicitly report the unsupported API** to the user.
- **Fall back to verified primitives**:
  1. For any ASGI-compatible stack: use `from llmfirewall.integrations import LLMFirewallASGIMiddleware` (zero external dependencies).
  2. For in-process prompt/completion checks: use `from llmfirewall import Firewall, Action; fw = Firewall(); result = fw.scan(text)`.
  3. For function guardrails: use `from llmfirewall import Firewall, SecurityBlockError; fw = Firewall(); @fw.protect`.

---

## 6. Verification Commands

After adding or modifying an integration, verify correctness using these exact commands:

```bash
# 1. Run automated integration validation
llmfirewall integrate validate

# 2. Run recipe integration tests
pytest tests/test_integration_recipes.py -v

# 3. Run developer tooling tests
pytest tests/test_developer_tooling.py -v

# 4. Run sample application verification suites
pytest examples/sample_apps/ -v

# 5. Run full existing test suite (must remain 772+ passed)
pytest -q

# 6. Static checks
ruff check .
```

A successful import alone (`python -c "import llmfirewall"`) is **not** proof of a working security integration. You must verify:
- Benign input is allowed (`Action.ALLOW`).
- Adversarial prompt injection is blocked (`Action.BLOCK`).
- PII/Secrets are redacted and the sanitized text is consumed (`Action.REDACT`).
- Rejections return HTTP 403 or raise `SecurityBlockError` / `SecurityViolation`.

---

## 7. Authoritative Reference Links

- [Public API Reference](docs/api.md)
- [FastAPI Endpoint Recipe](docs/integrations/fastapi_endpoint.md)
- [Flask Endpoint Recipe](docs/integrations/flask_endpoint.md)
- [Pure ASGI Middleware Recipe](docs/integrations/asgi_middleware.md)
- [Streaming Text Guard Recipe](docs/integrations/streaming_guard.md)
- [Agent Tool Calling Recipe](docs/integrations/agent_tool_calling.md)
- [RAG Ingestion Guard Recipe](docs/integrations/rag_context_guard.md)
- [System Architecture](docs/architecture.md)
- [Security Model & Threat Boundaries](docs/security-model.md)

