# LLMFirewall-Core Documentation

Welcome to the official documentation for **LLMFirewall-Core** (PyPI: `llmfirewall-core`, Python import: `llmfirewall`).

For the complete categorized sitemap, please see **[Documentation Index](index.md)**.

---

## 🗺️ Quick Navigation

### Getting Started
- **[Installation Guide](installation.md)** — Installation steps, optional dependency extras (`fastapi`, `flask`, `django`, `langchain`, `llamaindex`, `crypto`), virtual environment setup, and verification.
- **[5-Minute Quickstart](quickstart.md)** — Core scanning API, the Three Golden Invariants, runtime decorators, and redaction.
- **[Configuration & Presets](configuration.md)** — Preset configurations (`default`, `privacy`, `strict`), YAML/JSON policy-as-code, and rules.
- **[Frequently Asked Questions (FAQ)](faq.md)** — Overhead, air-gapped deployments, WAF differences, and split-token protection.

### Framework & Model Integrations
- **[OpenAI Integration Recipe](integrations/openai.md)** — SDK client wrapping (`wrap_openai`), prompt scanning, and completion sanitization.
- **[Anthropic Integration Recipe](integrations/anthropic.md)** — Claude client wrapping (`wrap_anthropic`) and stream protection.
- **[LangChain Integration Recipe](integrations/langchain.md)** — LCEL chains and Runnable protection.
- **[LangGraph Integration Recipe](integrations/langgraph.md)** — Multi-agent state guardrails and node protection (`@guard_node`).
- **[Model Context Protocol (MCP)](integrations/mcp.md)** — Inspecting and sanitizing tool calls in MCP clients (`MCPToolGuard`).
- **[FastAPI Integration Recipe](integrations/fastapi.md)** — Web API middleware (`FirewallMiddleware`) and dependency injection.
- **[Flask Integration Recipe](integrations/flask.md)** — Flask application extension (`FirewallExtension`).
- **[Django Integration Recipe](integrations/django.md)** — Django middleware and view protection.
- **[Pure ASGI 3.0 Middleware](integrations/asgi_middleware.md)** — Zero-dependency ASGI middleware.
- **[Streaming Text Guard](integrations/streaming_guard.md)** — Token-boundary sliding-window stream guard.
- **[Agent Tool Calling](integrations/agent_tool_calling.md)** — Tool parameter sandboxing and OS command protection.
- **[RAG Ingestion Guard](integrations/rag_context_guard.md)** — External document scanning and context quarantine.
- **[Distributed Security Context & Tracing](integrations/distributed-security-context.md)** — W3C traceparent headers, contextvars async isolation, and tenant propagation.
- **[Cross-Framework Compatibility Matrix](integrations/compatibility-matrix.md)** — Compatibility matrix, verified versions, and test methodology.

### API & System References
- **[Python API Reference](api.md)** — Comprehensive public API specification.
- **[CLI Reference](cli.md)** — Complete guide to `llmfirewall` CLI subcommands.
- **[System Architecture](architecture.md)** — Sub-millisecond pipeline architecture and security boundaries.
- **[Security Model](security-model.md)** — Threat models, trust boundaries, and data policies.
- **[Policy-as-Code](policy-as-code.md)** — Custom YAML/JSON security policies.

### Operations & Diagnostics
- **[Troubleshooting Guide](troubleshooting.md)** — Resolving common configuration and integration errors.
- **[Known Limitations](limitations.md)** — Architectural scope, heuristic boundaries, and Holdout v4 metrics.
- **[Observability](observability.md)** — Zero-retention safe logging (`safe_dict()`) and metrics.
- **[Benchmark Results](benchmarks.md)** — Latency and detection performance measurements.
