# LLMFirewall-Core Documentation Index

Welcome to the comprehensive documentation for **LLMFirewall-Core** (Distribution: `llmfirewall-core`, Import: `llmfirewall`).

---

## 🗺️ Documentation Sitemap

### 1. Getting Started
- **[Installation Guide](installation.md)**: PyPI package, pip extras (`fastapi`, `flask`, `django`, `langchain`, `llamaindex`, `crypto`), virtual environments, verification.
- **[5-Minute Quickstart](quickstart.md)**: Basic prompt scanning, the Three Golden Invariants, runtime decorators, and redaction.
- **[Configuration & Presets](configuration.md)**: Configuration schemas, built-in security presets (`default`, `privacy`, `strict`), YAML/JSON policy-as-code.
- **[Frequently Asked Questions (FAQ)](faq.md)**: Performance benchmarks, air-gapped offline use, WAF comparisons, split-token protection.

### 2. Core Architecture & Security Model
- **[System Architecture](architecture.md)**: Architecture overview, component boundaries, execution flow, zero-network design.
- **[Security Model & Trust Boundaries](security-model.md)**: Threat actors, trust boundaries, data handling policies, known constraints.
- **[Detection Engine](detection-engine.md)**: Heuristic and regex engine, prompt injection defenses, token boundary normalizers.
- **[Prompt Injection Defense](prompt-injection-defense.md)**: Homoglyphs, leetspeak, invisible characters, delimiter hijacking, and jailbreak defenses.
- **[Policy-as-Code & Linter](policy-as-code.md)**: Declarative YAML/JSON security policies, rule structure, static linter, and condition syntax.

### 3. API & CLI Reference
- **[Python API Reference](api.md)**: Public API exports, `Firewall`, `ScanResult`, `Action`, `Severity`, `wrap_openai`, `wrap_anthropic`, `guard_node`, `MCPToolGuard`, `StreamingTextGuard`.
- **[CLI Reference](cli.md)**: Complete CLI command reference (`scan`, `policy`, `benchmark`, `integrate`).
- **[Developer CLI Integration Tools](https://github.com/Livesh-L-28/LLMFirewall/blob/main/AGENTS.md)**: `llmfirewall integrate detect|list|scaffold|validate` tooling.

### 4. Framework & Ecosystem Integrations
- **[OpenAI Integration Recipe](integrations/openai.md)**: Synchronous and asynchronous OpenAI client wrapping with `wrap_openai`.
- **[Anthropic Integration Recipe](integrations/anthropic.md)**: Claude client wrapping and streaming defense with `wrap_anthropic`.
- **[LangChain Integration Recipe](integrations/langchain.md)**: Runnable chain and LCEL guardrails.
- **[LangGraph Integration Recipe](integrations/langgraph.md)**: Multi-agent graph node protection with `@guard_node` and `LangGraphStateGuard`.
- **[Model Context Protocol (MCP) Recipe](integrations/mcp.md)**: Client-side tool call inspection and result sanitization with `MCPToolGuard`.
- **[FastAPI Integration Recipe](integrations/fastapi.md)**: Web API middleware and dependency injection with `FirewallMiddleware`.
- **[Flask Integration Recipe](integrations/flask.md)**: Web application extension with `FirewallExtension`.
- **[Django Integration Recipe](integrations/django.md)**: Django middleware and view decorators.
- **[Pure ASGI 3.0 Middleware](integrations/asgi_middleware.md)**: Zero-dependency ASGI middleware for any ASGI framework.
- **[Streaming Text Guard](integrations/streaming_guard.md)**: Sliding-window token stream defense against split-token leaks.
- **[Agent Tool Calling Sandboxing](integrations/agent_tool_calling.md)**: Sandboxing agent tools, SSRF prevention, path traversal defense.
- **[RAG Ingestion Guard](integrations/rag_context_guard.md)**: Document ingestion scanning and untrusted context quarantine.
- **[Distributed Security Context & Tracing](integrations/distributed-security-context.md)**: Thread-safe, async-isolated W3C trace and tenant context propagation.
- **[Cross-Framework Compatibility Matrix](integrations/compatibility-matrix.md)**: Authoritative matrix of verified Python versions, components, sync/async support, and limitations.

### 5. Advanced Security & Defense Subsystems
- **[Context-Aware Security](context-aware-security.md)**: Multi-turn session tracking, cross-turn jailbreak detection, session drift.
- **[Cross-Step Agent Security](cross-step-agent-security.md)**: Multi-agent interaction sandboxing, capability budgets, blast radius controls.
- **[AI Security Posture Management (AI-SPM)](ai-spm.md)**: Asset exposure, security gaps, posture baselines.
- **[AI Security Knowledge Graph](security-knowledge-graph.md)**: Graph modeling of AI assets, dependencies, and attack surfaces.
- **[Incident Response & Correlation](incidents.md)**: Security event ingestion, timelines, and audit trails.

### 6. Operations, Troubleshooting & Governance
- **[Troubleshooting Guide](troubleshooting.md)**: Common errors (`ModuleNotFoundError`, unhandled `SecurityBlockError`, missing extras) and fixes.
- **[Known Limitations & Boundary Semantics](limitations.md)**: Heuristic boundaries, OS vs library sandboxing, SSRF DNS rebinding, Holdout v4 metrics.
- **[Observability & Zero-Retention Logging](observability.md)**: Zero-leakage metrics, `safe_dict()`, Prometheus telemetry, CEF SIEM exporter.
- **[Compliance & Control Mapping](compliance.md)**: NIST AI RMF, OWASP Top 10 for LLMs, and ISO/IEC 42001 alignment.

### 7. Evaluation & Benchmark Reports
- **[Benchmark Methodology & Results](benchmarks.md)**: Latency profiling, throughput, and detection benchmarks.
- **[Holdout Security Evaluation](holdout_security_evaluation.md)**: Holdout datasets v1 through v4 performance and certification.
- **[Release Assurance Checklist](release-checklist.md)**: Release verification gates and criteria.

---

## 🚀 Recommended Learning Path

1. Install LLMFirewall: [Installation Guide](installation.md)
2. Run the 5-minute walkthrough: [Quickstart Guide](quickstart.md)
3. Connect your LLM provider:
   - [OpenAI](integrations/openai.md)
   - [Anthropic](integrations/anthropic.md)
   - [LangGraph](integrations/langgraph.md)
   - [MCP](integrations/mcp.md)
   - [FastAPI](integrations/fastapi.md)
4. Configure production policies: [Configuration Guide](configuration.md)
5. Review security boundaries: [Known Limitations](limitations.md) and [FAQ](faq.md)
