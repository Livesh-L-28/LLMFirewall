## LLMFirewall-Core v1.4.0 — Stable Release

LLMFirewall-Core v1.4.0 is a stable release delivering expanded framework integrations (OpenAI, Anthropic, LangGraph, Model Context Protocol, pure ASGI 3.0, and LangChain), stateful conversation defense, developer integration tooling (`llmfirewall integrate`), and refined benchmark timing methodologies.

---

### 1. Major Changes & Ecosystem Integrations
- **SDK Integrations**:
  - `llmfirewall.integrations.openai`: `OpenAIGuard` and `wrap_openai` with sliding-window streaming token guard (`StreamingTextGuard`), prompt inspection, PII redaction propagation, and completion defense.
  - `llmfirewall.integrations.anthropic`: `AnthropicGuard` and `wrap_anthropic` intercepting Messages API with prompt and completion protection.
  - `llmfirewall.integrations.langgraph`: `LangGraphStateGuard` and `@guard_node` decorator for graph state scanning and redaction.
  - `llmfirewall.integrations.mcp`: `MCPToolGuard` providing Model Context Protocol JSON-RPC 2.0 tool call validation, argument inspection, and static SSRF checks.
  - `llmfirewall.integrations.asgi`: `LLMFirewallASGIMiddleware` pure ASGI 3.0 middleware with zero framework dependencies.
  - `llmfirewall.integrations.langchain`: `FirewallCallbackHandler` supporting runnable inputs, outputs, and callback interception.
- **Stateful Conversation Security**:
  - Added `MultiTurnSecurityState` and `ClientSessionContext` for multi-turn session tracking and threat accumulation.
  - Added detection for conversational pretexts asserting historical safety waivers.
- **Developer Scaffolding Tooling**:
  - `llmfirewall integrate` CLI subcommand suite (`detect`, `list`, `scaffold`, `validate`).
- **Production Hardening**:
  - Distributed rate limiting with Redis-backed algorithms and local in-memory fallback.
  - Key management and rotation engine (`KeyRotationManager`).
  - OpenTelemetry distributed tracing with W3C tracecontext propagation.
  - Reference deployment manifests (Docker, Kubernetes NetworkPolicy, PDB).

---

### 2. Benchmark Methodology Improvements
- Separated functional correctness tests from dedicated performance SLA benchmark tests in CI workflows to eliminate `sys.settrace()` profiling overhead during latency evaluation.
- Cleanly separated single-document filtering latency SLA (< 2.0 ms) from 2-document batch throughput in `security_benchmark_runner.py`.

---

### 3. Installation
Install LLMFirewall-Core from PyPI or wheels:
```bash
pip install llmfirewall-core==1.4.0
```
With optional integrations:
```bash
pip install "llmfirewall-core[fastapi,crypto]"
pip install "llmfirewall-core[all-integrations]"
```

---

### 4. Compatibility
- Python 3.9, 3.10, 3.11, and 3.12 verified across Linux, macOS (ARM64 & x86_64), and Windows.
- Minimal core dependencies strictly requiring `pydantic>=2.0.0` and `pyyaml>=6.0.0`.
- Preserves full backward compatibility with v1.3.2 core public APIs (`Firewall`, `Action`, `Severity`, `ScanResult`, `@protect`, `@protect_tool`).

---

### 5. Security Evaluation Summary
- **Curated Holdout v1–v3 Remediation**: 12/12 false negatives remediated across indirect injection, multilingual directives, and context delimiters within tested fixture sets.
- **SQL Educational Query False-Positive Remediation**: Added negative lookahead exclusions for keyword comparison queries while blocking 7/7 malicious SQL injection regression fixtures.
- **PII Structural Validation**: Structural SSN rules and Luhn credit card validation verified.

---

### 6. Known Limitations & Threat Boundaries
- **Heuristic Detection Limits**: Heuristic pattern matching and semantic rules cannot guarantee universal prevention of novel adversarial evasions. Empirical Holdout v4 evaluation reflects 60.0% recall (24 True Positives, 16 False Negatives, 40 True Negatives, 0 False Positives, representing a 40% false-negative rate on unseen adversarial evasions).
- **Tool Security Boundary**: Tool parameter validation and authorization operates at the application parameter schema and URL/path layer, not as an operating system container or kernel sandbox.
- **SSRF Inspection Boundary**: Static URL and CIDR inspection does not mitigate socket-level TOCTOU DNS rebinding without an egress forward proxy or socket IP pinning.
- **Data Retention Boundary**: Local `safe_dict()` scrubbing sanitizes audit logs and internal representations locally, but does not govern upstream cloud SaaS provider retention policies.
- **Streaming Guardrails**: Token-boundary sliding window buffers emitted chunks; chunks already transmitted to the client prior to mid-stream detection cannot be retroactively recalled.
- **Multilingual Scope**: Heuristic coverage is limited to tested rule patterns across 5 languages (English, French, German, Spanish, Russian).
- **Adoption Status**: Reflects 0 verified external evaluations and 0 verified production deployments.

---

### 7. Cryptographic Artifact Checksums (SHA-256)

#### Official Canonical Published Artifacts (PyPI & GitHub Release Downloadable Assets)
These checksums match the downloadable release assets attached to this GitHub Release and published on [PyPI](https://pypi.org/project/llmfirewall-core/1.4.0/):

```text
0c8676b602e5f882880745ccbeb30e5ed88c8d842e4aa751c97e7d05e13a93a5  llmfirewall_core-1.4.0-py3-none-any.whl (674,264 bytes)
760b8ddc94898583584525ef293e88025fe3e9203459326680bc834acd71fe18  llmfirewall_core-1.4.0.tar.gz (813,519 bytes)
```

#### Build Provenance & Internal Payload Verification
Independent forensic inspection verifies that all **262 member files** extracted from the wheel archive have **100% byte-for-byte identical contents and CRC-32 checksums** across the initial local certified build and the published PyPI distribution. The container hash divergence was strictly due to outer container metadata:
- **Wheel zip entry timestamps**: Local build used the default build timestamp (`2020-02-02`), whereas the GitHub Actions runner recorded the active build timestamp (`2026-11-01`).
- **Sdist gzip header**: A 2-byte difference in the outer container gzip timestamp header (`mtime`).

For complete transparency, the initial local Stage 6 build container checksums were:
```text
7b340cb2a369ea38bd0b66b65fa546540ddf3393524b299b8f36ee9641a4d4f9  llmfirewall_core-1.4.0-py3-none-any.whl (local build container)
4abdd4a7f536f815c139f221afb1fb2ac02453dcde703c65ba0b1d9fae58f9d8  llmfirewall_core-1.4.0.tar.gz (local build container)
```

- **Release Tag**: `v1.4.0` (annotated, unsigned)
- **Source Commit**: `1c7128017d5fc409a07f21636b91ae4e4726facd`
