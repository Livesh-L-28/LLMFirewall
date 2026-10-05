# LLMFirewall Documentation Index

Welcome to the comprehensive documentation for **LLMFirewall v1.1.0**.

---

## Navigation & Core Guides

### 1. Getting Started
- **[Getting Started Guide](getting-started.md)**: Introduction, quick concepts, and first steps.
- **[Installation Guide](installation.md)**: Virtual environment setup, PyPI installation, optional extras, and troubleshooting.
- **[Quick Start](../README.md#quick-start)**: Rapid tour of the basic scanning and runtime protection APIs.

### 2. Architecture & Design
- **[System Architecture](architecture.md)**: End-to-end request lifecycle, component boundaries, and sub-millisecond execution design.
- **[System Architecture Specification (Root)](../ARCHITECTURE.md)**: High-level architectural map and milestone history.
- **[v1.1 Architecture Review Audit](v1.1-architecture-review.md)**: Architecture audit, invariants, and extension review.

### 3. API & CLI Reference
- **[Python API Reference](api.md)**: Authoritative reference for `Firewall`, `Scanner`, `FirewallConfig`, models, enums, and exceptions.
- **[Subsystem API Accessors](python-api.md)**: Guide to specialized sub-engines (`inventory`, `graph`, `posture`, `compliance`, `risk`, `incidents`).
- **[CLI Reference](cli.md)**: Complete guide to all 21 subcommands, flags, input/output options, and exit codes.

### 4. Security & Compliance
- **[Security Model & Threat Boundaries](security-model.md)**: Threat actors, trust boundaries, data handling policies, and known limitations.
- **[Security Policy & Disclosure (SECURITY.md)](../SECURITY.md)**: Vulnerability disclosure channels, response SLAs, and supported versions.
- **[Security Audit Report](security-audit.md)**: Comprehensive static analysis, dependency evaluation, and code safety audit.
- **[Security Checklist](security-checklist.md)**: Pre-deployment operational security checklist.
- **[Policy-as-Code & Linter](policy-as-code.md)**: Declarative JSON/YAML security policies, rule structure, static linter, and condition syntax.
- **[Compliance & Control Mapping](compliance.md)**: Mapping security controls to NIST AI RMF, OWASP Top 10 for LLM, and ISO/IEC 42001.

### 5. Empirical Benchmarks & Validation
- **[Benchmark Results](benchmarks.md)**: Empirical 40-case security benchmark corpus results, detection rates, and latency measurements.
- **[Performance & Caching](performance.md)**: ScanCache LRU/TTL, compiled regex cache, and empirical 8x speedup benchmarks.
- **[Security Evaluation Engine](security-evaluation.md)**: Adversarial mutations (homoglyphs, BiDi, role confusion), failure clustering, and red-teaming.

### 6. Subsystem Guides
- **[Detection Engine 2.0](detection-engine.md)**: Unified heuristic/regex evaluation, execution planner, and aggregator.
- **[Advanced Prompt-Injection Defense](prompt-injection-defense.md)**: Homoglyph normalization, invisible chars, leetspeak, delimiters, and role confusion.
- **[AI Runtime Security 2.0](runtime-security.md)**: Sub-millisecond defense, multi-turn session tracking, streaming text guard, and rate limiting.
- **[AI Agent & Tool Security 2.0](agent-tool-security.md)**: Sandboxing agent tools, SSRF/cloud metadata prevention, path traversal defense, and action budgets.
- **[Agent Capability Security](capability-security.md)**: Action budgets, capability grants, and delegation control.
- **[RAG Security](rag-security.md)**: Document ingestion scanning, untrusted context tagging, and quarantine store.
- **[Risk Intelligence & Attack Chains](risk-intelligence.md)**: Cross-detector correlation, multi-stage attack chains, and blast radius estimation.
- **[Observability & Security Dashboard API](observability.md)**: Zero-leakage metrics, SecurityDashboardAPI, CEF SIEM exporter, and Prometheus telemetry.
- **[AI Security Posture Management (AI-SPM)](ai-spm.md)**: Asset exposure, security gaps, and posture baselines.
- **[AI Asset Inventory](asset-inventory.md)**: Discovery providers, cataloging, and inventory diffing.
- **[AI Security Knowledge Graph](security-knowledge-graph.md)**: In-process graph modeling, impact analysis, and blast radius.
- **[Attack Graph Analysis](attack-graph.md)**: Multi-step attack path discovery, choke points, and threat modeling.
- **[Incident Response & Investigation](incidents.md)**: Security event ingestion, automated correlation, timelines, and containment.
- **[Supply Chain Security](supply-chain-security.md)**: Model artifact verification, SBOM auditing, and serialization safety.
- **[Security Governance & Assurance Gates](governance.md)**: Automated CI/CD release readiness gates and cryptographic baselines.

### 7. Integrations & Developer Experience
- **[Developer Integrations 2.0](integrations.md)**: Pure ASGI 3.0 middleware, `StreamingTextGuard` sliding window, sync/async clients.
- **[FastAPI Web Integration](integrations/overview.md)**: Protecting web services with `FirewallMiddleware`.
- **[Examples Catalog (examples/README.md)](../examples/README.md)**: Index and execution instructions for all runnable examples.

### 8. Release Information
- **[Release Notes (v1.0.0)](releases/v1.0.0.md)**: Official v1.0.0 announcement.
- **[Release Report (v1.0.0)](releases/v1.0.0-release-report.md)**: Technical release audit and empirical validation sign-off for v1.0.0.
- **[Changelog (CHANGELOG.md)](../CHANGELOG.md)**: Chronological record of features, changes, and fixes.
- **[Contributing Guidelines (CONTRIBUTING.md)](../CONTRIBUTING.md)**: Code style, testing guidelines, and PR workflow.
