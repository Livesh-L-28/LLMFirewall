# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [1.0.0] - 2026-09-29

### Highlights
The first stable production release of **LLMFirewall**, establishing a lightweight, provider-agnostic, defense-in-depth security layer for Large Language Models, RAG pipelines, and autonomous AI agents.

### Added
- **Top-Level Public API**: Ergonomic entrypoints exported directly from `llmfirewall`: `Firewall`, `Scanner`, `FirewallConfig`, `Policy`, `SafeRedactor`, `AuditLogger`, `@protect`, and `protect_tool`.
- **Unified 21-Subcommand CLI**: Full coverage of the AI security lifecycle via `llmfirewall` (`scan`, `protect`, `policy`, `risk`, `incidents`, `inventory`, `posture`, `compliance`, `graph`, `attack`, `threat-model`, `test`, `eval`, `gate`, `baseline`, `rag`, `model`, `supply-chain`, `agent`, `runtime`, `observe`).
- **Sub-Millisecond Runtime Defense**: `RuntimeProtectionEngine` delivering sub-millisecond overhead (`~0.02ms` P50 latency) with fine-grained decisions: `ALLOW`, `BLOCK`, `REDACT`, `REVIEW`, `RATE_LIMIT`.
- **Agent Capability & Tool Sandboxing**: Action budgets, capability grants, delegation control, and parameter validation guards (SSRF, command injection, SQL injection).
- **RAG & Context Defense**: Ingestion scanning, strict untrusted context tagging, and quarantine isolation for poisoned document chunks.
- **Incident Response & Correlation**: Real-time event ingestion, automated correlation rules, chronological timelines with SHA-256 evidence digests, and safe dry-run containment hooks.
- **AI-SPM & Compliance**: Posture rule engine, baseline diffing, framework packs for NIST AI RMF, OWASP Top 10 for LLM, and ISO/IEC 42001 with SARIF 2.1.0 exports.
- **Security Knowledge & Attack Graphs**: In-process graph modeling of AI assets, directed multi-hop attack path discovery, and choke-point identification.
- **Universal Integrations**: ASGI middleware (`FirewallMiddleware`) for FastAPI, Starlette, and generic web frameworks.

### Changed
- Promoted development status classifier to `5 - Production/Stable`.
- Authoritative package version updated from `1.0.0rc1` to `1.0.0`.
- Standardized CLI output format and exit codes (`0` for allowed, `1` for blocked, `2` for usage error, `3` for runtime failure).
- Updated repository URLs to point to authoritative repository paths.

### Security
- Verified zero live hardcoded credentials, zero dynamic `eval`/`exec` calls, and zero arbitrary shell subprocess invocations across the core runtime engine.
- Strict `yaml.safe_load` enforcement across all configuration and policy parsing points.
- Parameterized SQLite queries across observability and security graph stores.
- Secure default settings: `FailBehavior.FAIL_CLOSED` and `PolicyMode.ENFORCE`.
- Zero-leakage invariant: Credentials and PII are redacted before reaching logs, telemetry, or exceptions.

### Testing
- 608 automated tests passing in 2.18s.
- 40-case empirical security benchmark corpus evaluated with 100% detection on benchmark samples and 0% false positives.
- 25 dedicated regression tests verifying past vulnerabilities remain closed.
- 13 cross-module integration tests verifying complete pipeline flow.

### Documentation
- Comprehensive documentation suite added under `docs/`: `architecture.md`, `api.md`, `cli.md`, `installation.md`, `security-model.md`, `security-audit.md`, `benchmarks.md`, and `README.md`.
- Complete example index created in `examples/README.md` cataloging 21 runnable examples.
- Updated `SECURITY.md` with active maintenance policies for v1.0.0.

### Packaging
- Clean wheel (`.whl`) and source distribution (`.tar.gz`) built via Hatchling.
- Zero required third-party runtime dependencies beyond `pydantic` and `pyyaml`.
- Modular optional extras: `fastapi`, `flask`, `django`, `langchain`, `llamaindex`, `all-integrations`, `dev`.

---

## [1.0.0rc1] - 2026-09-28

### Added
- Release Candidate 1 baseline validating Phases 1 through 40.
- Empirical benchmark suite running 40 test cases across 8 threat categories.
- Pre-release security audit verifying dependency hygiene and static analysis invariants.
- CI/CD workflows for multi-OS verification across Python 3.9, 3.10, 3.11, and 3.12.
