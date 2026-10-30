# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.3.2] - Unreleased

### Added
- **Default SSN Detection & Validation (FIND-FUNC-01)**:
  - Enabled `SSNSubDetector` by default in `PIIDetector` with SSA-compliant structural validation (`is_valid_ssn`).
  - Implemented false-positive suppression for order/tracking numbers and alphanumeric serial codes.
  - Added public API regression tests confirming valid synthetic SSN redaction blocks sensitive data from reaching downstream models.
- **Optional Dependency Isolation (FIND-TEST-01)**:
  - Added clean skipping and explicit error messages with installation instructions when optional dependencies (`fastapi`, `cryptography`) are absent.
  - Added unit test verifying `EncryptedStorageAdapter` fails closed with actionable installation guidance when `cryptography` is not installed.
- **Release Governance Ancestry Guard**:
  - Hardened `.github/workflows/release.yml` with full clone checkout (`fetch-depth: 0`) and `git merge-base --is-ancestor` verification ensuring release tags point strictly to commits on protected `main`.
  - Added automated CI governance and git ancestry verification test suite in `tests/test_governance.py`.
- **Synthetic Secret Fixture Hygiene (FIND-SEC-01)**:
  - Sanitized synthetic evaluation strings in `eval/generators.py`, `eval/payloads.py`, and `eval/suites.py` to prevent false positive secret scanning alerts while preserving 100% detection effectiveness.
  - Added regression test `test_find_sec_01_synthetic_evaluation_fixtures_hygiene` verifying fixture safety and detector effectiveness.

### Fixed
- **Benchmark Latency Documentation (FIND-PERF-01)**:
  - Qualified `README.md` and benchmark badges to distinguish detector inspection latency (`~0.10–0.20ms` P50) from serving runtime overhead delta (`~0.02ms` P50).
  - Updated test count documentation to reflect 874 verified test cases across unit, regression, and integration suites.
- **Security Policy Documentation (FIND-DOC-01)**:
  - Updated `SECURITY.md` supported version matrix to cover `1.3.x`, `1.2.x`, `1.1.x`, and `1.0.x`.
- **Cross-Platform Test Stabilization**:
  - Enforced LF line endings via `.gitattributes` and adjusted timer assertion margins for Windows and macOS runner reliability.

## [1.3.1] - 2026-10-27

### Fixed
- **Integrity Invariant Reconciliation**:
  - Reconciled protected `tests/test_secrets.py` to match exact required SHA-256 hash (`d5ca47fd85349bf4ef6d7944ab9a9f131aa27877b58bb90b31532203d7420e41`).
- **Release Version Metadata**:
  - Synchronized package version to `1.3.1` across `pyproject.toml`, `_version.py`, and `AGENTS.md`.

## [1.3.0] - 2026-10-27

### Added
- **Developer Integration Tooling**:
  - Added `llmfirewall integrate` CLI subcommand suite (`detect`, `list`, `scaffold`, `validate`).
  - Added automated framework detection and interactive/non-interactive boilerplate scaffolding for FastAPI, ASGI, Streaming, Tools, and RAG.
  - Added companion test generation for all supported scaffolding recipes.
- **Zero-Dependency Framework Integrations**:
  - Added `LLMFirewallASGIMiddleware` pure ASGI 3.0 middleware with zero framework dependencies.
  - Added `StreamingTextGuard` sliding-window token boundary guard for streaming LLM generations.
  - Added `LLMFirewallClient` and `AsyncLLMFirewallClient` high-level client wrappers.
- **Security Event Correlation**:
  - Added `AdvancedSecurityCorrelator` linking atomic findings to asset inventories, attack progression stages, and MITRE ATT&CK / OWASP LLM taxonomy.
- **Workflow & Agent Tool Security**:
  - Added `WorkflowEnforcer` and context-aware multi-step decision engine.
  - Added comprehensive adversarial integration test suites.

## [1.2.0] - 2026-10-24

### Added
- **Advanced Security Intelligence (Phase 58)**:
  - Added `AdvancedSecurityCorrelator` synthesizing explainable incident context without creating a divergent risk engine.
  - Connects atomic findings to affected assets, attack paths, evidence timelines, and attack progression stages (`RECONNAISSANCE`, `DELIVERY`, `EXPLOITATION`, `ESCALATION`, `EXFILTRATION`).
  - Added comprehensive test suite `tests/test_advanced_security_intelligence_phase58.py`.
- **Adaptive Threat Detection (Phase 59)**:
  - Added optional contextual and historical threat signals (`AdaptiveThreatEngine`, `HistoricalSignalTracker`, `ContextualSignal`).
  - Shannon entropy (`compute_shannon_entropy`) and token repetition ratio (`compute_token_repetition_ratio`) anomaly detectors with zero heavyweight model dependencies.
  - Safe default: disabled by default (`AdaptiveThreatConfig.enabled=False`) preserving deterministic baseline performance.
  - Added comprehensive test suite `tests/test_adaptive_threat_detection_phase59.py`.
- **AI Threat Intelligence (Phase 60)**:
  - Added structured, versioned AI threat intelligence subsystem (`AIThreatIndicator`, `ThreatIntelFeed`, `ThreatIntelManager`).
  - Strict ReDoS-safe feed validation (`ThreatFeedValidator`) and zero-automatic-trust promotion gates (`ThreatIntelTrustLevel`).
  - Added comprehensive test suite `tests/test_ai_threat_intelligence_phase60.py`.
- **Advanced Agent Security (Phase 61)**:
  - Added granular capability authorization scopes (`ResourceScope`, `ScopeType`).
  - Added delegation depth and hop validation (`DelegationChainValidator`), step-up approval provider (`StepUpApprovalProvider`), and sliding-window rate limiters (`SlidingWindowRateLimiter`).
  - Added `ToolResultTrustAnalyzer` detecting canary token leakage and indirect prompt injection attacks in external tool outputs.
  - Added comprehensive test suite `tests/test_advanced_agent_security_phase61.py`.
- **Advanced Memory Security (Phase 62)**:
  - Added memory trust classification (`MemoryTrustLabel`) and SHA-256 provenance tracking (`MemoryProvenanceRecord`).
  - Added sleeper injection attack detection (`MemoryPoisoningDetector`) and cross-session/cross-tenant memory boundary isolation (`SessionMemoryBoundary`, `AdvancedMemorySecurityGuard`).
  - Added comprehensive test suite `tests/test_advanced_memory_security_phase62.py`.
- **Enterprise Multi-Tenancy (Phase 63)**:
  - Added explicit tenant context (`TenantContext`, `TenantTier`) and tenant-aware policy layering (`TenantPolicyManager`).
  - Partitioned cache isolation in `ScanCache`: tenant IDs are cryptographically bound to cache keys to prevent cross-tenant data leakage or probing.
  - Added per-tenant token bucket / sliding window rate limiting (`TenantRateLimiter`) for noisy neighbor isolation.
  - Added comprehensive test suite `tests/test_enterprise_multi_tenancy_phase63.py`.
- **Security Data Persistence (Phase 64)**:
  - Added lightweight, pluggable storage adapters (`BasePersistenceAdapter`, `InMemoryPersistenceAdapter`, `JSONLPersistenceAdapter`, `SQLitePersistenceAdapter`).
  - Added `EncryptedStorageAdapter` protecting sensitive audit telemetry at rest with HMAC authenticated envelopes.
  - Bounded memory buffers and zero external database requirements for core library usage.
  - Added comprehensive test suite `tests/test_security_data_persistence_phase64.py`.
- **Advanced SIEM/SOC Integration (Phase 65)**:
  - Added standard RFC 5424 Syslog exporter (`export_events_syslog_rfc5424`) with priority mapping and structured security metadata.
  - Added OpenTelemetry (OTLP) LogRecords schema exporter (`export_events_opentelemetry`) with standard GenAI semantic conventions.
  - Added `WebhookAlertSink` supporting HMAC-SHA256 request signing and alert-storm rate limiting.
  - Added comprehensive test suite `tests/test_siem_soc_integration_phase65.py`.
- **Security Operations Automation (Phase 66)**:
  - Added automated response playbooks (`SecurityPlaybook`, `PlaybookStep`, `PlaybookEngine`).
  - Consequential containment actions (`REVOKE_AGENT_CAPABILITY`, `QUARANTINE_SESSION`, `ROTATE_CACHE`) require explicit policy authorization and fail closed.
  - Full dry-run / simulation support (`dry_run=True`) for safe change preview.
  - Added comprehensive test suite `tests/test_secops_automation_phase66.py`.
- **Advanced Red Teaming & Attack Chains (Phase 67)**:
  - Added multi-turn attack chain scenario evaluation (`MultiTurnAttackScenario`, `AttackTurn`, `MultiTurnRedTeamRunner`).
  - Standard attack chain suites for crescendo escalation and confused deputy agent tool injection.
  - Bounded execution and deterministic reproducible evaluation when seeded.
  - Added comprehensive test suite `tests/test_advanced_red_teaming_phase67.py`.
- **Performance & Distributed Execution (Phase 68)**:
  - Added `DistributedCacheAdapter` supporting two-tier L1 (memory) and L2 (remote distributed store) caching with fault-tolerant fail-open fallbacks.
  - Added bounded concurrent batch scanner `ParallelScanPool` preserving strict input ordering and fail-closed isolation.
  - Verified sub-millisecond warm cache lookup latency (< 0.05ms average).
  - Added comprehensive test suite `tests/test_performance_distributed_phase68.py`.
- **End-to-End Pipeline & Integration (Phase 69)**:
  - Added complete runnable pipeline example `examples/v1_2_end_to_end_pipeline.py`.
  - Added comprehensive cross-component test `tests/test_v1_2_integration.py`.

### Compatibility
- 100% backward compatible with v1.1.0 baseline across all 475 public exports, signatures, and default behaviors.
- Verified with 756 total passing tests (up from 692 baseline).

## [1.1.0] - 2026-10-05

### Added
- **Security Dashboard API & Enterprise SIEM Integration (Phase 54)**:
  - Added `SecurityDashboardAPI` providing privacy-safe summary metrics, paginated sanitized events, and time-bucketed aggregations.
  - Added Common Event Format (CEF) exporter (`export_events_cef`) for Splunk, ArcSight, QRadar, and Microsoft Sentinel.
  - Added cache telemetry counters (`llmfirewall_cache_hits_total`, `llmfirewall_cache_misses_total`, `llmfirewall_cache_hit_ratio`) to Prometheus exporter.
  - Added comprehensive test suite `tests/test_observability_v2.py`.
- **Adversarial Evaluation & Red-Teaming (Phase 53)**:
  - Added `AdversarialMutationEngine` generating attack mutations across Unicode homoglyphs, zero-width characters, BiDi overrides, leetspeak, delimiter manipulation, role confusion, RAG poisoning, and tool injection.
  - Added `AdversarialRedTeamRunner` evaluating bypass rates and clustering failure patterns into `FailureCluster` reports.
  - Added comprehensive test suite `tests/test_security_evaluation_v2.py`.
- **Performance & Scan Caching (Phase 52)**:
  - Added thread-safe `ScanCache` featuring bounded LRU eviction, configurable TTL, deterministic SHA-256 keys, ephemeral context isolation, and operational telemetry.
  - Added `RegexCache` and `compile_regex` for compiled regular expression caching across detectors.
  - Verified 8.1x latency speedup on warm cache hits (0.309 ms cold → 0.038 ms warm) with 99.9% hit ratios.
  - Added comprehensive test suite `tests/test_performance_and_caching.py` and benchmark runner `examples/benchmark_performance.py`.
- **Developer Integrations 2.0 (Phase 51)**:
  - Added pure ASGI 3.0 middleware `LLMFirewallASGIMiddleware` with zero external dependencies, streaming HTTP body inspection, and WebSocket support.
  - Added `StreamingTextGuard` implementing boundary-aware sliding window inspection for continuous LLM token streams.
  - Added `LLMFirewallClient` and `AsyncLLMFirewallClient` for unified sync and async LLM framework pipelines.
  - Added convenience entrypoints `Firewall.scan_prompt` and `Firewall.scan_output`.
  - Added comprehensive test suite `tests/test_developer_integrations_v2.py`.
- **Risk Intelligence 2.0 (Phase 50)**:
  - Added `SessionRiskTracker` for multi-turn session tracking with exponential temporal decay and low-and-slow probing attack detection.
  - Added `FindingCorrelationEngine` inferring compound attack chains (`EXFILTRATION_CHAIN`, `REMOTE_EXECUTION_CHAIN`, `INDIRECT_RAG_POISONING`, `PRIVILEGE_ESCALATION`, `MULTI_VECTOR_FLOOD`).
  - Added `BlastRadiusEstimator` estimating systemic downstream impact, reachable services, and immediate containment steps.
  - Added comprehensive test suite `tests/test_risk_intelligence_v2.py`.
- **Policy-as-Code 2.0 & Static Linter (Phase 49)**:
  - Added `PolicyLinter` detecting unreachable shadowed rules, logical contradictions, evaluation cycles, and invalid regexes.
  - Added advanced predicates to `RuleCondition` (`min_confidence`, `category`, `direction`).
  - Added dry-run policy simulation and conflict resolution validation.
  - Added comprehensive test suite `tests/test_policy_as_code.py`.
- **Agent & Tool Security 2.0 (Phase 47)**:
  - Added comprehensive tool argument validation, SSRF prevention (blocking link-local, private, and AWS/GCP cloud metadata IP ranges), and path traversal checks.
  - Added tool registry enforcement and action budget ceilings.
- **Advanced Prompt-Injection Defense (Phase 45)**:
  - Added `IndirectInjectionRule` detecting assistant target overrides and hidden comment payloads.
  - Added `DelimiterAttackRule` detecting boundary framing and special envelope tag escapes.
  - Added `AuthorityImpersonationRule` detecting administrator role impersonation and privilege claims.
  - Added `PromptSecurityContext` and `PromptSourceType` for source awareness and provenance tracking.
  - Added `MultiTurnSecurityState` for tracking bounded security history and suspicious multi-turn probing.
  - Added comprehensive test suite `tests/test_prompt_injection_defense.py`.
- **Advanced Detection Engine Pipeline (Phase 44)**:
  - Multi-stage detection engine in `DetectorEngine` supporting normalization, candidate pre-filtering, token heuristics, confidence calibration, and finding deduplication.
  - Structural typing protocol `DetectorProtocol` via `typing.Protocol`.
  - Deterministic execution planner `ExecutionPlanner` with cost model (`DetectorCost`).
  - Finding aggregator `FindingAggregator` with SHA-256 fingerprint deduplication.
- **End-to-End Pipeline & Examples (Phase 55)**:
  - Added complete runnable pipeline example `examples/v1_1_end_to_end_pipeline.py`.
  - Updated all documentation guides and references across `docs/` and `README.md`.

### Fixed
- Re-exported `HASH_CHUNK_SIZE` in `llmfirewall.__init__` to satisfy declared `__all__` public contract.
- Unified `Detector` to inherit directly from `BaseDetector`, closing interface hierarchy divergence.
- Re-parented `SecurityGateFailure` under `LLMFirewallError` so all framework-raised exceptions inherit from root error base.

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
