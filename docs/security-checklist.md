# Production Deployment & Security Hardening Checklist

Use this checklist to verify that LLMFirewall is correctly and securely integrated into production workloads.

---

## 1. Package & Supply-Chain Security

- [x] **Zero Unnecessary Runtime Dependencies**: Core package requires only `pydantic>=2.0.0`.
- [x] **Isolated Extras**: Framework integrations (e.g. `fastapi`) are strictly optional.
- [x] **Clean Distribution Artifacts**: Wheel and sdist exclude `.env`, `.git`, temporary files, and test caches.
- [x] **Zero Hardcoded Secrets**: Repository contains only synthetic testing secrets with dummy checksums.
- [x] **Vulnerability Scanning**: Automated dependency checks via `pip-audit` or Dependabot.

---

## 2. Runtime & Input Hardening

- [x] **Input Length Boundaries**: Enforced via `MAX_SCAN_TEXT_LENGTH` (5MB ceiling) on `ScanRequest` and `max_inspection_bytes` in FastAPI middleware.
- [x] **Unicode NFKC Normalization**: Strips zero-width characters, invisible formatting tags, and normalizes full-width homoglyphs before detection heuristics.
- [x] **Regex ReDoS Protection**: All regular expressions use atomic or non-backtracking patterns with bounded character classes and linear time complexity.
- [x] **CLI ANSI Sanitization**: Terminal output sanitization strips ANSI escape sequences (`\x1b[...]`) and control characters to prevent prompt spoofing in terminal logs.
- [x] **Controlled Error Handling**: Exceptions contain structured, sanitized diagnostic notes without leaking raw prompts, system filepaths, or environment variables.

---

## 3. Privacy & Compliance (GDPR, HIPAA, PCI-DSS)

- [x] **Zero Raw Prompt Retention**: Audit events and telemetry events record metadata, risk scores, and threat categories, never raw prompt text.
- [x] **Secret & PII Masking**: Detection findings store span offsets and replacement masks (`[REDACTED_EMAIL]`, `[REDACTED_SECRET]`); `store_matched_text` defaults to `False`.
- [x] **Low Cardinality Metrics**: Telemetry metrics keys use fixed, discrete labels (`action`, `category`) to avoid cardinality explosion and inadvertent leakage.

---

## 4. Operational Readiness & Resilience

- [x] **Failure Isolation**: Sinks and loggers trap backend delivery errors internally; telemetry crashes never alter security decisions or unblock blocked attacks.
- [x] **Fail-Closed by Default**: FastAPI middleware defaults to `fail_closed=True`, blocking traffic if the core inspection pipeline encounters an unhandled runtime error.
- [x] **Instance Reuse**: Persistent singleton `Firewall()` instance reuses compiled regex patterns with sub-millisecond execution overhead (<0.11ms).
- [x] **Structured Machine-Readable Output**: Both CLI (`--json`) and audit logger emit strict, valid JSON for automated SIEM parsing and alert triggering.
