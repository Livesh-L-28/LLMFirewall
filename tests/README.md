# LLMFirewall Test Architecture & Security Regression Documentation

This directory contains the testing infrastructure, security verification datasets, and regression suites for **LLMFirewall**.

---

## 1. Test Architecture & Structure

The test suite is organized into distinct functional layers:

```text
tests/
├── conftest.py                       # Global, reusable, non-mutating pytest fixtures
├── benchmark_report.py               # Precision, Recall, and Confusion Matrix calculation tool
│
├── datasets/                         # Versioned, synthetic security & benign benchmarks
│   ├── safe_inputs.json              # Benign queries (code, SQL, medical, math, markdown)
│   ├── prompt_injection.json         # Prompt injection attack patterns
│   ├── pii.json                      # Positive & negative PII samples (emails, phones, cards, IPs)
│   └── secrets.json                  # Positive & negative synthetic credential patterns
│
├── test_core.py                      # Base interfaces, contracts, exceptions
├── test_domain_models.py             # Finding, RiskScore, PolicyDecision, ScanRequest, ScanResult
├── test_detectors.py                 # Detector engine, FindingCollection, registry
├── test_prompt_injection.py          # PromptInjectionDetector heuristic rules & compound attacks
├── test_pii.py                       # Email, Phone, IP, Payment (Luhn), and custom regex rules
├── test_secrets.py                   # API keys, tokens, JWTs, private keys, Shannon entropy gating
├── test_risk_engine.py               # Deterministic scoring, category multipliers, diminishing returns
├── test_policy_engine.py             # Policy decision rules, action precedence (BLOCK > REDACT > WARN > ALLOW)
├── test_redactor.py                  # Safe token replacement, span deduplication, zero secret exposure
├── test_firewall_integration.py      # End-to-end master orchestrator execution pipeline
├── test_output_firewall.py           # Bidirectional inspection (direction='input' vs 'output')
├── test_audit.py                     # Structured JSON audit logging & SIEM telemetry
├── test_config.py                    # Strongly typed FirewallConfig, immutability, validation
├── test_fastapi_integration.py       # ASGI FirewallMiddleware, in-flight redaction, size limits
├── test_cli.py                       # CLI parsing, stdin/file inputs, JSON mode, exit codes (0, 1, 2, 3)
├── test_information_leakage.py       # Critical security invariants: zero credential or PII leakage
├── test_malformed_input.py           # Unusual inputs, null bytes, homoglyphs, ReDoS resistance
└── test_security_regressions.py      # Labeled regression suites executing against JSON datasets
```

---

## 2. Test Markers

Standard pytest markers are defined in `pyproject.toml` to allow selective test execution:

```bash
# Run unit tests
pytest -m unit

# Run integration tests
pytest -m integration

# Run security & information leakage tests
pytest -m security

# Run regression tests on labeled datasets
pytest -m regression

# Run FastAPI tests
pytest -m fastapi

# Run CLI tests
pytest -m cli
```

---

## 3. Running Coverage

Coverage is measured using `pytest-cov`:

```bash
pytest --cov=llmfirewall --cov-report=term-missing
```

Core library coverage is maintained at **>=90%** across statements and branches.

---

## 4. Benchmark & Metrics Evaluation

A standalone evaluation utility measures True Positives (TP), False Positives (FP), True Negatives (TN), False Negatives (FN), Precision, Recall, and F1 scores against labeled benchmarks:

```bash
python3 tests/benchmark_report.py
```

### Reproducible Benchmark Results (v0.1.0)

| Dataset | Cases | TP | FP | TN | FN | Precision | Recall | F1 |
|---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| Safe Benign Prompts | 10 | 0 | 0 | 10 | 0 | 1.00 | 1.00 | 1.00 |
| Prompt Injection | 10 | 10 | 0 | 0 | 0 | 1.00 | 1.00 | 1.00 |
| PII (Personally Identifiable Info) | 8 | 4 | 0 | 4 | 0 | 1.00 | 1.00 | 1.00 |
| Secrets & Credentials | 8 | 5 | 0 | 3 | 0 | 1.00 | 1.00 | 1.00 |

> **Important Methodology Note**: These measurements describe behavior on the included test datasets and should not be interpreted as universal detector accuracy in real-world environments.

---

## 5. Security Regression Process

When a security vulnerability, bypass, or false positive is identified:

1. **Create a minimal reproduction** in a clean test case or append to `tests/datasets/*.json`.
2. **Add a regression test** in `tests/test_security_regressions.py` or the appropriate domain test file.
3. **Verify the test fails** against the existing implementation.
4. **Implement the fix** in the detector, policy engine, or redactor.
5. **Verify the regression test passes**.
6. **Retain the test permanently** to prevent future regressions.

---

## 6. Strict Credential Hygiene

- **NO REAL SECRETS**: All API keys, tokens, credit card numbers, and private keys in tests and datasets are strictly synthetic mock values (e.g. Luhn-valid test numbers, fake `sk-proj-...` patterns).
- **NO PAID/EXTERNAL APIS**: All tests execute entirely offline and local-first without contacting external model providers.
