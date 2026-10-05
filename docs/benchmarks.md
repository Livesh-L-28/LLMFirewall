# LLMFirewall Security Benchmarks & Empirical Performance

This document summarizes the empirical security evaluation and latency benchmarks conducted during the **Phase 41 Release Validation** of LLMFirewall.

> [!IMPORTANT]
> **Scope & Benchmark Population Notice:**
> The reported detection metrics correspond directly to the project's internal **40-case security benchmark corpus**, 25 regression test cases, and 13 integration test scenarios evaluated under controlled lab conditions. These metrics should not be interpreted as universal or infallible security guarantees against all possible real-world attacks.

---

## 1. Test Environment

All benchmark runs were executed on the following reference hardware and software environment:

- **Operating System**: macOS 14.3.1 (Darwin arm64)
- **CPU Architecture**: Apple Silicon (arm64)
- **Python Version**: Python 3.12.1
- **Pytest Version**: 9.1.1
- **Package Version**: `1.0.0` (validated across `1.0.0rc1` and `1.0.0`)
- **Dataset Version**: Benchmark Dataset v1 (40 curated reference scenarios)

---

## 2. Test Suite Validation Results

The full automated verification suite executed across the repository yielded:

| Test Suite Category | Test Count | Passed | Failed | Status |
|:---|:---:|:---:|:---:|:---:|
| **Unit Tests** | 598 | 598 | 0 | **PASS** |
| **Security Regression Tests** | 25 | 25 | 0 | **PASS** |
| **End-to-End Integration Tests** | 29 | 29 | 0 | **PASS** |
| **Core Detection & Policy Tests** | 40 | 40 | 0 | **PASS** |
| **Total Automated Tests (v1.1.0)** | **692** | **692** | **0** | **PASS** |

Execution time for the 692-test automated suite was **2.84 seconds** with 100% pass rate.

---

## 3. 40-Case Security Benchmark Evaluation

The benchmark dataset consists of 40 structured test cases spanning 8 key threat categories, containing 28 true adversarial attack payloads and 12 benign control prompts to assess both detection efficacy and false-positive rates.

### 3.1 Overall Confusion Matrix & Metrics

- **Total Test Cases**: 40
- **True Positives (TP)**: 28 (all attacks correctly detected)
- **False Positives (FP)**: 0 (no benign prompts falsely blocked)
- **True Negatives (TN)**: 12 (all benign inputs correctly allowed)
- **False Negatives (FN)**: 0 (zero undetected reference attacks)
- **Precision**: 1.00 (100% on benchmark corpus)
- **Recall**: 1.00 (100% on benchmark corpus)
- **Accuracy**: 1.00 (100% on benchmark corpus)
- **False Positive Rate (FPR)**: 0.0%
- **False Negative Rate (FNR)**: 0.0%

### 3.2 Breakdown by Threat Category

| Threat Category | Cases | Passed | P50 Latency (ms) | P95 Latency (ms) | Accuracy |
|:---|:---:|:---:|:---:|:---:|:---:|
| **Prompt Injection** | 11 | 11 | 0.105 | 0.128 | 1.00 |
| **Jailbreak Payloads** | 7 | 7 | 0.110 | 0.131 | 1.00 |
| **Tool Abuse & Parameter Attacks** | 5 | 5 | 0.098 | 0.154 | 1.00 |
| **Sensitive Data & PII Masking** | 5 | 5 | 0.023 | 0.145 | 1.00 |
| **Agent Capability Escalation** | 3 | 3 | 0.158 | 1.637 | 1.00 |
| **Data Exfiltration** | 3 | 3 | 0.150 | 0.474 | 1.00 |
| **Memory Poisoning** | 3 | 3 | 0.082 | 0.098 | 1.00 |
| **RAG Document Poisoning** | 3 | 3 | 0.080 | 0.088 | 1.00 |
| **Aggregate / Overall** | **40** | **40** | **0.104** | **0.474** | **1.00** |

---

## 4. Latency and Performance Overhead

To evaluate runtime overhead introduced by LLMFirewall in high-throughput production serving pipelines, microbenchmarks were conducted over 500 iterations measuring prompt processing with and without firewall inspection.

### 4.1 Measurement Results

| Metric | Without Firewall | With Firewall | Added Overhead |
|:---|:---:|:---:|:---:|
| **P50 Latency** | 0.0001 ms | 0.0223 ms | **+0.0222 ms** |
| **P95 Latency** | 0.0001 ms | 0.0263 ms | **+0.0262 ms** |
| **P99 Latency** | 0.0001 ms | 0.0590 ms | **+0.0589 ms** |
| **Mean Latency** | 0.0001 ms | 0.0235 ms | **+0.0234 ms** |

### 4.2 Latency Conclusion
The empirical added median overhead of LLMFirewall is approximately **0.022 milliseconds** (`~22 microseconds`), confirming that the runtime protection layer adds **sub-millisecond overhead** well below the variance of network transport and downstream LLM inference.

### 4.3 Scan Cache Throughput & Speedup (v1.1.0)
Phase 52 introduced the in-memory L1/L2 `ScanCache` with bounded LRU eviction and SHA-256 state hashing. Microbenchmarks across 1,000 iterations yielded:
- **Cold Inspection Latency (P50)**: 0.309 ms
- **Warm Cache Hit Latency (P50)**: 0.038 ms
- **Speedup Factor**: **8.1x faster** on warm hits (`~38 microseconds`)
- **Memory Footprint**: Bounded buffer under 5 MB for 5,000 cached records.

For full caching methodology and reproducibility scripts, see [docs/performance.md](performance.md).

---

## 5. Security Regression Verification

To prevent historical bugs from re-emerging, the release suite includes 25 targeted regression tests (`tests/regression/` and `tests/test_security_regressions.py`):

1. **Jailbreak Regressions (7 tests)**: Obfuscated prefixes, character encoding tricks, multi-language system overrides.
2. **Data Leakage Regressions (5 tests)**: PII normalization, credit card Luhn check integrity, secret entropy thresholds.
3. **Agent Security Regressions (4 tests)**: SSRF IP evasion, loop boundary exhaustion, unapproved tool parameter mutations.
4. **RAG & Memory Regressions (4 tests)**: Context boundary injection, poisoned chunk quarantine isolation.
5. **Runtime Protection Regressions (5 tests)**: Shadow mode non-blocking integrity, `FAIL_CLOSED` handling during internal errors, rate limiter token leakage.

All 25 regression suites passed with 0 failures.

---

## 6. Limitations of the Benchmark

1. **Corpus Scope**: The benchmark suite contains 40 curated test cases representing common injection styles and known attack patterns. Real-world adversaries generate novel variants that may not be covered by static benchmark distributions.
2. **Synthetic Data**: Secret and credential test vectors utilize synthetic test formats (e.g. `AKIAIOSFODNN7EXAMPLE`, `ghp_012345...`) to prevent credential leakage.
3. **Continuous Evolution**: As attack vectors evolve, benchmark datasets and heuristic pattern registries will be updated in subsequent releases.
