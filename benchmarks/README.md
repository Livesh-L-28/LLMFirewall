# LLMFirewall-Core Benchmark Framework

A reproducible, empirical benchmarking suite for measuring the security detection accuracy, False Positive Rate (FPR), False Negative Rate (FNR), latency percentiles, and multi-threaded throughput of **LLMFirewall-Core**.

---

## Overview & Philosophy

Security benchmarks must be transparent, verifiable, and free of marketing exaggeration.
This suite executes against local, version-controlled JSON datasets without calling external network services.

> [!WARNING]
> **Universal Security Disclaimer**: High detection scores on synthetic benchmark datasets do **not** imply universal immunity against zero-day attacks, adaptive adversarial jailbreaks, or sophisticated multi-turn social engineering. Synthetic datasets serve as regression tests and baseline performance indicators, not proof of absolute protection.

---

## Datasets

All datasets reside in `benchmarks/datasets/`:

1. **`benign.json` (25 samples)**: Realistic developer prompts covering code generation, API design, mathematical derivations, translation, and everyday conversational queries.
   - *Target Action*: `ALLOW`
   - *Metric Measured*: False Positive Rate (FPR)

2. **`prompt_injection.json` (25 samples)**: Direct and indirect injection payloads, system prompt extraction, roleplay jailbreaks (e.g. DAN mode), and administrative override patterns.
   - *Target Action*: `BLOCK`
   - *Metric Measured*: Detection rate and False Negative Rate (FNR)

3. **`pii.json` (20 samples)**: Sensitive personal and financial identifiers including emails, phone numbers, Social Security Numbers (SSNs), and payment card numbers.
   - *Target Action*: `REDACT`
   - *Metric Measured*: Redaction accuracy

4. **`adversarial.json` (20 samples)**: Evasion variations testing detector robustness against casing permutations, embedded delimiters, XML wrappers, JSON payloads, and mixed instructions.
   - *Target Action*: `BLOCK` or `REDACT`
   - *Metric Measured*: Evasion detection rate

---

## How to Run the Benchmarks

### Prerequisites

Ensure you have Python 3.9+ and have installed `llmfirewall-core`:

```bash
git clone https://github.com/Livesh-L-28/LLMFirewall.git
cd LLMFirewall
pip install -e .
```

### Execution

Run the runner script:

```bash
python benchmarks/run_benchmarks.py
```

### What the Runner Measures

1. **Classification Accuracy & Error Rates**:
   - False Positive Rate (FPR) on benign inputs.
   - False Negative Rate (FNR) on prompt injection attempts.
   - Redaction precision on PII inputs.
   - Defense rate against adversarial evasions.
2. **Latency Percentiles**:
   - Executes 50 warm-up runs to stabilize Python caches and JIT paths.
   - Times individual scans across all 90 test samples using high-resolution monotonic clocks (`time.perf_counter_ns()`).
   - Reports Minimum, Median (p50), Mean, p95, p99, and Maximum latency in milliseconds.
3. **Multi-Threaded Throughput**:
   - Spawns 4 concurrent worker threads executing 400 requests.
   - Reports completed requests per second (RPS).
4. **Automated Report Generation**:
   - Automatically writes the results and hardware specifications to `benchmarks/RESULTS.md`.

---

## Reviewing Latest Results

See [`benchmarks/RESULTS.md`](RESULTS.md) for the latest empirical measurements executed on developer hardware.
