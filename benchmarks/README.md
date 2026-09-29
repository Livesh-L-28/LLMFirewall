# LLMFirewall Performance Benchmarking Documentation

This directory contains the reproducible benchmarking harness, scaling suites, and performance telemetry for **LLMFirewall**.

---

## 1. Benchmark Architecture & Methodology

All measurements follow a strict **measure-first, evidence-based** approach:

```text
benchmarks/
├── README.md                   # Benchmark methodology, baseline tables, hardware setup
├── benchmark_firewall.py       # Master runner executing all 12 component benchmarks
├── utils.py                    # Verified hardware retrieval, percentile stats (p50, p95, p99), tracemalloc
├── benchmark_results.json      # Machine-readable benchmark output from actual execution
└── datasets/
    ├── small.txt               # ~200B prompt (typical micro-prompt)
    ├── medium.txt              # ~1.8KB prompt (typical RAG context / complex query)
    ├── large.txt               # ~45KB document (large RAG retrieval / long generation)
    └── security_cases.json     # Realistic security payloads (injection, PII, secrets, mixed)
```

### Metrics Recorded
- **Latency Percentiles**: Min, Median (p50), Mean, p95, p99, Max (in milliseconds)
- **Throughput**: Operations/second (`ops/sec`) and megabytes processed per second (`MB/sec`)
- **Memory Footprint**: Peak heap allocation tracked via `tracemalloc`
- **Isolation**: Warmup iterations precede all timed runs; cold-start and steady-state are recorded separately

---

## 2. Running Benchmarks

To execute the benchmark suite and generate `benchmark_results.json`:

```bash
python3 benchmarks/benchmark_firewall.py
```

---

## 3. Measured Performance Results (v0.1.0)

> **Environment**: macOS 14.3.1 (ARM64) | Apple Silicon (8 logical cores) | 16 GB RAM | Python 3.12.1

### A. Individual Detector Latency

| Detector | Small (196 B) | Medium (1.8 KB) | Large (44 KB) | Throughput (Medium) |
|---|:---:|:---:|:---:|:---:|
| **Prompt Injection** | 0.040 ms | 0.354 ms | 8.878 ms | 2,768 req/s (4.6 MB/s) |
| **PII Detector** | 0.021 ms | 0.180 ms | 4.578 ms | 5,420 req/s (9.0 MB/s) |
| **Secret Detector** | 0.020 ms | 0.190 ms | 4.811 ms | 5,160 req/s (8.6 MB/s) |

### B. Detector Combinations (Medium Prompt ~1.8 KB)

| Combination | Median Latency | p95 Latency | Throughput |
|---|:---:|:---:|:---:|
| Prompt Injection Only | 0.369 ms | 0.435 ms | 2,646 req/s |
| PII Only | 0.196 ms | 0.259 ms | 4,885 req/s |
| Secrets Only | 0.206 ms | 0.224 ms | 4,740 req/s |
| Prompt Injection + PII | 0.554 ms | 0.632 ms | 1,769 req/s |
| Prompt Injection + Secrets | 0.565 ms | 0.659 ms | 1,732 req/s |
| PII + Secrets | 0.390 ms | 0.441 ms | 2,499 req/s |
| **All Detectors (Default)** | **0.773 ms** | **1.050 ms** | **1,224 req/s** |

### C. Input-Size Scaling (Linear Complexity)

| Input Size | Median Latency | p95 Latency | Processed MB/s |
|:---:|:---:|:---:|:---:|
| 100 Bytes | 0.060 ms | 0.095 ms | 1.36 MB/s |
| 500 Bytes | 0.223 ms | 0.328 ms | 2.00 MB/s |
| 1,000 Bytes (1 KB) | 0.433 ms | 0.528 ms | 2.14 MB/s |
| 5,000 Bytes (5 KB) | 2.139 ms | 2.274 ms | 2.21 MB/s |
| 10,000 Bytes (10 KB) | 4.255 ms | 4.384 ms | 2.24 MB/s |
| 25,000 Bytes (25 KB) | 10.481 ms | 10.616 ms | 2.27 MB/s |
| 50,000 Bytes (50 KB) | 20.894 ms | 21.090 ms | 2.28 MB/s |

*Scaling Analysis*: Execution scales strictly linearly ($\mathcal{O}(n)$) with payload size, sustaining ~2.2 MB/s without super-linear or catastrophic regex backtracking.

### D. Subsystem Latencies

| Subsystem | Workload | Median Latency | p99 Latency | Throughput |
|---|---|:---:|:---:|:---:|
| **Risk Engine** | 0 findings | 0.0013 ms | 0.0014 ms | 744,232 ops/s |
| **Risk Engine** | 5 findings | 0.0084 ms | 0.0119 ms | 112,358 ops/s |
| **Risk Engine** | 100 findings | 0.1030 ms | 0.1433 ms | 9,591 ops/s |
| **Policy Engine** | 5 rules evaluation | 0.0035 ms | 0.0042 ms | 268,546 ops/s |
| **Redactor** | 5 span replacements | 0.0053 ms | 0.0058 ms | 185,626 ops/s |
| **Audit Logging** | Disabled vs Enabled | +0.017 ms | — | Negligible overhead |
| **Object Reuse** | Reused vs Fresh instance | +0.030 ms | — | Safe reuse saves 30 µs/req |

### E. Integrations Overhead

- **FastAPI Base**: 0.684 ms/req | **With Firewall**: 1.266 ms/req | **Overhead**: **+0.582 ms**
- **CLI Startup (`llmfirewall --version`)**: **113.09 ms** (Python VM + package initialization)
- **CLI Scan Total**: **116.10 ms** (Execution overhead in CLI: **~3.01 ms**)
- **Peak Memory**: Heap footprint during 45KB document scan is only **~398 KB**.

---

## 4. Performance Regression Baseline Strategy

To prevent performance regressions:
1. Benchmark results are committed as `benchmarks/benchmark_results.json`.
2. New versions compare their median scan latencies against this baseline.
3. Because CI machines (e.g. GitHub Actions runners) vary in hardware performance, benchmarks are run on dedicated hardware or compared relatively against the baseline Python time.
