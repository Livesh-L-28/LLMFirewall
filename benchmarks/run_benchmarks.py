#!/usr/bin/env python3
"""LLMFirewall-Core Public Security & Performance Benchmark Suite.

Executes reproducible security evaluation across curated datasets:
- Benign input classification & False Positive Rate (FPR)
- Prompt Injection & Jailbreak detection & False Negative Rate (FNR)
- Sensitive PII detection and redaction accuracy
- Adversarial evasion robustness
- Latency percentiles (min, median, p95, p99) and concurrent throughput (req/sec)

DISCLAIMER: Benchmark results on synthetic datasets measure specific detector
rules against curated patterns. They do not constitute proof of universal
security against unknown, zero-day, or sophisticated adaptive attacks.
"""

from __future__ import annotations

import concurrent.futures
import json
import os
import platform
import statistics
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Tuple

import llmfirewall
from llmfirewall import Action, Firewall, Policy


DATASETS_DIR = Path(__file__).resolve().parent / "datasets"


def get_system_metadata() -> Dict[str, Any]:
    """Collects host machine and runtime execution metadata."""
    return {
        "benchmark_version": "1.0.0",
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "package_name": "llmfirewall-core",
        "package_version": getattr(llmfirewall, "__version__", "1.4.0"),
        "python_version": f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
        "python_executable": sys.executable,
        "platform": platform.platform(),
        "processor": platform.processor() or platform.machine(),
        "architecture": platform.architecture()[0],
        "logical_cpus": os.cpu_count() or 1,
    }


def load_dataset(filename: str) -> List[Dict[str, Any]]:
    """Loads a JSON dataset from the datasets directory."""
    path = DATASETS_DIR / filename
    if not path.is_file():
        raise FileNotFoundError(f"Dataset not found at {path}")
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def run_latency_profile(fw: Firewall, sample_texts: List[str], warm_up_runs: int = 50) -> Dict[str, float]:
    """Profiles scan latency percentiles in milliseconds after warm-up."""
    # Warm-up phase to stabilize caches and JIT paths
    for i in range(warm_up_runs):
        fw.scan_prompt(sample_texts[i % len(sample_texts)])

    timings_ms: List[float] = []
    for text in sample_texts:
        t0 = time.perf_counter_ns()
        fw.scan_prompt(text)
        t1 = time.perf_counter_ns()
        timings_ms.append((t1 - t0) / 1_000_000.0)

    timings_sorted = sorted(timings_ms)
    n = len(timings_sorted)

    return {
        "samples": n,
        "min_ms": round(timings_sorted[0], 3),
        "mean_ms": round(statistics.mean(timings_sorted), 3),
        "median_ms": round(statistics.median(timings_sorted), 3),
        "p95_ms": round(timings_sorted[int(n * 0.95)], 3) if n > 1 else round(timings_sorted[0], 3),
        "p99_ms": round(timings_sorted[int(n * 0.99)], 3) if n > 1 else round(timings_sorted[0], 3),
        "max_ms": round(timings_sorted[-1], 3),
    }


def run_throughput_profile(
    fw: Firewall,
    sample_texts: List[str],
    total_requests: int = 400,
    concurrency: int = 4,
) -> Dict[str, Any]:
    """Profiles multi-threaded concurrent throughput (requests per second)."""
    texts = [sample_texts[i % len(sample_texts)] for i in range(total_requests)]

    def _worker(text: str) -> None:
        fw.scan_prompt(text)

    t0 = time.perf_counter()
    with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as executor:
        list(executor.map(_worker, texts))
    elapsed = time.perf_counter() - t0

    rps = total_requests / elapsed if elapsed > 0 else 0.0
    return {
        "concurrency": concurrency,
        "total_requests": total_requests,
        "total_time_seconds": round(elapsed, 3),
        "requests_per_second": round(rps, 1),
    }


def evaluate_dataset(
    fw: Firewall,
    dataset: List[Dict[str, Any]],
    dataset_name: str,
) -> Dict[str, Any]:
    """Evaluates security classification against expected ground truth."""
    results: List[Dict[str, Any]] = []
    correct_count = 0

    for item in dataset:
        text = item["text"]
        expected_act = item["expected_action"].lower()
        expected_threat = item.get("expected_threat")

        scan = fw.scan_prompt(text)
        actual_act = scan.action.value.lower()
        threat_types = [f.threat_type.value for f in scan.findings]

        # Classification match logic
        is_correct = False
        if expected_act == "allow":
            is_correct = (actual_act == "allow" and not scan.is_blocked)
        elif expected_act == "block":
            is_correct = (actual_act == "block" or scan.is_blocked)
        elif expected_act == "redact":
            is_correct = (actual_act == "redact" or scan.action == Action.REDACT)

        if is_correct:
            correct_count += 1

        results.append({
            "id": item["id"],
            "expected_action": expected_act,
            "actual_action": actual_act,
            "expected_threat": expected_threat,
            "detected_threats": threat_types,
            "is_correct": is_correct,
            "risk_score": scan.risk_score.score,
        })

    accuracy = correct_count / len(dataset) if dataset else 1.0

    return {
        "dataset_name": dataset_name,
        "total_samples": len(dataset),
        "correct_samples": correct_count,
        "accuracy": round(accuracy * 100.0, 1),
        "items": results,
    }


def main() -> None:
    print("=" * 70)
    print(" LLMFirewall-Core Benchmark Suite")
    print("=" * 70)

    metadata = get_system_metadata()
    print(f"Package:     {metadata['package_name']} v{metadata['package_version']}")
    print(f"Python:      {metadata['python_version']} on {metadata['platform']}")
    print(f"CPUs:        {metadata['logical_cpus']} ({metadata['processor']})")
    print("-" * 70)

    # Initialize standard firewall with default policy preset
    fw = Firewall(policy="default")

    # Load datasets
    benign_data = load_dataset("benign.json")
    injection_data = load_dataset("prompt_injection.json")
    pii_data = load_dataset("pii.json")
    adversarial_data = load_dataset("adversarial.json")

    total_samples = len(benign_data) + len(injection_data) + len(pii_data) + len(adversarial_data)
    print(f"Loaded {total_samples} test samples across 4 benchmark datasets:")
    print(f"  - benign.json:            {len(benign_data)} samples")
    print(f"  - prompt_injection.json:  {len(injection_data)} samples")
    print(f"  - pii.json:               {len(pii_data)} samples")
    print(f"  - adversarial.json:       {len(adversarial_data)} samples")
    print("-" * 70)

    # 1. Classification Evaluations
    print("Executing classification benchmarks...")
    eval_benign = evaluate_dataset(fw, benign_data, "Benign Inputs")
    eval_injection = evaluate_dataset(fw, injection_data, "Prompt Injections")
    eval_pii = evaluate_dataset(fw, pii_data, "PII & Sensitive Data")
    eval_adv = evaluate_dataset(fw, adversarial_data, "Adversarial Evasions")

    # Metrics computation:
    # False Positive Rate (FPR) on benign: benign samples incorrectly flagged as block/warn/redact
    fp_count = len(benign_data) - eval_benign["correct_samples"]
    fpr = (fp_count / len(benign_data)) * 100.0 if benign_data else 0.0

    # False Negative Rate (FNR) on prompt injection: injections that failed to block
    fn_injection_count = len(injection_data) - eval_injection["correct_samples"]
    fnr_injection = (fn_injection_count / len(injection_data)) * 100.0 if injection_data else 0.0

    # False Negative Rate on adversarial: evasions that failed detection
    fn_adv_count = len(adversarial_data) - eval_adv["correct_samples"]
    fnr_adv = (fn_adv_count / len(adversarial_data)) * 100.0 if adversarial_data else 0.0

    # PII Redaction success rate
    pii_redact_rate = eval_pii["accuracy"]

    print("\n--- Classification Performance ---")
    print(f"Benign Accuracy:           {eval_benign['accuracy']}% ({eval_benign['correct_samples']}/{eval_benign['total_samples']})")
    print(f"False Positive Rate (FPR): {round(fpr, 1)}%")
    print(f"Prompt Injection Block Rate: {eval_injection['accuracy']}% ({eval_injection['correct_samples']}/{eval_injection['total_samples']})")
    print(f"Injection FNR:             {round(fnr_injection, 1)}%")
    print(f"PII Redaction Rate:        {pii_redact_rate}% ({eval_pii['correct_samples']}/{eval_pii['total_samples']})")
    print(f"Adversarial Defense Rate:  {eval_adv['accuracy']}% ({eval_adv['correct_samples']}/{eval_adv['total_samples']})")
    print(f"Adversarial FNR:           {round(fnr_adv, 1)}%")

    # 2. Performance & Latency Profiling
    all_sample_texts = [d["text"] for d in benign_data + injection_data + pii_data + adversarial_data]
    print("\nExecuting latency profiling (50 warm-up runs, 90 timed samples)...")
    latency = run_latency_profile(fw, all_sample_texts, warm_up_runs=50)

    print("\n--- Latency Percentiles (ms) ---")
    print(f"Min:    {latency['min_ms']} ms")
    print(f"Median: {latency['median_ms']} ms")
    print(f"Mean:   {latency['mean_ms']} ms")
    print(f"P95:    {latency['p95_ms']} ms")
    print(f"P99:    {latency['p99_ms']} ms")
    print(f"Max:    {latency['max_ms']} ms")

    # 3. Concurrent Throughput Profiling
    print("\nExecuting concurrent throughput test (4 workers, 400 requests)...")
    throughput = run_throughput_profile(fw, all_sample_texts, total_requests=400, concurrency=4)
    print(f"Throughput: {throughput['requests_per_second']} requests/second ({throughput['total_requests']} in {throughput['total_time_seconds']}s)")

    # 4. Generate RESULTS.md
    results_md_path = Path(__file__).resolve().parent / "RESULTS.md"
    generate_markdown_report(
        output_path=results_md_path,
        metadata=metadata,
        eval_benign=eval_benign,
        eval_injection=eval_injection,
        eval_pii=eval_pii,
        eval_adv=eval_adv,
        fpr=fpr,
        fnr_injection=fnr_injection,
        fnr_adv=fnr_adv,
        latency=latency,
        throughput=throughput,
    )
    print(f"\n[OK] Empirical benchmark report written to: {results_md_path}")
    print("=" * 70)


def generate_markdown_report(
    output_path: Path,
    metadata: Dict[str, Any],
    eval_benign: Dict[str, Any],
    eval_injection: Dict[str, Any],
    eval_pii: Dict[str, Any],
    eval_adv: Dict[str, Any],
    fpr: float,
    fnr_injection: float,
    fnr_adv: float,
    latency: Dict[str, float],
    throughput: Dict[str, Any],
) -> None:
    """Generates the authoritative benchmarks/RESULTS.md file."""
    content = f"""# LLMFirewall-Core Benchmark Results

Empirical security accuracy and execution latency measurements generated by `benchmarks/run_benchmarks.py`.

> [!IMPORTANT]
> **Universal Security Disclaimer**: These benchmarks measure detector accuracy and latency on curated synthetic datasets.
> Synthetic evaluations cannot guarantee universal immunity against unknown, novel, or multi-turn adaptive attacks.
> All results below are strictly reproducible from the included datasets and test script.

---

## 1. Environment & Hardware Specifications

| Specification | Value |
|---|---|
| **Package** | `{metadata['package_name']}` v`{metadata['package_version']}` |
| **Python Version** | `{metadata['python_version']}` |
| **Operating System** | `{metadata['platform']}` |
| **Processor Architecture** | `{metadata['processor']}` ({metadata['architecture']}) |
| **Logical CPU Cores** | `{metadata['logical_cpus']}` |
| **Execution Date** | `{metadata['timestamp']}` |
| **Dependencies** | Minimal core (`pydantic>=2.0.0`, `pyyaml>=6.0.0`) |

---

## 2. Security Classification Metrics

Evaluated with standard baseline policy preset (`policy="default"`).

| Dataset | Sample Count | Expected Action | Detection / Pass Rate | Error Metric |
|---|---|---|---|---|
| **Benign Inputs** (`benign.json`) | {eval_benign['total_samples']} | `allow` | **{eval_benign['accuracy']}%** ({eval_benign['correct_samples']}/{eval_benign['total_samples']}) | **FPR: {round(fpr, 1)}%** |
| **Prompt Injection** (`prompt_injection.json`) | {eval_injection['total_samples']} | `block` | **{eval_injection['accuracy']}%** ({eval_injection['correct_samples']}/{eval_injection['total_samples']}) | **FNR: {round(fnr_injection, 1)}%** |
| **PII & Sensitive Data** (`pii.json`) | {eval_pii['total_samples']} | `redact` | **{eval_pii['accuracy']}%** ({eval_pii['correct_samples']}/{eval_pii['total_samples']}) | Redaction: {eval_pii['accuracy']}% |
| **Adversarial Evasions** (`adversarial.json`) | {eval_adv['total_samples']} | `block` / `redact` | **{eval_adv['accuracy']}%** ({eval_adv['correct_samples']}/{eval_adv['total_samples']}) | **FNR: {round(fnr_adv, 1)}%** |

### Definitions
- **False Positive Rate (FPR)**: Proportion of legitimate, benign queries incorrectly blocked or alerted.
- **False Negative Rate (FNR)**: Proportion of adversarial prompt injections or evasions that bypassed detection.
- **Redaction Accuracy**: Proportion of sensitive personal identifiers successfully converted into sanitized tokens (`[REDACTED_*]`).

---

## 3. Latency & Throughput Measurements

### Execution Latency (Single-Threaded)
Measured across {latency['samples']} diverse samples following 50 warm-up runs:

| Percentile | Latency (ms) | Target SLA |
|---|---|---|
| **Minimum** | `{latency['min_ms']} ms` | < 1.0 ms |
| **Median (p50)** | `{latency['median_ms']} ms` | < 5.0 ms |
| **Mean** | `{latency['mean_ms']} ms` | < 10.0 ms |
| **p95** | `{latency['p95_ms']} ms` | < 15.0 ms |
| **p99** | `{latency['p99_ms']} ms` | < 25.0 ms |
| **Maximum** | `{latency['max_ms']} ms` | < 50.0 ms |

### Concurrent Throughput
Evaluated with {throughput['concurrency']} concurrent worker threads over {throughput['total_requests']} requests:

- **Total Execution Time**: `{throughput['total_time_seconds']} seconds`
- **Throughput**: **`{throughput['requests_per_second']} requests/second`**

---

## 4. Test Methodology & Reproduction

To reproduce these measurements on your local hardware:

```bash
# 1. Clone repository & install package
git clone https://github.com/Livesh-L-28/LLMFirewall.git
cd LLMFirewall
pip install -e .

# 2. Execute benchmark suite
python benchmarks/run_benchmarks.py
```

All benchmark datasets are located in `benchmarks/datasets/` and can be inspected or extended by community contributors.
"""
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(content)


if __name__ == "__main__":
    main()
