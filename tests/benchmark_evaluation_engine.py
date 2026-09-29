"""Performance and latency benchmark for Security Evaluation Engine."""

import statistics
import time
from typing import List

from llmfirewall.eval import SecurityEvaluationEngine, get_builtin_security_test_cases


def benchmark_security_evaluation():
    engine = SecurityEvaluationEngine()
    test_cases = get_builtin_security_test_cases()

    # Benchmark full suite evaluation latency
    iterations = 50
    suite_times: List[float] = []

    for _ in range(iterations):
        t0 = time.perf_counter()
        report = engine.run_suite(test_cases)
        suite_times.append((time.perf_counter() - t0) * 1000.0)

    # Benchmark baseline comparison latency
    base_dict = report.to_safe_dict()
    diff_times: List[float] = []

    for _ in range(200):
        t0 = time.perf_counter()
        engine.compare_baseline(report.metrics, report.results, base_dict)
        diff_times.append((time.perf_counter() - t0) * 1000.0)

    def stats(latencies: List[float]):
        latencies_sorted = sorted(latencies)
        p50 = statistics.median(latencies_sorted)
        p95 = latencies_sorted[int(len(latencies_sorted) * 0.95)]
        p99 = latencies_sorted[int(len(latencies_sorted) * 0.99)]
        return p50, p95, p99

    print("=" * 68)
    print(" LLMFirewall Phase 23 Security Evaluation Engine Benchmarks")
    print("=" * 68)
    print(f"Total Test Cases per Suite: {len(test_cases)}")
    print(f"{'Operation':<38} | P50 (ms) | P95 (ms) | P99 (ms)")
    print("-" * 68)

    p50_s, p95_s, p99_s = stats(suite_times)
    print(f"{'Full Suite Evaluation (' + str(len(test_cases)) + ' tests)':<38} | {p50_s:>8.4f} | {p95_s:>8.4f} | {p99_s:>8.4f}")

    p50_d, p95_d, p99_d = stats(diff_times)
    print(f"{'Baseline Comparison & Diff':<38} | {p50_d:>8.4f} | {p95_d:>8.4f} | {p99_d:>8.4f}")

    # Tests per second throughput
    tests_per_second = (len(test_cases) / (p50_s / 1000.0)) if p50_s > 0 else 0
    print(f"\nThroughput: ~{tests_per_second:.1f} test evaluations/second")
    print("=" * 68)


if __name__ == "__main__":
    benchmark_security_evaluation()
