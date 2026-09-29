"""Performance benchmarks for Phase 30: Continuous AI Security Testing & Red-Team Engine."""

import os
import resource
import time
from typing import List

from llmfirewall import (
    AttackCategory,
    MockAdapter,
    SecurityTest,
    SecurityTestSuite,
    TestOrchestrator,
    get_prompt_injection_suite,
)


def get_memory_usage_mb() -> float:
    """Return max RSS in megabytes."""
    usage = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    # macOS reports in bytes, Linux in kilobytes
    if os.uname().sysname == "Darwin":
        return usage / (1024.0 * 1024.0)
    return usage / 1024.0


def benchmark_single_test():
    print("--- 1. Single Security Test Orchestration Overhead ---")
    mock = MockAdapter()
    orchestrator = TestOrchestrator(target=mock)
    suite = get_prompt_injection_suite()
    test_case = suite.tests[0]

    # Warmup
    for _ in range(10):
        orchestrator.run_suite(test_cases=[test_case])

    latencies = []
    iterations = 200
    start = time.perf_counter()
    for _ in range(iterations):
        t0 = time.perf_counter()
        orchestrator.run_suite(test_cases=[test_case])
        latencies.append((time.perf_counter() - t0) * 1000.0)
    total_time = time.perf_counter() - start

    latencies.sort()
    p50 = latencies[int(iterations * 0.50)]
    p95 = latencies[int(iterations * 0.95)]
    p99 = latencies[int(iterations * 0.99)]
    throughput = iterations / total_time

    print(f"Executed {iterations} single-test cycles in {total_time * 1000:.2f} ms")
    print(f"Throughput : {throughput:,.1f} test-runs/sec")
    print(f"Latency P50: {p50:.3f} ms")
    print(f"Latency P95: {p95:.3f} ms")
    print(f"Latency P99: {p99:.3f} ms")


def benchmark_100_tests():
    print("\n--- 2. 100 Security Tests Suite Execution (Sequential) ---")
    mock = MockAdapter()
    orchestrator = TestOrchestrator(target=mock)

    # Build 100 synthetic tests
    base_suite = get_prompt_injection_suite()
    tests: List[SecurityTest] = []
    for i in range(100):
        base_t = base_suite.tests[i % len(base_suite.tests)]
        tests.append(
            SecurityTest(
                id=f"BENCH-100-{i:03d}",
                name=f"Benchmark Test {i}",
                category=base_t.category,
                input_payload=base_t.input_payload,
                expected_action=base_t.expected_action,
            )
        )
    suite = SecurityTestSuite(name="bench-100", tests=tests)

    start = time.perf_counter()
    report = orchestrator.run_suite(suite=suite, workers=1)
    total_time = time.perf_counter() - start

    print(f"Executed 100 tests in {total_time * 1000:.2f} ms")
    print(f"Throughput : {100 / total_time:,.1f} tests/sec")
    print(f"Mean Latency: {report.metrics.mean_latency_ms:.3f} ms")
    print(f"P95 Latency : {report.metrics.p95_latency_ms:.3f} ms")
    print(f"Pass Rate   : {report.metrics.pass_rate * 100:.1f}%")


def benchmark_1000_tests():
    print("\n--- 3. 1,000 Security Tests Scale Benchmark ---")
    mock = MockAdapter()
    orchestrator = TestOrchestrator(target=mock)

    base_suite = get_prompt_injection_suite()
    tests: List[SecurityTest] = []
    for i in range(1000):
        base_t = base_suite.tests[i % len(base_suite.tests)]
        tests.append(
            SecurityTest(
                id=f"BENCH-1K-{i:04d}",
                name=f"Benchmark Test {i}",
                category=base_t.category,
                input_payload=base_t.input_payload,
                expected_action=base_t.expected_action,
            )
        )
    suite = SecurityTestSuite(name="bench-1000", tests=tests)

    mem_before = get_memory_usage_mb()
    start = time.perf_counter()
    report = orchestrator.run_suite(suite=suite, workers=1)
    total_time = time.perf_counter() - start
    mem_after = get_memory_usage_mb()

    print(f"Executed 1,000 tests in {total_time * 1000:.2f} ms")
    print(f"Throughput  : {1000 / total_time:,.1f} tests/sec")
    print(f"Mean Latency: {report.metrics.mean_latency_ms:.3f} ms")
    print(f"P95 Latency : {report.metrics.p95_latency_ms:.3f} ms")
    print(f"Memory Delta: {mem_after - mem_before:.2f} MB (Peak RSS: {mem_after:.2f} MB)")


def benchmark_parallel_execution():
    print("\n--- 4. Multi-Worker Parallel Test Orchestration (1,000 Tests) ---")
    mock = MockAdapter()
    orchestrator = TestOrchestrator(target=mock)

    base_suite = get_prompt_injection_suite()
    tests: List[SecurityTest] = []
    for i in range(1000):
        base_t = base_suite.tests[i % len(base_suite.tests)]
        tests.append(
            SecurityTest(
                id=f"PAR-1K-{i:04d}",
                name=f"Benchmark Test {i}",
                category=base_t.category,
                input_payload=base_t.input_payload,
                expected_action=base_t.expected_action,
            )
        )
    suite = SecurityTestSuite(name="bench-par", tests=tests)

    for workers in [2, 4, 8]:
        start = time.perf_counter()
        report = orchestrator.run_suite(suite=suite, workers=workers)
        total_time = time.perf_counter() - start
        print(f"Workers: {workers:<2} | Total: {total_time * 1000:.2f} ms | Throughput: {1000 / total_time:,.1f} tests/sec")


def benchmark_evidence_sanitization():
    print("\n--- 5. Evidence Redaction Benchmark ---")
    orchestrator = TestOrchestrator()
    sample = (
        "Evaluation finding: Leaked token ghp_0123456789abcdefghijklmnopqrstuvwxyz "
        "and email user.admin@corp.internal from endpoint /api/v1/auth."
    )

    count = 1000
    start = time.perf_counter()
    for _ in range(count):
        orchestrator.sanitize_text(sample)
    total_time = time.perf_counter() - start

    print(f"Executed {count:,} evidence redactions in {total_time * 1000:.2f} ms")
    print(f"Throughput : {count / total_time:,.1f} redactions/sec")
    print(f"Mean Latency: {(total_time / count) * 1000:.3f} ms")


if __name__ == "__main__":
    benchmark_single_test()
    benchmark_100_tests()
    benchmark_1000_tests()
    benchmark_parallel_execution()
    benchmark_evidence_sanitization()
