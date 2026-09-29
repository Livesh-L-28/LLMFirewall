"""Performance benchmarks for Phase 31: AI Security Governance, Security Gates & Continuous Assurance."""

import io
import os
import resource
import time
from typing import List

from llmfirewall.audit import AuditLogger
from llmfirewall import (
    Action,
    AttackCategory,
    GateType,
    GovernanceEngine,
    GovernanceFinding,
    GovernancePolicy,
    SecurityBaseline,
    SecurityEvidence,
    SecurityGate,
    SecurityTestResult,
    Severity,
    TargetType,
)

# Silent audit logger to benchmark engine logic without console I/O bottleneck
silent_audit = AuditLogger(sink=io.StringIO())


def get_memory_usage_mb() -> float:
    """Return max RSS in megabytes."""
    usage = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    if os.uname().sysname == "Darwin":
        return usage / (1024.0 * 1024.0)
    return usage / 1024.0


def benchmark_100_gates():
    print("--- 1. Evaluating 100 Security Gates ---")
    gates = [
        SecurityGate(
            id=f"gate-{i}",
            type=GateType.TEST_GATE,
            required=True,
            minimum_pass_rate=0.9,
        )
        for i in range(100)
    ]
    policy = GovernancePolicy(name="bench-100-gates", gates=gates)
    engine = GovernanceEngine(audit_logger=silent_audit)

    result = SecurityTestResult(
        test_id="PI-001",
        category=AttackCategory.PROMPT_INJECTION,
        target_type=TargetType.PROMPT,
        severity=Severity.LOW,
        passed=True,
        actual_action=Action.BLOCK,
        expected_action=Action.BLOCK,
    )
    evidence = SecurityEvidence(test_results=[result])

    # Warmup
    for _ in range(5):
        engine.evaluate(evidence, policy=policy)

    latencies = []
    iterations = 50
    start = time.perf_counter()
    for _ in range(iterations):
        t0 = time.perf_counter()
        engine.evaluate(evidence, policy=policy)
        latencies.append((time.perf_counter() - t0) * 1000.0)
    total_time = time.perf_counter() - start

    latencies.sort()
    p50 = latencies[int(iterations * 0.50)]
    p95 = latencies[int(iterations * 0.95)]
    p99 = latencies[int(iterations * 0.99)]

    print(f"Evaluated {iterations} runs of 100 gates in {total_time * 1000:.2f} ms")
    print(f"Latency P50: {p50:.3f} ms")
    print(f"Latency P95: {p95:.3f} ms")
    print(f"Latency P99: {p99:.3f} ms")
    print(f"Memory RSS : {get_memory_usage_mb():.2f} MB")


def benchmark_1000_gates():
    print("\n--- 2. Evaluating 1,000 Security Gates ---")
    gates = [
        SecurityGate(
            id=f"gate-{i}",
            type=GateType.TEST_GATE,
            required=True,
            minimum_pass_rate=0.8,
        )
        for i in range(1000)
    ]
    policy = GovernancePolicy(name="bench-1000-gates", gates=gates)
    engine = GovernanceEngine(audit_logger=silent_audit)

    result = SecurityTestResult(
        test_id="PI-001",
        category=AttackCategory.PROMPT_INJECTION,
        target_type=TargetType.PROMPT,
        severity=Severity.LOW,
        passed=True,
        actual_action=Action.BLOCK,
        expected_action=Action.BLOCK,
    )
    evidence = SecurityEvidence(test_results=[result])

    # Warmup
    for _ in range(3):
        engine.evaluate(evidence, policy=policy)

    latencies = []
    iterations = 20
    start = time.perf_counter()
    for _ in range(iterations):
        t0 = time.perf_counter()
        engine.evaluate(evidence, policy=policy)
        latencies.append((time.perf_counter() - t0) * 1000.0)
    total_time = time.perf_counter() - start

    latencies.sort()
    p50 = latencies[int(iterations * 0.50)]
    p95 = latencies[int(iterations * 0.95)]
    p99 = latencies[int(iterations * 0.99)]

    print(f"Evaluated {iterations} runs of 1,000 gates in {total_time * 1000:.2f} ms")
    print(f"Latency P50: {p50:.3f} ms")
    print(f"Latency P95: {p95:.3f} ms")
    print(f"Latency P99: {p99:.3f} ms")
    print(f"Memory RSS : {get_memory_usage_mb():.2f} MB")


def benchmark_10000_evidence_records():
    print("\n--- 3. Processing 10,000 Security Evidence Records ---")
    results = [
        SecurityTestResult(
            test_id=f"TEST-{i:05d}",
            category=AttackCategory.PROMPT_INJECTION if i % 2 == 0 else AttackCategory.PII_EXPOSURE,
            target_type=TargetType.PROMPT,
            severity=Severity.LOW if i % 10 != 0 else Severity.MEDIUM,
            passed=(i % 50 != 0),
            actual_action=Action.BLOCK if (i % 50 != 0) else Action.ALLOW,
            expected_action=Action.BLOCK,
        )
        for i in range(10000)
    ]
    evidence = SecurityEvidence(test_results=results)
    policy = GovernancePolicy.default_development_policy()
    engine = GovernanceEngine(audit_logger=silent_audit)

    latencies = []
    iterations = 5
    start = time.perf_counter()
    for _ in range(iterations):
        t0 = time.perf_counter()
        engine.evaluate(evidence, policy=policy)
        latencies.append((time.perf_counter() - t0) * 1000.0)
    total_time = time.perf_counter() - start

    latencies.sort()
    p50 = latencies[int(iterations * 0.50)]
    p95 = latencies[int(iterations * 0.95)]
    p99 = latencies[int(iterations * 0.99)]

    print(f"Processed {iterations} runs of 10,000 evidence records in {total_time * 1000:.2f} ms")
    print(f"Latency P50: {p50:.3f} ms")
    print(f"Latency P95: {p95:.3f} ms")
    print(f"Latency P99: {p99:.3f} ms")
    print(f"Memory RSS : {get_memory_usage_mb():.2f} MB")


def benchmark_large_baseline_comparison():
    print("\n--- 4. Large Baseline (1,000 Findings) Integrity & Comparison ---")
    findings = [
        GovernanceFinding.from_test_finding(
            category="prompt_injection" if i % 2 == 0 else "tool_abuse",
            description=f"Automated benchmark finding {i}",
            severity=Severity.MEDIUM,
            test_id=f"TEST-{i:04d}",
        )
        for i in range(1000)
    ]
    t0_base = time.perf_counter()
    baseline = SecurityBaseline.create(
        baseline_id="BASE-LARGE-1000",
        findings=findings,
    )
    t_create = (time.perf_counter() - t0_base) * 1000.0

    t0_verify = time.perf_counter()
    verified = baseline.verify_integrity()
    t_verify = (time.perf_counter() - t0_verify) * 1000.0
    assert verified is True

    t0_diff = time.perf_counter()
    diff = baseline.compare_findings(findings)
    t_diff = (time.perf_counter() - t0_diff) * 1000.0
    assert diff.is_identical is True

    print(f"Baseline Creation Duration : {t_create:.3f} ms")
    print(f"SHA-256 Tamper Verification: {t_verify:.3f} ms")
    print(f"1,000-Finding Diff Duration : {t_diff:.3f} ms")
    print(f"Memory RSS                 : {get_memory_usage_mb():.2f} MB")


if __name__ == "__main__":
    print("=" * 65)
    print(" LLMFirewall Phase 31: Governance & Assurance Performance Benchmark")
    print("=" * 65)
    benchmark_100_gates()
    benchmark_1000_gates()
    benchmark_10000_evidence_records()
    benchmark_large_baseline_comparison()
    print("\n" + "=" * 65)
    print(" Benchmark completed successfully.")
    print("=" * 65)
