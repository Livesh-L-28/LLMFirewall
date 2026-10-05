#!/usr/bin/env python3
"""Performance & Caching Benchmark for LLMFirewall v1.1.0 (Phase 52).

Measures latency and throughput across cold and cached execution paths.
"""

import time
from llmfirewall import Action, Firewall


def run_benchmark() -> None:
    print("=== LLMFirewall Core v1.1.0 — Performance & Caching Benchmark ===\n")

    test_prompts = [
        "Please summarize the annual financial performance and key risk factors.",
        "What are the best practices for setting up zero-trust network access in AWS?",
        "Explain the differences between symmetric and asymmetric encryption algorithms.",
        "Draft an executive memo regarding cybersecurity compliance and privacy frameworks.",
        "Analyze the following database query for potential bottlenecks and indexing opportunities.",
    ]

    # Initialize firewall with cache enabled
    fw = Firewall(enable_cache=True, cache_size=5000, cache_ttl=1800.0)

    # 1. Cold Scan Measurement
    print("1. Running Cold Scans (No Cache)...")
    cold_times = []
    for prompt in test_prompts:
        t0 = time.perf_counter()
        res = fw.scan_prompt(prompt, context={"no_cache": True})
        elapsed_us = (time.perf_counter() - t0) * 1_000_000.0
        cold_times.append(elapsed_us)
        assert res.action == Action.ALLOW

    avg_cold_us = sum(cold_times) / len(cold_times)
    print(f"  Avg Cold Scan Latency: {avg_cold_us:.2f} μs ({avg_cold_us / 1000.0:.3f} ms)")
    print(f"  Cold Scan Throughput:  {1_000_000.0 / avg_cold_us:.0f} req/sec\n")

    # 2. Warm Cache Populating
    for prompt in test_prompts:
        fw.scan_prompt(prompt)

    # 3. Warm Cache Hit Measurement
    print("2. Running Warm Cache Hit Scans...")
    warm_times = []
    iterations = 5000
    t_start = time.perf_counter()
    for i in range(iterations):
        prompt = test_prompts[i % len(test_prompts)]
        t0 = time.perf_counter()
        res = fw.scan_prompt(prompt)
        elapsed_us = (time.perf_counter() - t0) * 1_000_000.0
        warm_times.append(elapsed_us)
        assert res.metadata.get("cached") is True

    total_warm_sec = time.perf_counter() - t_start
    avg_warm_us = sum(warm_times) / len(warm_times)
    warm_ops_per_sec = iterations / total_warm_sec
    speedup = avg_cold_us / max(0.1, avg_warm_us)

    print(f"  Iterations:            {iterations}")
    print(f"  Avg Warm Cache Latency:{avg_warm_us:.2f} μs ({avg_warm_us / 1000.0:.4f} ms)")
    print(f"  Warm Cache Throughput: {warm_ops_per_sec:.0f} req/sec")
    print(f"  Performance Speedup:   {speedup:.1f}x faster with ScanCache!\n")

    # 4. Cache Operational Telemetry
    metrics = fw.cache.get_metrics()
    print("3. Cache Operational Telemetry:")
    print(f"  Cache Size:            {metrics.size} / {metrics.max_size}")
    print(f"  Cache Hits:            {metrics.hits}")
    print(f"  Cache Misses:          {metrics.misses}")
    print(f"  Cache Hit Ratio:       {metrics.hit_ratio * 100:.2f}%")
    print(f"  Cache Evictions:       {metrics.evictions}")
    print("\n=== Benchmark Completed Successfully ===")


if __name__ == "__main__":
    run_benchmark()
