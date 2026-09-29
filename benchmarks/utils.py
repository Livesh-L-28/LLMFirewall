"""Shared profiling, measurement, and statistical utilities for LLMFirewall benchmarks."""

import os
import platform
import sys
import time
import tracemalloc
from typing import Any, Callable, Dict, List, Optional, Tuple

import psutil
from llmfirewall._version import __version__


def get_system_environment() -> Dict[str, Any]:
    """Retrieve verified hardware and runtime environment details."""
    mem = psutil.virtual_memory()
    return {
        "python_version": sys.version.split()[0],
        "llmfirewall_version": __version__,
        "platform": platform.platform(),
        "processor": platform.processor() or platform.machine(),
        "cpu_count_logical": psutil.cpu_count(logical=True),
        "cpu_count_physical": psutil.cpu_count(logical=False),
        "total_memory_gb": round(mem.total / (1024 ** 3), 2),
    }


def compute_statistics(latencies_ms: List[float]) -> Dict[str, float]:
    """Compute min, median, mean, p95, p99, and max latencies in milliseconds."""
    if not latencies_ms:
        return {"min": 0.0, "median": 0.0, "mean": 0.0, "p95": 0.0, "p99": 0.0, "max": 0.0}

    sorted_vals = sorted(latencies_ms)
    n = len(sorted_vals)

    def percentile(p: float) -> float:
        k = (n - 1) * p
        f = int(k)
        c = f + 1
        if c < n:
            d = k - f
            return sorted_vals[f] * (1 - d) + sorted_vals[c] * d
        return sorted_vals[-1]

    return {
        "min": round(sorted_vals[0], 4),
        "median": round(percentile(0.50), 4),
        "mean": round(sum(sorted_vals) / n, 4),
        "p95": round(percentile(0.95), 4),
        "p99": round(percentile(0.99), 4),
        "max": round(sorted_vals[-1], 4),
    }


def measure_latency_and_throughput(
    func: Callable[[], Any],
    iterations: int = 200,
    warmup: int = 20,
    payload_bytes: int = 0,
) -> Tuple[Dict[str, float], float, float]:
    """Execute warmup and timed iterations, returning statistics, throughput (ops/sec), and MB/sec.
    
    Returns:
        (stats_dict, ops_per_sec, mb_per_sec)
    """
    # 1. Warmup
    for _ in range(warmup):
        func()

    # 2. Timed measurement
    latencies_ms: List[float] = []
    total_start = time.perf_counter()

    for _ in range(iterations):
        t0 = time.perf_counter()
        func()
        t1 = time.perf_counter()
        latencies_ms.append((t1 - t0) * 1000.0)

    total_elapsed_sec = time.perf_counter() - total_start
    stats = compute_statistics(latencies_ms)

    ops_per_sec = round(iterations / total_elapsed_sec, 2)
    mb_per_sec = round((payload_bytes * iterations) / (total_elapsed_sec * 1024 * 1024), 2) if payload_bytes else 0.0

    return stats, ops_per_sec, mb_per_sec


def measure_memory_peak(func: Callable[[], Any], iterations: int = 100) -> Dict[str, float]:
    """Measure peak heap memory allocation using tracemalloc during iterations."""
    tracemalloc.start()
    tracemalloc.reset_peak()

    for _ in range(iterations):
        func()

    current_bytes, peak_bytes = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    return {
        "current_kb": round(current_bytes / 1024.0, 2),
        "peak_kb": round(peak_bytes / 1024.0, 2),
    }
