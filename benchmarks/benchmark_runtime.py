"""Performance benchmark comparing agent runtime with and without LLMFirewall.

Phase 26: LLM & Agent Runtime Protection.
Measures:
- Latency (P50, P95, P99)
- Agent reasoning loops per second
- Memory and firewall overhead breakdown
"""

import gc
import statistics
import time
from typing import Any, Dict, List

from llmfirewall import Firewall, RuntimeContext


def mock_agent_loop_baseline(iterations: int = 5) -> str:
    """Agent execution simulation WITHOUT firewall protection."""
    for i in range(iterations):
        # Simulating light local mock processing (e.g. calculator or search step)
        _ = {"tool": "calc", "res": i * 42}
    return "Agent completed task."


def mock_agent_loop_guarded(firewall: Firewall, iterations: int = 5) -> str:
    """Agent execution simulation WITH LLMFirewall runtime protection."""
    with firewall.runtime.session(context=RuntimeContext(user_id="bench-user")) as session:
        session.check_user_input("Please solve calculation steps.")
        for i in range(iterations):
            session.step_iteration()
            session.check_tool_call("calc", arguments={"step": i, "x": 10})
            session.check_tool_result("calc", output=f"Step {i} evaluated to {i * 42}")
        return session.finalize("Agent completed task.").sanitized_text or "Done"


def run_benchmark(num_runs: int = 200) -> Dict[str, Any]:
    firewall = Firewall()

    # Warmup
    for _ in range(10):
        mock_agent_loop_baseline()
        mock_agent_loop_guarded(firewall)

    baseline_times: List[float] = []
    guarded_times: List[float] = []

    gc.disable()
    try:
        for _ in range(num_runs):
            t0 = time.perf_counter()
            mock_agent_loop_baseline(iterations=5)
            t1 = time.perf_counter()
            baseline_times.append((t1 - t0) * 1000.0)

            t2 = time.perf_counter()
            mock_agent_loop_guarded(firewall, iterations=5)
            t3 = time.perf_counter()
            guarded_times.append((t3 - t2) * 1000.0)
    finally:
        gc.enable()

    def calc_stats(times: List[float]) -> Dict[str, float]:
        sorted_times = sorted(times)
        p50 = statistics.median(sorted_times)
        p95 = sorted_times[int(len(sorted_times) * 0.95)]
        p99 = sorted_times[int(len(sorted_times) * 0.99)]
        mean = statistics.mean(sorted_times)
        return {"p50": round(p50, 4), "p95": round(p95, 4), "p99": round(p99, 4), "mean": round(mean, 4)}

    base_stats = calc_stats(baseline_times)
    guard_stats = calc_stats(guarded_times)
    overhead_ms = round(guard_stats["mean"] - base_stats["mean"], 4)

    return {
        "num_runs": num_runs,
        "iterations_per_run": 5,
        "baseline_ms": base_stats,
        "guarded_ms": guard_stats,
        "average_firewall_overhead_ms": overhead_ms,
    }


if __name__ == "__main__":
    report = run_benchmark(200)
    print("==================================================")
    print("LLMFirewall Phase 26 — Agent Runtime Benchmark")
    print("==================================================")
    print(f"Total Runs: {report['num_runs']} | Iterations/Run: {report['iterations_per_run']}")
    print("Baseline (no firewall):")
    print(f"  P50: {report['baseline_ms']['p50']}ms | P95: {report['baseline_ms']['p95']}ms | P99: {report['baseline_ms']['p99']}ms")
    print("Guarded Runtime (full boundary inspection):")
    print(f"  P50: {report['guarded_ms']['p50']}ms | P95: {report['guarded_ms']['p95']}ms | P99: {report['guarded_ms']['p99']}ms")
    print(f"Net Firewall Overhead: {report['average_firewall_overhead_ms']}ms per full multi-turn agent cycle")
    print("==================================================")
