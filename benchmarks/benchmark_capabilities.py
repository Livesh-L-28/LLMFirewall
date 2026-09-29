"""Performance benchmarks for Phase 29: Agent Capability Security & Action Control."""

import time
from concurrent.futures import ThreadPoolExecutor

from llmfirewall import (
    ActionBudget,
    ActionRequest,
    BudgetManager,
    CapabilityEngine,
    CapabilityGrant,
    Firewall,
)


def benchmark_capability_authorization():
    print("--- 1. Capability Authorization Latency (Sequential) ---")
    engine = CapabilityEngine()
    engine.grant_capability("bench_agent", "filesystem.read", resource_scope=["./docs/*"])

    req = ActionRequest(
        agent_id="bench_agent",
        capability_name="filesystem.read",
        resource="./docs/faq.txt",
    )

    # Warmup
    for _ in range(100):
        engine.authorize_action(req)

    # 10,000 policy checks
    count = 10000
    latencies = []
    start = time.perf_counter()
    for _ in range(count):
        t0 = time.perf_counter()
        engine.authorize_action(req)
        latencies.append((time.perf_counter() - t0) * 1000.0)
    total_time = time.perf_counter() - start

    latencies.sort()
    p50 = latencies[int(count * 0.50)]
    p95 = latencies[int(count * 0.95)]
    p99 = latencies[int(count * 0.99)]
    throughput = count / total_time

    print(f"Executed {count:,} authorization checks in {total_time * 1000:.2f} ms")
    print(f"Throughput : {throughput:,.1f} checks/sec")
    print(f"Latency P50: {p50 * 1000:.2f} µs")
    print(f"Latency P95: {p95 * 1000:.2f} µs")
    print(f"Latency P99: {p99 * 1000:.2f} µs")


def benchmark_budget_reservation_concurrency():
    print("\n--- 2. Thread-Safe Budget Reservation Under High Concurrency ---")
    budget = ActionBudget(max_actions=10000)
    mgr = BudgetManager(budget=budget)
    engine = CapabilityEngine()
    engine.grant_capability("concurrent_agent", "filesystem.read")

    def execute_call(idx: int):
        req = ActionRequest(
            action_id=f"act-{idx}",
            agent_id="concurrent_agent",
            session_id=f"sess-{idx % 10}",
            capability_name="filesystem.read",
        )
        return engine.authorize_action(req, budget_manager=mgr)

    workers = 16
    total_tasks = 5000
    start = time.perf_counter()
    with ThreadPoolExecutor(max_workers=workers) as executor:
        results = list(executor.map(execute_call, range(total_tasks)))
    elapsed = time.perf_counter() - start

    allowed = sum(1 for r in results if r.is_allowed)
    print(f"Dispatched {total_tasks:,} concurrent requests across {workers} worker threads in {elapsed * 1000:.2f} ms")
    print(f"Allowed: {allowed:,} / {total_tasks:,} (Reserved actions in budget: {mgr.total_actions:,})")
    print(f"Concurrent throughput: {total_tasks / elapsed:,.1f} req/s")


def benchmark_firewall_authorize_action():
    print("\n--- 3. Top-Level Firewall.authorize_action() Overhead ---")
    fw = Firewall()
    fw.capability_engine.grant_capability("agent_x", "network.request")

    start = time.perf_counter()
    for _ in range(1000):
        fw.authorize_action("network.request", agent_id="agent_x", resource="https://api.example.com")
    elapsed = time.perf_counter() - start

    print(f"1,000 top-level Firewall.authorize_action() calls in {elapsed * 1000:.2f} ms ({elapsed / 1000 * 1000:.3f} ms/op)")


if __name__ == "__main__":
    print("=========================================================")
    print("LLMFirewall Phase 29: Capability Security & Action Control Benchmark")
    print("=========================================================")
    benchmark_capability_authorization()
    benchmark_budget_reservation_concurrency()
    benchmark_firewall_authorize_action()
    print("=========================================================")
