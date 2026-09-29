"""Performance benchmarks for Phase 35: AI Security Posture Management (AI-SPM).

Evaluates throughput, memory overhead, and scaling characteristics for:
- Full Posture Evaluation
- Incremental Posture Evaluation (graph dependent tracking)
- Baseline Snapshot Generation (SHA-256 canonical hashing)
- Posture Diff & Regression Analysis
- Human & JSON Report Generation
"""

import gc
import io
import json
import os
import resource
import time
from typing import Any, Dict, List

from llmfirewall.audit import AuditLogger
from llmfirewall.graph import KnowledgeGraph, Node, NodeType, Relationship, RelationshipType
from llmfirewall.inventory import (
    Asset,
    AssetInventory,
    AssetSource,
    AssetStatus,
    AssetType,
)
from llmfirewall.spm import (
    PostureEngine,
    PostureSnapshot,
    format_posture_diff_human,
    format_posture_human,
    format_posture_json,
    format_posture_summary_human,
)

silent_audit = AuditLogger(sink=io.StringIO())


def get_memory_usage_mb() -> float:
    """Return max RSS in megabytes."""
    usage = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    if os.uname().sysname == "Darwin":
        return usage / (1024.0 * 1024.0)
    return usage / 1024.0


def benchmark_spm_scale(num_assets: int) -> Dict[str, Any]:
    """Benchmark AI-SPM performance and memory at a given scale."""
    gc.collect()
    mem_before = get_memory_usage_mb()

    kg = KnowledgeGraph(max_nodes=num_assets * 3, max_relationships=num_assets * 4, audit_logger=silent_audit)
    inv = AssetInventory(kg=kg, max_assets=num_assets * 2, audit_logger=silent_audit)
    engine = PostureEngine(inventory=inv, kg=kg, audit_logger=silent_audit, max_assets=num_assets * 2)

    # Pre-populate assets and graph connections
    # We create Agents, Tools, Models, Controls, RAG Sources
    num_agents = max(1, num_assets // 5)
    num_tools = max(1, num_assets // 5)
    num_models = max(1, num_assets // 10)
    num_controls = max(1, num_assets // 10)
    num_rag = num_assets - (num_agents + num_tools + num_models + num_controls)

    # 1. Asset Population
    t_pop_start = time.perf_counter()

    for i in range(num_agents):
        aid = f"agent:agent_{i:05d}"
        inv.register(Asset(id=aid, type=AssetType.AGENT, name=f"Agent {i}", environment="production"))
        kg.add_node(Node(id=aid, type=NodeType.AGENT.value))

    for i in range(num_tools):
        tid = f"tool:tool_{i:05d}"
        inv.register(Asset(id=tid, type=AssetType.TOOL, name=f"Tool {i}", environment="production"))
        kg.add_node(Node(id=tid, type=NodeType.TOOL.value))

    for i in range(num_models):
        mid = f"model:model_{i:05d}"
        inv.register(Asset(id=mid, type=AssetType.MODEL, name=f"Model {i}", environment="production"))
        kg.add_node(Node(id=mid, type=NodeType.MODEL.value))

    for i in range(num_controls):
        cid = f"control:ctrl_{i:05d}"
        inv.register(Asset(id=cid, type=AssetType.SECURITY_CONTROL, name=f"Control {i}", environment="production"))
        kg.add_node(Node(id=cid, type=NodeType.SECURITY_CONTROL.value))

    for i in range(num_rag):
        rid = f"rag_source:rag_{i:05d}"
        inv.register(Asset(id=rid, type=AssetType.RAG_SOURCE, name=f"RAG {i}", environment="production"))
        kg.add_node(Node(id=rid, type=NodeType.RAG_SOURCE.value))

    # Add edges
    for i in range(num_agents):
        aid = f"agent:agent_{i:05d}"
        mid = f"model:model_{i % num_models:05d}"
        tid = f"tool:tool_{i % num_tools:05d}"
        cid = f"control:ctrl_{i % num_controls:05d}"
        kg.add_relationship(Relationship(source=aid, type=RelationshipType.USES.value, target=mid))
        kg.add_relationship(Relationship(source=aid, type=RelationshipType.CAN_CALL.value, target=tid))
        kg.add_relationship(Relationship(source=cid, type=RelationshipType.PROTECTS.value, target=tid))

    t_pop = time.perf_counter() - t_pop_start

    # 2. Full Posture Evaluation
    t0 = time.perf_counter()
    postures = engine.evaluate_all()
    t_eval = time.perf_counter() - t0
    eval_throughput = num_assets / t_eval if t_eval > 0 else float("inf")

    # 3. Incremental Evaluation
    # Simulate a single tool change
    changed_tool = "tool:tool_00000"
    t0 = time.perf_counter()
    re_eval = engine.incremental_evaluate([changed_tool])
    t_incremental = time.perf_counter() - t0

    # 4. Snapshot Creation & SHA-256 Hashing
    t0 = time.perf_counter()
    snap1 = engine.snapshot(posture_version="1.0")
    t_snapshot = time.perf_counter() - t0

    # 5. Posture Diff
    # Change a control state and capture snap2
    engine.ingest_test_results(changed_tool, [
        {"target": "control:ctrl_00000", "passed": False, "timestamp": time.time() + 10}
    ])
    snap2 = engine.snapshot(posture_version="2.0")
    t0 = time.perf_counter()
    diff = PostureEngine.diff(snap1, snap2)
    t_diff = time.perf_counter() - t0

    # 6. Report Generation Throughput
    t0 = time.perf_counter()
    sum_data = engine.summary()
    rep_human = format_posture_summary_human(sum_data)
    rep_json = format_posture_json(sum_data)
    rep_diff = format_posture_diff_human(diff)
    t_report = time.perf_counter() - t0

    mem_after = get_memory_usage_mb()
    mem_overhead = mem_after - mem_before

    return {
        "num_assets": num_assets,
        "population_time_sec": round(t_pop, 4),
        "full_evaluation_sec": round(t_eval, 4),
        "evaluation_throughput_assets_per_sec": round(eval_throughput, 1),
        "incremental_evaluation_ms": round(t_incremental * 1000.0, 3),
        "incremental_assets_count": len(re_eval),
        "snapshot_creation_ms": round(t_snapshot * 1000.0, 3),
        "diff_evaluation_ms": round(t_diff * 1000.0, 3),
        "report_generation_ms": round(t_report * 1000.0, 3),
        "memory_overhead_mb": round(mem_overhead, 2),
        "snapshot_hash": snap1.snapshot_hash[:16] + "...",
    }


def main():
    print("=" * 80)
    print("LLMFirewall Phase 35: AI-SPM Performance & Scalability Benchmarks")
    print("=" * 80)

    scales = [1_000, 10_000, 50_000]
    results = []

    for n in scales:
        print(f"\n[*] Benchmarking scale: {n:,} assets...")
        res = benchmark_spm_scale(n)
        results.append(res)
        print(f"    - Full Evaluation:       {res['full_evaluation_sec']} s ({res['evaluation_throughput_assets_per_sec']:,} assets/sec)")
        print(f"    - Incremental Eval:      {res['incremental_evaluation_ms']} ms ({res['incremental_assets_count']} dependent assets)")
        print(f"    - Snapshot (SHA-256):    {res['snapshot_creation_ms']} ms")
        print(f"    - Diff & Regressions:    {res['diff_evaluation_ms']} ms")
        print(f"    - Report Formatting:     {res['report_generation_ms']} ms")
        print(f"    - Memory Overhead:       {res['memory_overhead_mb']} MB")

    out_file = "benchmarks/benchmark_spm_results.json"
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)
    print(f"\n[+] Detailed benchmark results saved to: {out_file}\n")


if __name__ == "__main__":
    main()
