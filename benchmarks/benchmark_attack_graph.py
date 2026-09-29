"""Performance benchmarks for Phase 33: Attack Graph & AI Threat Modeling."""

import gc
import io
import json
import os
import resource
import time
from typing import Any, Dict

from llmfirewall.attack_graph import AttackGraph
from llmfirewall.audit import AuditLogger
from llmfirewall.graph import KnowledgeGraph, NodeType, RelationshipType

# Silent audit logger to benchmark logic without stdout I/O overhead
silent_audit = AuditLogger(sink=io.StringIO())


def get_memory_usage_mb() -> float:
    """Return max RSS in megabytes."""
    usage = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    if os.uname().sysname == "Darwin":
        return usage / (1024.0 * 1024.0)
    return usage / 1024.0


def benchmark_attack_graph_scale(num_nodes: int, num_edges_factor: int = 2) -> Dict[str, Any]:
    """Benchmark AttackGraph path discovery, threat modeling, and diffing at given scale."""
    gc.collect()
    mem_before = get_memory_usage_mb()

    kg = KnowledgeGraph(
        audit_logger=silent_audit,
        max_nodes=num_nodes * 2,
        max_relationships=num_nodes * num_edges_factor * 2,
    )

    # 1. Populate KnowledgeGraph
    t0 = time.perf_counter()
    for i in range(num_nodes):
        if i % 5 == 0:
            ntype = NodeType.APPLICATION.value
        elif i % 5 == 1:
            ntype = NodeType.AGENT.value
        elif i % 5 == 2:
            ntype = NodeType.TOOL.value
        elif i % 5 == 3:
            ntype = NodeType.MODEL.value
        else:
            ntype = NodeType.SECURITY_CONTROL.value

        props = {"idx": i, "env": "prod"}
        if ntype == NodeType.TOOL.value and i % 10 == 0:
            props["category"] = "database"

        kg.add_node(f"node:{i}", node_type=ntype, properties=props)

    # Connect relationships
    num_edges = num_nodes * num_edges_factor
    for i in range(num_edges):
        src = f"node:{i % num_nodes}"
        tgt = f"node:{(i * 7 + 1) % num_nodes}"
        if src != tgt:
            src_n = kg.get_node(src)
            tgt_n = kg.get_node(tgt)
            if src_n and tgt_n:
                if src_n.type == NodeType.APPLICATION.value and tgt_n.type == NodeType.AGENT.value:
                    rel_type = RelationshipType.USES.value
                elif src_n.type == NodeType.AGENT.value and tgt_n.type == NodeType.TOOL.value:
                    rel_type = RelationshipType.CAN_CALL.value
                elif src_n.type == NodeType.SECURITY_CONTROL.value and tgt_n.type == NodeType.TOOL.value:
                    rel_type = RelationshipType.PROTECTS.value
                else:
                    rel_type = RelationshipType.CALLS.value
                try:
                    kg.add_relationship(src, rel_type, tgt)
                except Exception:
                    pass

    setup_time = time.perf_counter() - t0
    mem_after_load = get_memory_usage_mb()

    ag = AttackGraph(kg=kg, audit_logger=silent_audit)

    # 2. Benchmark Bounded Attack Path Discovery
    query_count = 20
    t0 = time.perf_counter()
    paths_found_total = 0
    for q_idx in range(query_count):
        src_id = f"node:{(q_idx * 5) % num_nodes}"
        paths = ag.find_paths(source=src_id, max_depth=4, max_paths=25)
        paths_found_total += len(paths)
    path_discovery_duration = time.perf_counter() - t0
    avg_path_query_ms = (path_discovery_duration / query_count) * 1000.0

    # 3. Benchmark AI Threat Model Generation
    t0 = time.perf_counter()
    sample_agent_id = "node:1" if kg.get_node("node:1") else None
    tm = ag.generate_threat_model(asset_id=sample_agent_id, name=f"Scale Benchmark TM ({num_nodes})")
    tm_duration_ms = (time.perf_counter() - t0) * 1000.0

    # 4. Benchmark Snapshot & Diff
    t0 = time.perf_counter()
    snap1 = ag.snapshot()
    # Simulate adding an edge
    extra_tool = f"node:extra_tool_{num_nodes}"
    kg.add_node(extra_tool, NodeType.TOOL.value, properties={"category": "database"})
    if sample_agent_id:
        try:
            kg.add_relationship(sample_agent_id, RelationshipType.CAN_CALL.value, extra_tool)
        except Exception:
            pass
    snap2 = ag.snapshot()
    diff = AttackGraph.diff(snap1, snap2)
    diff_duration_ms = (time.perf_counter() - t0) * 1000.0

    # 5. Security Gap Extraction
    t0 = time.perf_counter()
    gaps = ag.extract_security_gaps()
    gap_duration_ms = (time.perf_counter() - t0) * 1000.0

    mem_end = get_memory_usage_mb()
    peak_rss_mb = mem_end - mem_before

    return {
        "nodes": num_nodes,
        "relationships": kg.store.relationship_count(),
        "setup_seconds": round(setup_time, 3),
        "path_queries_count": query_count,
        "total_paths_discovered": paths_found_total,
        "avg_path_query_ms": round(avg_path_query_ms, 3),
        "threat_model_gen_ms": round(tm_duration_ms, 3),
        "snapshot_diff_ms": round(diff_duration_ms, 3),
        "security_gap_analysis_ms": round(gap_duration_ms, 3),
        "peak_rss_mb": round(peak_rss_mb, 2),
    }


def run_benchmarks() -> None:
    """Run Phase 33 Attack Graph benchmarks across 1K, 10K, and 50K scales."""
    scales = [1000, 10000, 50000]
    results = []

    print("\n" + "=" * 80)
    print(" PHASE 33: ATTACK GRAPH & AI THREAT MODELING BENCHMARK")
    print("=" * 80)
    print(f"{'Nodes':<8} | {'Edges':<8} | {'Avg Path (ms)':<14} | {'TM Gen (ms)':<12} | {'Diff (ms)':<10} | {'Peak RSS (MB)':<12}")
    print("-" * 80)

    for scale in scales:
        res = benchmark_attack_graph_scale(scale)
        results.append(res)
        print(
            f"{res['nodes']:<8} | "
            f"{res['relationships']:<8} | "
            f"{res['avg_path_query_ms']:<14.3f} | "
            f"{res['threat_model_gen_ms']:<12.3f} | "
            f"{res['snapshot_diff_ms']:<10.3f} | "
            f"{res['peak_rss_mb']:<12.2f}"
        )

    print("=" * 80 + "\n")


if __name__ == "__main__":
    run_benchmarks()
