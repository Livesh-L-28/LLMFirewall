"""Performance benchmarks for Phase 32: AI Security Knowledge Graph."""

import gc
import io
import os
import resource
import time
from typing import Dict, Any

from llmfirewall.audit import AuditLogger
from llmfirewall.graph import (
    KnowledgeGraph,
    InMemoryGraphStore,
    NodeType,
    RelationshipType,
)

# Silent audit logger to benchmark engine logic without console I/O bottleneck
silent_audit = AuditLogger(sink=io.StringIO())


def get_memory_usage_mb() -> float:
    """Return max RSS in megabytes."""
    usage = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    if os.uname().sysname == "Darwin":
        return usage / (1024.0 * 1024.0)
    return usage / 1024.0


def benchmark_graph_scale(num_nodes: int, num_edges_factor: int = 2) -> Dict[str, Any]:
    """Benchmark knowledge graph performance and memory at a given scale."""
    gc.collect()
    mem_before = get_memory_usage_mb()
    kg = KnowledgeGraph(audit_logger=silent_audit, max_nodes=num_nodes * 2, max_relationships=num_nodes * num_edges_factor * 2)

    # 1. Node Insertion
    t0 = time.perf_counter()
    for i in range(num_nodes):
        ntype = NodeType.AGENT.value if i % 4 == 0 else (
            NodeType.TOOL.value if i % 4 == 1 else (
                NodeType.MODEL.value if i % 4 == 2 else NodeType.SECURITY_CONTROL.value
            )
        )
        kg.add_node(f"node:{i}", node_type=ntype, properties={"idx": i, "env": "prod"})
    node_insert_time = time.perf_counter() - t0
    node_rate = num_nodes / node_insert_time if node_insert_time > 0 else 0.0

    # 2. Relationship Insertion
    num_edges = num_nodes * num_edges_factor
    t0 = time.perf_counter()
    for i in range(num_edges):
        src = f"node:{i % num_nodes}"
        tgt = f"node:{(i * 7 + 1) % num_nodes}"
        if src != tgt:
            rel_type = RelationshipType.CAN_CALL.value if i % 3 == 0 else (
                RelationshipType.PROTECTS.value if i % 3 == 1 else RelationshipType.USES.value
            )
            try:
                kg.add_relationship(src, rel_type, tgt)
            except Exception:
                pass
    actual_edges = kg.store.relationship_count()
    edge_insert_time = time.perf_counter() - t0
    edge_rate = actual_edges / edge_insert_time if edge_insert_time > 0 else 0.0

    # Memory after loading graph
    mem_after = get_memory_usage_mb()
    graph_mem_mb = max(0.0, mem_after - mem_before)

    # 3. Node Lookup (1,000 random point lookups)
    lookup_count = 1000
    t0 = time.perf_counter()
    for i in range(lookup_count):
        nid = f"node:{(i * 37) % num_nodes}"
        _ = kg.get_node(nid)
    lookup_time = time.perf_counter() - t0
    avg_lookup_us = (lookup_time / lookup_count) * 1_000_000.0

    # 4. Path Search (bounded BFS traversal, 50 queries)
    path_count = 50
    t0 = time.perf_counter()
    for i in range(path_count):
        src = f"node:{(i * 13) % num_nodes}"
        tgt = f"node:{(i * 13 + 5) % num_nodes}"
        _ = kg.find_path(src, tgt, max_depth=4)
    path_time = time.perf_counter() - t0
    avg_path_ms = (path_time / path_count) * 1000.0

    # 5. Security Impact Analysis (50 queries)
    impact_count = 50
    t0 = time.perf_counter()
    for i in range(impact_count):
        target_id = f"node:{(i * 29) % num_nodes}"
        _ = kg.security_impact(target_id, max_depth=2)
    impact_time = time.perf_counter() - t0
    avg_impact_ms = (impact_time / impact_count) * 1000.0

    # 6. Blast Radius (50 queries)
    blast_count = 50
    t0 = time.perf_counter()
    for i in range(blast_count):
        target_id = f"node:{(i * 31) % num_nodes}"
        _ = kg.blast_radius(target_id, max_depth=3)
    blast_time = time.perf_counter() - t0
    avg_blast_ms = (blast_time / blast_count) * 1000.0

    # 7. Snapshot & Deterministic Hashing
    t0 = time.perf_counter()
    snap = kg.snapshot()
    snap_time = time.perf_counter() - t0

    return {
        "num_nodes": num_nodes,
        "num_edges": actual_edges,
        "node_insert_rate": round(node_rate, 1),
        "edge_insert_rate": round(edge_rate, 1),
        "avg_lookup_us": round(avg_lookup_us, 2),
        "avg_path_ms": round(avg_path_ms, 3),
        "avg_impact_ms": round(avg_impact_ms, 3),
        "avg_blast_ms": round(avg_blast_ms, 3),
        "snapshot_ms": round(snap_time * 1000.0, 2),
        "hash_prefix": snap.graph_hash[:16],
        "delta_rss_mb": round(graph_mem_mb, 2),
        "total_rss_mb": round(mem_after, 2),
    }


def main():
    print("=" * 70)
    print(" LLMFirewall Phase 32 — AI Security Knowledge Graph Benchmarks")
    print("=" * 70)

    scales = [1_000, 10_000, 50_000]

    for scale in scales:
        print(f"\n--- Benchmarking Scale: {scale:,} Nodes ---")
        res = benchmark_graph_scale(scale, num_edges_factor=2)
        print(f"  Nodes: {res['num_nodes']:,} | Relationships: {res['num_edges']:,}")
        print(f"  Node Insertion:         {res['node_insert_rate']:,} nodes/sec")
        print(f"  Relationship Insertion: {res['edge_insert_rate']:,} edges/sec")
        print(f"  Point Lookup Latency:   {res['avg_lookup_us']:.2f} µs/lookup")
        print(f"  Path Search (BFS d=4):  {res['avg_path_ms']:.3f} ms/query")
        print(f"  Security Impact Query:  {res['avg_impact_ms']:.3f} ms/query")
        print(f"  Blast Radius Query:     {res['avg_blast_ms']:.3f} ms/query")
        print(f"  Snapshot & SHA-256:     {res['snapshot_ms']:.2f} ms (Digest: {res['hash_prefix']}...)")
        print(f"  Memory Footprint:       +{res['delta_rss_mb']:.2f} MB RSS (Total: {res['total_rss_mb']:.2f} MB)")

    print("\n" + "=" * 70)
    print(" Benchmark Completed Successfully.")
    print("=" * 70)


if __name__ == "__main__":
    main()
