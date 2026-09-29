"""Performance benchmarks for Phase 34: AI Asset Inventory & Discovery.

Evaluates throughput, memory overhead, and scaling characteristics for:
- Asset Normalization & Deterministic Fingerprinting
- Multi-Source Deduplication & Provenance Merging
- Indexed Lookup & Attribute-Filtered Search
- Baseline Snapshot Generation (SHA-256 canonical hashing)
- Architectural Diff & Drift Detection
- Snapshot Serialization
"""

import gc
import io
import json
import os
import resource
import time
from typing import Any, Dict, List

from llmfirewall.audit import AuditLogger
from llmfirewall.inventory import (
    Asset,
    AssetInventory,
    AssetProvenance,
    AssetSource,
    AssetStatus,
    AssetType,
    DiscoveryConfidence,
    InventorySnapshot,
    normalize_asset_id,
)

# Silent audit logger to prevent console I/O bottleneck
silent_audit = AuditLogger(sink=io.StringIO())


def get_memory_usage_mb() -> float:
    """Return max RSS in megabytes."""
    usage = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    if os.uname().sysname == "Darwin":
        return usage / (1024.0 * 1024.0)
    return usage / 1024.0


def benchmark_inventory_scale(num_assets: int) -> Dict[str, Any]:
    """Benchmark inventory performance and memory at a given scale."""
    gc.collect()
    mem_before = get_memory_usage_mb()
    inv = AssetInventory(max_assets=num_assets * 2, audit_logger=silent_audit)

    types = [
        AssetType.AGENT.value,
        AssetType.MODEL.value,
        AssetType.TOOL.value,
        AssetType.SECURITY_CONTROL.value,
        AssetType.RAG_SOURCE.value,
        AssetType.PACKAGE.value,
    ]
    envs = ["development", "testing", "staging", "production"]

    # 1. Normalization & Registration Throughput
    t0 = time.perf_counter()
    for i in range(num_assets):
        a_type = types[i % len(types)]
        a_env = envs[i % len(envs)]
        raw_name = f"Component-{i:06d}"
        asset = Asset(
            id=f"{a_type}:{raw_name.lower().replace('-', '_')}",
            type=a_type,
            name=f"Service Asset {i}",
            version=f"1.{i % 10}.0",
            environment=a_env,
            source=AssetSource.CONFIGURATION if i % 2 == 0 else AssetSource.RUNTIME,
            status=AssetStatus.ACTIVE,
            metadata={"cluster_id": f"c-{i % 50}", "tier": i % 4},
            tags=["ai", "core", a_env],
            confidence=DiscoveryConfidence.HIGH,
            provenance=[
                AssetProvenance(
                    source=AssetSource.CONFIGURATION,
                    provider_name="config_discovery",
                    reference=f"config_{i % 100}.yaml",
                )
            ],
        )
        inv.register(asset)
    reg_dur = time.perf_counter() - t0
    reg_rate = num_assets / reg_dur if reg_dur > 0 else 0.0

    # 2. Multi-Source Deduplication & Merge Throughput
    # Re-register half the assets from a different source (RUNTIME) with merged metadata
    num_dedup = min(num_assets, 10_000)
    t0 = time.perf_counter()
    for i in range(num_dedup):
        a_type = types[i % len(types)]
        raw_name = f"Component-{i:06d}"
        update_asset = Asset(
            id=f"{a_type}:{raw_name.lower().replace('-', '_')}",
            type=a_type,
            name=f"Service Asset {i}",
            version=f"1.{i % 10}.0",
            source=AssetSource.RUNTIME,
            metadata={"runtime_invocations": i * 10},
            tags=["runtime_observed"],
            provenance=[
                AssetProvenance(
                    source=AssetSource.RUNTIME,
                    provider_name="runtime_discovery",
                    reference="events.log",
                )
            ],
        )
        inv.register(update_asset)
    dedup_dur = time.perf_counter() - t0
    dedup_rate = num_dedup / dedup_dur if dedup_dur > 0 else 0.0

    # 3. Memory Measurement
    mem_after = get_memory_usage_mb()
    inventory_mem_mb = max(0.0, mem_after - mem_before)

    # 4. Point Lookup Throughput (1,000 lookups)
    lookup_samples = min(1_000, num_assets)
    t0 = time.perf_counter()
    hits = 0
    for i in range(lookup_samples):
        a_type = types[i % len(types)]
        raw_name = f"Component-{i:06d}"
        cid = f"{a_type}:{raw_name.lower().replace('-', '_')}"
        if inv.get(cid) is not None:
            hits += 1
    lookup_dur = time.perf_counter() - t0
    lookup_rate = lookup_samples / lookup_dur if lookup_dur > 0 else 0.0

    # 5. Filtered List Search
    t0 = time.perf_counter()
    prod_assets = inv.list_assets(environment="production")
    query_dur_ms = (time.perf_counter() - t0) * 1000.0

    # 6. Snapshot Generation (SHA-256 Canonical Hashing)
    t0 = time.perf_counter()
    snap1 = inv.snapshot()
    snap_dur_ms = (time.perf_counter() - t0) * 1000.0

    # 7. Baseline Diff & Drift Detection
    # Make small modification for realistic diff
    inv.remove(f"{types[0]}:component_000000")
    inv.register(Asset(id=f"{types[1]}:brand_new_component", type=types[1], name="New Component"))
    snap2 = inv.snapshot()

    t0 = time.perf_counter()
    diff = AssetInventory.diff(snap1, snap2)
    diff_dur_ms = (time.perf_counter() - t0) * 1000.0

    # 8. Serialization Throughput
    t0 = time.perf_counter()
    json_bytes = len(snap2.to_json(indent=0).encode("utf-8"))
    json_dur_ms = (time.perf_counter() - t0) * 1000.0

    return {
        "num_assets": num_assets,
        "registration_rate_per_sec": round(reg_rate, 1),
        "dedup_merge_rate_per_sec": round(dedup_rate, 1),
        "lookup_rate_per_sec": round(lookup_rate, 1),
        "query_prod_duration_ms": round(query_dur_ms, 2),
        "snapshot_duration_ms": round(snap_dur_ms, 2),
        "diff_duration_ms": round(diff_dur_ms, 2),
        "json_serialization_ms": round(json_dur_ms, 2),
        "json_size_mb": round(json_bytes / (1024.0 * 1024.0), 2),
        "memory_overhead_mb": round(inventory_mem_mb, 2),
    }


def run_all_benchmarks() -> List[Dict[str, Any]]:
    """Execute inventory benchmarks across standard scales: 1K, 10K, and 50K."""
    scales = [1_000, 10_000, 50_000]
    results = []

    print("================================================================================")
    print("           LLMFirewall Phase 34: AI Asset Inventory Benchmarks                  ")
    print("================================================================================")
    print(f"{'Scale':<10} | {'Reg Rate':<12} | {'Dedup Rate':<12} | {'Lookup Rate':<12} | {'Snap (ms)':<10} | {'Diff (ms)':<10} | {'Mem (MB)':<8}")
    print("-" * 88)

    for scale in scales:
        metrics = benchmark_inventory_scale(scale)
        results.append(metrics)
        print(
            f"{metrics['num_assets']:<10} | "
            f"{metrics['registration_rate_per_sec']:>10.1f}/s | "
            f"{metrics['dedup_merge_rate_per_sec']:>10.1f}/s | "
            f"{metrics['lookup_rate_per_sec']:>10.1f}/s | "
            f"{metrics['snapshot_duration_ms']:>8.2f}ms | "
            f"{metrics['diff_duration_ms']:>8.2f}ms | "
            f"{metrics['memory_overhead_mb']:>6.1f}MB"
        )

    print("================================================================================")
    return results


if __name__ == "__main__":
    run_all_benchmarks()
