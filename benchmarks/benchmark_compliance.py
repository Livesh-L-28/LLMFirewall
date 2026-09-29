"""Performance benchmarks for Phase 36: AI Security Compliance & Control Mapping.

Evaluates throughput, memory overhead, and scaling characteristics at:
- 100 controls
- 1,000 controls
- 10,000 controls
and realistic asset counts.

Measures:
1. Framework loading & catalog indexing
2. Control mapping registration
3. Evidence resolution & gathering
4. Control assessment throughput
5. Tamper-evident snapshot creation (SHA-256 canonical hashing)
6. Snapshot diffing & regression detection
7. Human report & JSON generation
"""

import gc
import io
import json
import os
from pathlib import Path
import resource
import time
from typing import Any, Dict, List

from llmfirewall.audit import AuditLogger
from llmfirewall.compliance import (
    ApplicabilityStatus,
    ComplianceControl,
    ComplianceDiff,
    ComplianceEngine,
    ComplianceEvidence,
    ComplianceFramework,
    ComplianceSnapshot,
    ControlAssessment,
    ControlCatalog,
    ControlMapping,
    ControlState,
    EvidenceType,
    EvidenceValidity,
    format_compliance_human,
    format_compliance_json,
    format_control_detail_human,
    format_diff_human,
)
from llmfirewall.inventory import (
    Asset,
    AssetInventory,
    AssetType,
)

silent_audit = AuditLogger(sink=io.StringIO())


def get_memory_usage_mb() -> float:
    """Return max RSS in megabytes."""
    usage = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    if os.uname().sysname == "Darwin":
        return usage / (1024.0 * 1024.0)
    return usage / 1024.0


def benchmark_compliance_scale(num_controls: int, num_assets: int = 50) -> Dict[str, Any]:
    """Benchmark compliance engine at specified control scale."""
    gc.collect()
    mem_before = get_memory_usage_mb()

    # 1. Framework Loading & Catalog Indexing
    t0 = time.perf_counter()
    catalog = ControlCatalog()

    controls_dict: Dict[str, ComplianceControl] = {}
    categories = ["access_control", "prompt_security", "tool_security", "model_security", "rag_security", "data_security", "monitoring"]
    domains = ["Access Control", "Prompt Security", "Tool Security", "Model Security", "RAG Security", "Data Protection", "Monitoring"]

    for i in range(num_controls):
        cid = f"CTRL-{i:05d}"
        full_id = f"bench-fw:{cid}"
        idx = i % len(categories)
        ctrl = ComplianceControl(
            id=full_id,
            framework_id="bench-fw",
            control_id=cid,
            title=f"Benchmark Control {i}",
            category=categories[idx],
            domain=domains[idx],
            requirements=[f"Requirement {i}.A", f"Requirement {i}.B"],
            evidence_requirements=["configuration", "security_test"],
            applicability={"asset_types": ["agent", "tool", "application"]},
        )
        controls_dict[full_id] = ctrl

    fw = ComplianceFramework(
        id="bench-fw",
        name="Benchmark Framework",
        version="1.0.0",
        domains=domains,
        controls=controls_dict,
    )
    catalog.register_framework(fw)
    t_load = (time.perf_counter() - t0) * 1000.0  # ms

    # Pre-populate inventory
    inv = AssetInventory(audit_logger=silent_audit)
    for a in range(num_assets):
        aid = f"agent:agent_{a:04d}"
        inv.register(Asset(id=aid, type=AssetType.AGENT, name=f"Agent {a}", environment="production"))

    engine = ComplianceEngine(catalog=catalog, inventory=inv, audit_logger=silent_audit)

    # 2. Control Mapping Registration
    t0 = time.perf_counter()
    for i in range(min(num_controls, 1000)):
        engine.add_mapping(ControlMapping(
            control_id=f"bench-fw:CTRL-{i:05d}",
            security_control_id=f"guardrail_{i % 10}",
            rationale="Automated control mapping",
        ))
    t_mapping = (time.perf_counter() - t0) * 1000.0

    # 3. Evidence Resolution & Ingestion
    t0 = time.perf_counter()
    now = time.time()
    for a in range(min(num_assets, 20)):
        aid = f"agent:agent_{a:04d}"
        for i in range(min(num_controls, 50)):
            cid = f"bench-fw:CTRL-{i:05d}"
            engine.add_evidence(ComplianceEvidence(
                type=EvidenceType.SECURITY_TEST,
                source="bench_test_suite",
                asset_id=aid,
                control_id=cid,
                collected_at=now,
                content_reference=f"test_run:{i}:{a}",
                status=EvidenceValidity.VALID,
            ))
    t_evidence = (time.perf_counter() - t0) * 1000.0

    # 4. Assessment Throughput (Asset Assessment)
    target_aid = "agent:agent_0000"
    t0 = time.perf_counter()
    assessments = engine.assess_asset(target_aid, framework_id="bench-fw")
    t_assess = (time.perf_counter() - t0) * 1000.0
    assess_ops_sec = (len(assessments) / (t_assess / 1000.0)) if t_assess > 0 else 0.0

    # 5. Snapshot Creation (Canonical SHA-256 Digest)
    t0 = time.perf_counter()
    # Take snapshot over single target asset to ensure deterministic scale benchmark
    snap1 = engine.snapshot(framework_id="bench-fw")
    t_snapshot = (time.perf_counter() - t0) * 1000.0

    # 6. Diff & Regression Analysis
    # Create altered snapshot
    engine2 = ComplianceEngine(catalog=catalog, inventory=inv, audit_logger=silent_audit)
    snap2 = engine2.snapshot(framework_id="bench-fw")
    t0 = time.perf_counter()
    diff_res = engine.diff(snap1, snap2)
    t_diff = (time.perf_counter() - t0) * 1000.0

    # 7. Report Generation
    t0 = time.perf_counter()
    human_rep = format_compliance_human(assessments[:100], framework_name="Benchmark Framework", framework_version="1.0.0")
    json_rep = format_compliance_json(assessments[:100])
    t_report = (time.perf_counter() - t0) * 1000.0

    gc.collect()
    mem_after = get_memory_usage_mb()

    return {
        "num_controls": num_controls,
        "num_assets": num_assets,
        "framework_loading_ms": round(t_load, 2),
        "control_mapping_ms": round(t_mapping, 2),
        "evidence_ingestion_ms": round(t_evidence, 2),
        "asset_assessment_ms": round(t_assess, 2),
        "assessment_throughput_controls_per_sec": round(assess_ops_sec, 1),
        "snapshot_creation_ms": round(t_snapshot, 2),
        "snapshot_diff_ms": round(t_diff, 2),
        "report_generation_ms": round(t_report, 2),
        "memory_overhead_mb": round(max(0.0, mem_after - mem_before), 2),
    }


def run_all_compliance_benchmarks() -> None:
    scales = [100, 1000, 10000]
    results = []

    print("=" * 80)
    print("PHASE 36: AI SECURITY COMPLIANCE & CONTROL MAPPING BENCHMARK SUITE")
    print("=" * 80)

    for n in scales:
        print(f"Running benchmark for {n:,} controls...")
        res = benchmark_compliance_scale(n, num_assets=50)
        results.append(res)
        print(
            f"  Controls: {n:,} | Framework Load: {res['framework_loading_ms']}ms | "
            f"Assess: {res['asset_assessment_ms']}ms ({res['assessment_throughput_controls_per_sec']} ctrl/s) | "
            f"Snapshot: {res['snapshot_creation_ms']}ms | Diff: {res['snapshot_diff_ms']}ms | "
            f"Mem: {res['memory_overhead_mb']}MB"
        )

    out_path = Path(__file__).parent / "benchmark_compliance_results.json"
    out_path.write_text(json.dumps(results, indent=2), encoding="utf-8")
    print(f"\nBenchmark results saved to: {out_path}")
    print("=" * 80)


if __name__ == "__main__":
    run_all_compliance_benchmarks()
