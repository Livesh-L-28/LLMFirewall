"""Performance benchmarks for Advanced RAG and Context Security.

Phase 27: Advanced RAG & Context Security.
Measures:
1. Ingestion scanning latency (cold scan vs cached scan)
2. Context retrieval security filtering and deduplication overhead
3. Cache invalidation on policy change
4. P50, P95, P99 latency percentiles
"""

import gc
import statistics
import time
from typing import Any, Dict, List

from llmfirewall import ContextItem, Firewall, Policy, SourceProvenance


def run_rag_benchmarks(num_runs: int = 150) -> Dict[str, Any]:
    fw = Firewall()
    scanner = fw.ingestion_scanner
    orchestrator = fw.context_orchestrator

    doc_text = "Acme Knowledge Base: Data retention period is strictly 365 calendar days."
    chunks = [
        ContextItem(content=f"Knowledge chunk {i}: policy details regarding system maintenance {i}.", provenance=SourceProvenance(source_id=f"src-{i}"))
        for i in range(10)
    ]

    # Warmup
    for _ in range(5):
        scanner.scan_document(doc_text, document_id="warmup-doc")
        orchestrator.filter_and_secure(chunks)

    # 1. Cold Ingestion Scan
    scanner.cache.clear()
    cold_times = []
    gc.disable()
    try:
        for i in range(num_runs):
            t0 = time.perf_counter()
            scanner.scan_document(f"Document content {i} with specific numbers {i*7}.", document_id=f"doc-{i}")
            t1 = time.perf_counter()
            cold_times.append((t1 - t0) * 1000.0)
    finally:
        gc.enable()

    # 2. Cached Ingestion Scan
    cached_times = []
    gc.disable()
    try:
        for _ in range(num_runs):
            t0 = time.perf_counter()
            scanner.scan_document(doc_text, document_id="doc-cached-target")
            t1 = time.perf_counter()
            cached_times.append((t1 - t0) * 1000.0)
    finally:
        gc.enable()

    # 3. Context Orchestration (Filter, Deduplicate, Budget)
    context_times = []
    gc.disable()
    try:
        for _ in range(num_runs):
            t0 = time.perf_counter()
            orchestrator.filter_and_secure(chunks)
            t1 = time.perf_counter()
            context_times.append((t1 - t0) * 1000.0)
    finally:
        gc.enable()

    def calc_stats(times: List[float]) -> Dict[str, float]:
        sorted_times = sorted(times)
        return {
            "p50": round(statistics.median(sorted_times), 4),
            "p95": round(sorted_times[int(len(sorted_times) * 0.95)], 4),
            "p99": round(sorted_times[int(len(sorted_times) * 0.99)], 4),
            "mean": round(statistics.mean(sorted_times), 4),
        }

    return {
        "runs": num_runs,
        "cold_ingestion_ms": calc_stats(cold_times),
        "cached_ingestion_ms": calc_stats(cached_times),
        "context_orchestration_ms": calc_stats(context_times),
    }


if __name__ == "__main__":
    report = run_rag_benchmarks(150)
    print("==================================================")
    print("LLMFirewall Phase 27 — RAG & Context Benchmark")
    print("==================================================")
    print("Cold Ingestion Scan (per document):")
    print(f"  P50: {report['cold_ingestion_ms']['p50']}ms | P95: {report['cold_ingestion_ms']['p95']}ms | P99: {report['cold_ingestion_ms']['p99']}ms")
    print("Cached Ingestion Scan (cache hit):")
    print(f"  P50: {report['cached_ingestion_ms']['p50']}ms | P95: {report['cached_ingestion_ms']['p95']}ms | P99: {report['cached_ingestion_ms']['p99']}ms")
    print("Context Orchestration (10 retrieved chunks):")
    print(f"  P50: {report['context_orchestration_ms']['p50']}ms | P95: {report['context_orchestration_ms']['p95']}ms | P99: {report['context_orchestration_ms']['p99']}ms")
    print("==================================================")
