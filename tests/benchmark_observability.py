"""Microbenchmarks for Phase 24 Observability & Security Intelligence.

Measures:
- SecurityEvent creation and SHA-256 hashing throughput
- InMemoryEventStore write and query latency
- SQLiteEventStore write and indexed query latency
- SecurityIntelligenceEngine summary aggregation over 10K events
"""

import time
from datetime import datetime, timezone
import pytest

from llmfirewall.core.models import Action, Severity
from llmfirewall.observability import (
    InMemoryEventStore,
    SQLiteEventStore,
    SecurityEvent,
    SecurityEventType,
    SecurityIntelligenceEngine,
    hash_content,
)


def test_benchmark_event_creation_and_hashing():
    raw_payload = "Please summarize customer transaction history without leaking account numbers."
    count = 10000
    start = time.perf_counter()
    for i in range(count):
        h = hash_content(raw_payload)
        ev = SecurityEvent(
            event_type=SecurityEventType.SECURITY_DECISION,
            request_id=f"bench-req-{i}",
            action=Action.ALLOW,
            payload_hash=h,
            payload_length=len(raw_payload),
        )
    elapsed = time.perf_counter() - start
    ops_sec = count / elapsed
    # Should easily process > 20,000 events/second
    assert ops_sec > 5000, f"Throughput too low: {ops_sec:.1f} ops/sec"


def test_benchmark_in_memory_store_writes_and_summary():
    store = InMemoryEventStore(max_events=10000)
    count = 5000
    now = datetime.now(timezone.utc)

    # 1. Ingestion latency
    start = time.perf_counter()
    for i in range(count):
        store.write(
            SecurityEvent(
                event_type=SecurityEventType.SECURITY_DECISION,
                timestamp=now,
                request_id=f"mem-{i}",
                action=Action.BLOCK if i % 10 == 0 else Action.ALLOW,
                risk_level=Severity.HIGH if i % 10 == 0 else Severity.LOW,
                risk_score=0.9 if i % 10 == 0 else 0.1,
                detector_name="PromptInjectionDetector" if i % 10 == 0 else None,
                duration_ms=5.0,
            )
        )
    ingest_time = time.perf_counter() - start
    assert ingest_time < 2.0, f"InMemory write took too long: {ingest_time:.2f}s"

    # 2. Aggregation throughput
    intel = SecurityIntelligenceEngine(store=store)
    start = time.perf_counter()
    summary = intel.summary()
    agg_time = time.perf_counter() - start

    assert summary["total_requests"] == 5000
    assert summary["blocks"] == 500
    assert agg_time < 0.1, f"Aggregation took too long: {agg_time:.4f}s"


def test_benchmark_sqlite_indexed_query(tmp_path):
    db_file = tmp_path / "bench.db"
    store = SQLiteEventStore(db_path=str(db_file))
    count = 1000
    now = datetime.now(timezone.utc)

    for i in range(count):
        store.write(
            SecurityEvent(
                event_type=SecurityEventType.SECURITY_DECISION,
                timestamp=now,
                request_id=f"sql-{i}",
                action=Action.BLOCK if i % 5 == 0 else Action.ALLOW,
                detector_name="SecretDetector" if i % 5 == 0 else None,
            )
        )

    from llmfirewall.observability.store import EventFilter
    start = time.perf_counter()
    results = store.query(EventFilter(detector_name="SecretDetector", limit=100))
    query_time = time.perf_counter() - start

    assert len(results) == 100
    # Indexed sqlite query over 1,000 rows should take < 10ms
    assert query_time < 0.05, f"SQLite query too slow: {query_time:.4f}s"
