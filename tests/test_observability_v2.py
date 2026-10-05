"""Comprehensive Unit & Integration Tests for Observability & Security Dashboard API (Phase 54)."""

from datetime import datetime, timezone
import pytest

from llmfirewall import Action, Firewall
from llmfirewall.cache import ScanCache
from llmfirewall.observability import (
    DashboardSummary,
    EventSeverity,
    InMemoryEventStore,
    PaginatedEventsResponse,
    SecurityDashboardAPI,
    SecurityEvent,
    SecurityEventType,
    export_events_cef,
    export_prometheus_metrics,
)


@pytest.fixture
def populated_store() -> InMemoryEventStore:
    store = InMemoryEventStore()
    now = datetime.now(timezone.utc)

    e1 = SecurityEvent(
        request_id="req-1",
        event_type=SecurityEventType.SECURITY_DECISION,
        severity=EventSeverity.INFO,
        action=Action.ALLOW,
        duration_ms=2.5,
        timestamp=now,
    )
    e2 = SecurityEvent(
        request_id="req-2",
        event_type=SecurityEventType.DETECTOR_TRIGGERED,
        severity=EventSeverity.CRITICAL,
        action=Action.BLOCK,
        detector_name="prompt_injection_detector",
        duration_ms=4.1,
        timestamp=now,
    )
    e3 = SecurityEvent(
        request_id="req-3",
        event_type=SecurityEventType.REDACTION_APPLIED,
        severity=EventSeverity.HIGH,
        action=Action.REDACT,
        detector_name="secret_detector",
        duration_ms=3.0,
        timestamp=now,
    )

    store.write(e1)
    store.write(e2)
    store.write(e3)
    return store


def test_dashboard_api_get_summary(populated_store: InMemoryEventStore) -> None:
    cache = ScanCache()
    dashboard = SecurityDashboardAPI(store=populated_store, cache_metrics_provider=cache)

    summary: DashboardSummary = dashboard.get_summary()

    assert summary.total_requests == 3
    assert summary.total_blocked == 1
    assert summary.total_redacted == 1
    assert summary.total_allowed == 1
    assert summary.block_rate_percent == pytest.approx(33.33, 0.1)
    assert summary.p50_latency_ms > 0.0
    assert summary.threat_breakdown.get("prompt_injection_detector") == 1
    assert summary.threat_breakdown.get("secret_detector") == 1
    assert summary.cache_metrics is not None


def test_dashboard_api_get_events_sanitization(populated_store: InMemoryEventStore) -> None:
    dashboard = SecurityDashboardAPI(store=populated_store)

    resp: PaginatedEventsResponse = dashboard.get_events(limit=2, offset=0)
    assert resp.total_count == 3
    assert len(resp.events) == 2

    # Verify no raw payload fields exist in sanitized model
    ev = resp.events[0]
    assert hasattr(ev, "event_id")
    assert not hasattr(ev, "raw_content")
    assert not hasattr(ev, "prompt_text")


def test_dashboard_api_get_events_filtering(populated_store: InMemoryEventStore) -> None:
    dashboard = SecurityDashboardAPI(store=populated_store)

    critical_events = dashboard.get_events(severity="critical")
    assert critical_events.total_count == 1
    assert critical_events.events[0].severity == "critical"

    block_events = dashboard.get_events(action="block")
    assert block_events.total_count == 1
    assert block_events.events[0].action == "block"


def test_dashboard_api_timeseries_buckets(populated_store: InMemoryEventStore) -> None:
    dashboard = SecurityDashboardAPI(store=populated_store)
    buckets = dashboard.get_timeseries(window_seconds=3600, bucket_count=4)

    assert len(buckets) == 4
    # The most recent bucket should capture the 3 events written just now
    total_captured = sum(b.total_requests for b in buckets)
    assert total_captured == 3


def test_cef_exporter(populated_store: InMemoryEventStore) -> None:
    events = populated_store.query()
    cef_output = export_events_cef(events)

    lines = [line for line in cef_output.split("\n") if line.strip()]
    assert len(lines) == 3

    for line in lines:
        assert line.startswith("CEF:0|LLMFirewall|LLMFirewallCore|1.1.0|")
        assert "cs1Label=DetectorName" in line
        assert "cs2Label=PolicyID" in line

    # Critical event should map to severity 10
    assert any("|10|" in line for line in lines)


def test_prometheus_exporter_with_cache_metrics() -> None:
    summary_data = {
        "total_requests": 100,
        "allows": 90,
        "blocks": 10,
        "warns": 0,
        "redactions": 0,
        "block_rate_percent": 10.0,
        "latency": {"p50_ms": 1.2, "p95_ms": 3.4, "p99_ms": 5.0, "average_ms": 1.5},
        "cache": {"hits": 80, "misses": 20, "hit_ratio": 0.8},
    }

    metrics_text = export_prometheus_metrics(summary_data)
    assert "llmfirewall_requests_total 100" in metrics_text
    assert "llmfirewall_cache_hits_total 80" in metrics_text
    assert "llmfirewall_cache_misses_total 20" in metrics_text
    assert "llmfirewall_cache_hit_ratio 0.8" in metrics_text
