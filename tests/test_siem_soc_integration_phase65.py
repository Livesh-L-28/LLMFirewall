"""Unit, integration, and security tests for Phase 65 — Advanced SIEM/SOC Integration."""

from datetime import datetime, timezone
import hashlib
import hmac
import json
import pytest

from llmfirewall.core.models import Action
from llmfirewall.observability import (
    EventSeverity,
    SecurityEvent,
    SecurityEventType,
    WebhookAlertConfig,
    WebhookAlertSink,
    export_events_opentelemetry,
    export_events_syslog_rfc5424,
)


@pytest.fixture
def sample_security_events():
    ts = datetime(2026, 10, 24, 8, 0, 0, tzinfo=timezone.utc)
    e1 = SecurityEvent(
        event_id="evt-001",
        timestamp=ts,
        event_type=SecurityEventType.DETECTOR_TRIGGERED,
        severity=EventSeverity.CRITICAL,
        trace_id="tr-abc-123",
        request_id="req-123",
        action=Action.BLOCK,
        risk_score=0.95,
        detector_name="prompt_injection_detector",
        environment="production",
        payload_hash="sha256_mock_hash",
        payload_length=120,
    )
    e2 = SecurityEvent(
        event_id="evt-002",
        timestamp=ts,
        event_type=SecurityEventType.REQUEST_COMPLETED,
        severity=EventSeverity.INFO,
        trace_id="tr-abc-124",
        request_id="req-124",
        action=Action.ALLOW,
        risk_score=0.05,
        environment="production",
        payload_length=45,
    )
    return [e1, e2]


def test_syslog_rfc5424_export(sample_security_events):
    """Verify RFC 5424 syslog output adheres to specification."""
    syslog_text = export_events_syslog_rfc5424(sample_security_events, hostname="firewall-prod-01")
    lines = syslog_text.strip().split("\n")
    assert len(lines) == 2

    # Line 1: Critical (facility 10 * 8 + 2 = 82)
    crit_line = lines[0]
    assert crit_line.startswith("<82>1 ")
    assert "firewall-prod-01 llmfirewall - detector_triggered" in crit_line
    assert '[llmfirewall@41123 eventId="evt-001"' in crit_line
    assert 'action="block"' in crit_line
    assert 'detector="prompt_injection_detector"' in crit_line
    assert 'riskScore="0.950"' in crit_line


def test_opentelemetry_export(sample_security_events):
    """Verify OpenTelemetry OTLP LogRecords formatting and semantic conventions."""
    otlp = export_events_opentelemetry(sample_security_events)

    assert "resourceLogs" in otlp
    resource_logs = otlp["resourceLogs"]
    assert len(resource_logs) == 1

    resource = resource_logs[0]["resource"]
    service_attr = next(a for a in resource["attributes"] if a["key"] == "service.name")
    assert service_attr["value"]["stringValue"] == "llmfirewall"

    scope_logs = resource_logs[0]["scopeLogs"]
    records = scope_logs[0]["logRecords"]
    assert len(records) == 2

    # First record should be Critical (severity 21)
    rec1 = records[0]
    assert rec1["severityNumber"] == 21
    assert rec1["severityText"] == "CRITICAL"
    assert rec1["traceId"] == "tr-abc-123"

    attr_dict = {a["key"]: a["value"] for a in rec1["attributes"]}
    assert attr_dict["gen_ai.system"]["stringValue"] == "llmfirewall"
    assert attr_dict["security.action"]["stringValue"] == "block"
    assert attr_dict["security.risk_score"]["doubleValue"] == 0.95


def test_webhook_alert_sink_dispatch_and_filtering(sample_security_events):
    """Verify WebhookAlertSink filters out low severity events and dispatches high severity."""
    config = WebhookAlertConfig(
        url="https://soc.example.com/alerts",
        min_severity=EventSeverity.HIGH,
        dry_run=True,
    )
    sink = WebhookAlertSink(config)

    e_crit = sample_security_events[0]
    e_info = sample_security_events[1]

    # INFO event should be filtered out
    res_info = sink.dispatch(e_info)
    assert res_info is None
    assert len(sink.dispatched_alerts) == 0

    # CRITICAL event should be dispatched
    res_crit = sink.dispatch(e_crit)
    assert res_crit is not None
    assert res_crit["payload"]["event_id"] == "evt-001"
    assert res_crit["payload"]["severity"] == EventSeverity.CRITICAL.value
    assert len(sink.dispatched_alerts) == 1


def test_webhook_alert_sink_hmac_signature(sample_security_events):
    """Verify WebhookAlertSink attaches valid HMAC-SHA256 signature."""
    secret = "soc-secret-webhook-key-9988"
    config = WebhookAlertConfig(
        url="https://soc.example.com/alerts",
        secret_token=secret,
        min_severity=EventSeverity.HIGH,
        dry_run=True,
    )
    sink = WebhookAlertSink(config)

    alert = sink.dispatch(sample_security_events[0])
    assert alert is not None
    sig = alert["signature"]
    assert len(sig) == 64  # hex digest

    # Verify signature independently
    payload_bytes = json.dumps(alert["payload"], sort_keys=True).encode("utf-8")
    expected_sig = hmac.new(secret.encode("utf-8"), payload_bytes, hashlib.sha256).hexdigest()
    assert sig == expected_sig


def test_webhook_alert_sink_rate_limiting(sample_security_events):
    """Verify WebhookAlertSink caps notifications to prevent alert storms."""
    config = WebhookAlertConfig(
        url="https://soc.example.com/alerts",
        min_severity=EventSeverity.HIGH,
        max_alerts_per_minute=2,
        dry_run=True,
    )
    sink = WebhookAlertSink(config)
    event = sample_security_events[0]

    t0 = 1000.0
    assert sink.dispatch(event, now=t0) is not None
    assert sink.dispatch(event, now=t0 + 1) is not None
    # 3rd alert within 60s window must be dropped by rate limit
    assert sink.dispatch(event, now=t0 + 2) is None
    assert len(sink.dispatched_alerts) == 2

    # After 65s, window clears
    assert sink.dispatch(event, now=t0 + 65.0) is not None
    assert len(sink.dispatched_alerts) == 3
