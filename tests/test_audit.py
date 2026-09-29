"""Comprehensive unit tests for AuditLogger, structured JSON logging, and safety verification."""

import io
import json
import logging
import pytest

from llmfirewall.audit import AuditLogger
from llmfirewall.core.models import (
    Action,
    AuditEvent,
    Finding,
    PolicyDecision,
    RiskScore,
    ScanRequest,
    ScanResult,
    Severity,
    ThreatType,
)
from llmfirewall.firewall import Firewall


def test_audit_event_structure_and_json_serialization():
    sink = io.StringIO()
    logger = AuditLogger(sink=sink)

    req = ScanRequest(
        text="Sample prompt query",
        direction="input",
        user_id="user_test_42",
        session_id="session_xyz",
    )
    res = ScanResult(
        request_id=req.id,
        decision=PolicyDecision(
            action=Action.ALLOW,
            reason="All security checks passed.",
        ),
        risk_score=RiskScore(score=0.0, max_severity=Severity.INFO),
        findings=[],
        original_text=req.text,
        processed_text=req.text,
        execution_time_ms=3.45,
    )

    event = logger.log_scan(request=req, result=res, metadata={"environment": "production"})

    # Check AuditEvent attributes
    assert event.scan_id == res.id
    assert event.request_id == req.id
    assert event.action_taken == Action.ALLOW
    assert event.risk_score == 0.0
    assert event.max_severity == Severity.INFO
    assert event.user_id == "user_test_42"
    assert event.session_id == "session_xyz"
    assert event.metadata["environment"] == "production"

    # Verify structured JSON format written to sink
    output = sink.getvalue().strip()
    data = json.loads(output)

    assert data["scan_id"] == res.id
    assert data["request_id"] == req.id
    assert data["action_taken"] == "allow"
    assert data["risk_score"] == 0.0
    assert data["max_severity"] == "info"
    assert "timestamp" in data


def test_security_invariant_zero_secret_exposure_in_audit_log():
    """Verify that credentials and raw secret tokens NEVER appear in emitted audit events or JSON."""
    raw_secret_token = "sk-proj-SUPER_SECRET_KEY_NEVER_LEAK_THIS_STRING_IN_LOGS"
    prompt_text = f"Configure system with {raw_secret_token} now."

    sink = io.StringIO()
    logger = AuditLogger(sink=sink)
    firewall = Firewall(audit_logger=logger)

    result = firewall.check_prompt(prompt_text, user_id="admin_1")

    # Assert request was blocked
    assert result.is_blocked is True
    assert result.decision.action == Action.BLOCK

    # Inspect the emitted audit log
    assert len(logger.buffered_events) == 1
    event = logger.buffered_events[0]
    json_line = logger.buffered_lines[0]

    # CRITICAL SECURITY INVARIANTS:
    # 1. Raw secret token MUST NOT appear in the AuditEvent object
    assert raw_secret_token not in str(event)
    # 2. Raw secret token MUST NOT appear in the JSON serialized sink
    assert raw_secret_token not in json_line
    # 3. Raw prompt text is NOT included in AuditEvent
    assert prompt_text not in json_line

    # Structured metadata should still capture the attack taxonomy safely:
    assert ThreatType.SECRET in event.threat_types
    assert "secret_detector" in event.detector_names
    assert "api_key_rule" in event.detection_categories
    assert event.action_taken == Action.BLOCK
    assert event.risk_score >= 0.8


def test_security_invariant_zero_raw_pii_in_audit_log():
    """Verify customer PII (credit cards, emails, phones) is NEVER logged into audit events."""
    raw_email = "customer.confidential@sensitive-corp.com"
    raw_phone = "+1-800-555-0199"
    prompt_text = f"Contact account holder at {raw_email} or call {raw_phone}."

    sink = io.StringIO()
    logger = AuditLogger(sink=sink)
    firewall = Firewall(audit_logger=logger)

    result = firewall.check_prompt(prompt_text, user_id="csr_agent_12")

    assert result.decision.action == Action.REDACT
    assert len(logger.buffered_events) == 1

    event = logger.buffered_events[0]
    json_line = logger.buffered_lines[0]

    # SECURITY CHECKS:
    assert raw_email not in str(event)
    assert raw_phone not in str(event)
    assert raw_email not in json_line
    assert raw_phone not in json_line

    # Verify telemetry metadata
    assert ThreatType.PII in event.threat_types
    assert "email" in event.detection_categories
    assert "phone" in event.detection_categories
    assert "pii_detector" in event.detector_names
    assert event.findings_count == 2
    assert event.action_taken == Action.REDACT


def test_configurable_logging_levels_and_custom_formatter():
    """Test custom output formatters and logging level handling."""
    custom_sink = io.StringIO()

    def custom_formatter(record: dict) -> str:
        return f"[AUDIT_PREFIX] action={record['action_taken']} risk={record['risk_score']} threats={len(record['threat_types'])}"

    logger = AuditLogger(
        sink=custom_sink,
        min_level=logging.WARNING,
        formatter=custom_formatter,
    )

    req = ScanRequest(text="Clean request")
    res = ScanResult(
        request_id=req.id,
        decision=PolicyDecision(action=Action.ALLOW, reason="Clean"),
        risk_score=RiskScore(score=0.0, max_severity=Severity.INFO),
        findings=[],
    )

    logger.log_scan(request=req, result=res)
    output = custom_sink.getvalue().strip()

    assert output.startswith("[AUDIT_PREFIX] action=allow risk=0.0 threats=0")
