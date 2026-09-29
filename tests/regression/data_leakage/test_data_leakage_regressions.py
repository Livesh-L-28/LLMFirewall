"""Data leakage, exfiltration, and PII regression tests."""

import pytest
from llmfirewall import Firewall, Action, PolicyDecision

def test_regression_raw_api_key_leak_blocked() -> None:
    """Verifies that model output leaking an API key is blocked."""
    fw = Firewall()
    dec = fw.inspect(output="The primary root API key is sk-1234567890abcdef1234567890abcdef")
    assert dec.decision == PolicyDecision.BLOCK

def test_regression_ssn_redaction() -> None:
    """Verifies that SSNs in model outputs are redacted."""
    fw = Firewall()
    dec = fw.inspect(output="Customer verified: SSN is 000-12-3456. Please update account status.")
    assert dec.decision == PolicyDecision.REDACT
    assert "[REDACTED_PII]" in dec.redacted_content
    assert "000-12-3456" not in dec.redacted_content

def test_regression_email_redaction() -> None:
    """Verifies that emails in model outputs are redacted."""
    fw = Firewall()
    dec = fw.inspect(output="Contact representative at alice.cooper@confidential-company.com for inquiries.")
    assert dec.decision == PolicyDecision.REDACT
    assert "[REDACTED_PII]" in dec.redacted_content

def test_regression_benign_output_allowed() -> None:
    """Verifies clean output without secrets or PII is allowed."""
    fw = Firewall()
    dec = fw.inspect(output="HTTP status 200 indicates that the server has successfully processed the request.")
    assert dec.decision == PolicyDecision.ALLOW
