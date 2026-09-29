"""Comprehensive tests for SafeRedactor and configurable sensitive span redaction."""

import pytest
from llmfirewall.core.models import Action, Finding, RiskScore, Severity, ThreatType
from llmfirewall.firewall import Firewall
from llmfirewall.policy.config import PolicyConfig, PolicyRule
from llmfirewall.policy.redaction_config import RedactionConfig
from llmfirewall.policy.redactor import SafeRedactor, redact_text_spans


def test_redaction_email_phone_ip_secrets():
    """Verify standard default tokens for email, phone, IP, and secrets."""
    config = RedactionConfig(
        category_tokens={
            "email": "[EMAIL_REDACTED]",
            "phone": "[PHONE_REDACTED]",
            "ip": "[IP_REDACTED]",
            "api_key_rule": "[API_KEY_REDACTED]",
        }
    )
    redactor = SafeRedactor(config=config)
    text = (
        "User alice@example.com called +1-800-555-0199 from 192.168.1.1 "
        "using key sk-proj-1234567890abcdefghijklmnopqrstuvwxyz1234567890abcdef."
    )
    findings = [
        Finding(
            detector_name="pii_detector",
            threat_type=ThreatType.PII,
            description="Email address",
            severity=Severity.MEDIUM,
            start_pos=5,
            end_pos=22,
            metadata={"pii_category": "email"},
        ),
        Finding(
            detector_name="pii_detector",
            threat_type=ThreatType.PII,
            description="Phone number",
            severity=Severity.MEDIUM,
            start_pos=30,
            end_pos=45,
            metadata={"pii_category": "phone"},
        ),
        Finding(
            detector_name="pii_detector",
            threat_type=ThreatType.PII,
            description="IPv4 address",
            severity=Severity.LOW,
            start_pos=51,
            end_pos=62,
            metadata={"pii_category": "ip"},
        ),
        Finding(
            detector_name="secret_detector",
            threat_type=ThreatType.SECRET,
            description="API Key",
            severity=Severity.CRITICAL,
            start_pos=73,
            end_pos=133,
            metadata={"rule_id": "api_key_rule"},
        ),
    ]

    redacted = redactor.redact(text, findings)

    assert "alice@example.com" not in redacted
    assert "+1-800-555-0199" not in redacted
    assert "192.168.1.1" not in redacted
    assert "sk-proj-" not in redacted

    assert "[EMAIL_REDACTED]" in redacted
    assert "[PHONE_REDACTED]" in redacted
    assert "[IP_REDACTED]" in redacted
    assert "[API_KEY_REDACTED]" in redacted

    # Verify surrounding context is completely preserved
    assert redacted.startswith("User [EMAIL_REDACTED] called [PHONE_REDACTED] from [IP_REDACTED]")


def test_custom_replacement_tokens():
    """Verify that users can configure arbitrary placeholder tokens."""
    custom_config = RedactionConfig(
        category_tokens={
            "email": "<CENSORED_MAIL>",
            "phone": "<CENSORED_TEL>",
            "secret": "<CENSORED_KEY>",
        },
        default_token="<MASKED>",
    )
    redactor = SafeRedactor(config=custom_config)

    text = "Send mail to bob@corp.org or secret sk-1234567890."
    findings = [
        Finding(
            detector_name="pii",
            threat_type=ThreatType.PII,
            description="Email",
            severity=Severity.MEDIUM,
            start_pos=13,
            end_pos=25,
            metadata={"pii_category": "email"},
        ),
        Finding(
            detector_name="sec",
            threat_type=ThreatType.SECRET,
            description="Key",
            severity=Severity.HIGH,
            start_pos=36,
            end_pos=49,
        ),
    ]

    redacted = redactor.redact(text, findings)
    assert redacted == "Send mail to <CENSORED_MAIL> or secret <CENSORED_KEY>."


def test_overlapping_matches_handling():
    """Verify overlapping matches keep the broadest span without producing garbled text."""
    config = RedactionConfig(category_tokens={"token_rule": "[TOKEN_REDACTED]"})
    redactor = SafeRedactor(config=config)
    text = "Authorization token: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI..."
    # Finding 1: Whole bearer token (21..len(text))
    # Finding 2: Nested inner token (28..len(text))
    end_idx = len(text)
    f_outer = Finding(
        detector_name="sec",
        threat_type=ThreatType.SECRET,
        description="Full Token",
        severity=Severity.HIGH,
        start_pos=21,
        end_pos=end_idx,
        metadata={"rule_id": "token_rule"},
    )
    f_inner = Finding(
        detector_name="sec",
        threat_type=ThreatType.SECRET,
        description="Inner Token",
        severity=Severity.MEDIUM,
        start_pos=28,
        end_pos=end_idx,
        metadata={"rule_id": "token_rule"},
    )

    redacted = redactor.redact(text, [f_inner, f_outer])
    assert redacted == "Authorization token: [TOKEN_REDACTED]"


def test_context_preservation_precision():
    """Ensure exact boundaries: surrounding whitespace, punctuation, brackets are preserved."""
    redactor = SafeRedactor()
    text = '{"email": "user@test.io", "active": true}'
    f = Finding(
        detector_name="pii",
        threat_type=ThreatType.PII,
        description="Email",
        severity=Severity.MEDIUM,
        start_pos=11,
        end_pos=23,
        replacement_text="[EMAIL_REDACTED]",
        metadata={"pii_category": "email"},
    )

    redacted = redactor.redact(text, [f])
    assert redacted == '{"email": "[EMAIL_REDACTED]", "active": true}'


def test_firewall_integration_with_custom_redaction_config():
    """Test policy redaction with custom configured tokens through Firewall.check()."""
    custom_policy = PolicyConfig(
        rules=[
            PolicyRule(
                id="redact_pii_custom",
                description="Redact PII",
                threat_type=ThreatType.PII,
                action=Action.REDACT,
            )
        ],
        redaction_config=RedactionConfig(
            category_tokens={"email": "[PROTECTED_USER_EMAIL]"}
        ),
    )
    firewall = Firewall(
        policy_engine=None,  # Will inject custom config
    )
    # Reconfigure policy engine
    from llmfirewall.policy.engine import PolicyEngine
    firewall._policy_engine = PolicyEngine(config=custom_policy)

    result = firewall.check("Inquire at support@company.org for assistance.")
    assert result.decision.action == Action.REDACT
    assert result.text == "Inquire at [PROTECTED_USER_EMAIL] for assistance."
    assert "support@company.org" not in result.text
