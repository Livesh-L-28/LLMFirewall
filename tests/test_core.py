"""Tests for LLMFirewall Phase 1 Core Contracts and Interfaces updated for Phase 3 models."""

import pytest
from pydantic import ValidationError

from llmfirewall.core.exceptions import (
    BlockedOutputError,
    BlockedPromptError,
    ConfigurationError,
    LLMFirewallError,
)
from llmfirewall.core.interfaces import BaseDetector, BasePolicyEngine, BaseRiskEngine
from llmfirewall.core.models import (
    Action,
    Finding,
    FirewallResult,
    PolicyDecision,
    RiskScore,
    Severity,
    ThreatType,
)


def test_severity_ordering_and_values():
    assert Severity.INFO.value == "info"
    assert Severity.LOW.value == "low"
    assert Severity.MEDIUM.value == "medium"
    assert Severity.HIGH.value == "high"
    assert Severity.CRITICAL.value == "critical"


def test_decision_action_values():
    assert Action.ALLOW.value == "allow"
    assert Action.WARN.value == "warn"
    assert Action.BLOCK.value == "block"
    assert Action.REDACT.value == "redact"


def test_finding_valid_creation():
    finding = Finding(
        detector_name="test_detector",
        threat_type=ThreatType.SECRET,
        description="Found dummy token",
        severity=Severity.HIGH,
        confidence=0.95,
        start_pos=10,
        end_pos=25,
        matched_text="sk-1234567890",
        replacement_text="[REDACTED_SECRET]",
    )
    assert finding.detector_name == "test_detector"
    assert finding.threat_type == ThreatType.SECRET
    assert finding.category == "secret"
    assert finding.severity == Severity.HIGH
    assert finding.confidence == 0.95
    assert finding.matched_text == "sk-1234567890"


def test_finding_validation_errors():
    # Confidence out of bounds
    with pytest.raises(ValidationError):
        Finding(
            detector_name="test",
            threat_type=ThreatType.CUSTOM,
            description="test",
            severity=Severity.LOW,
            confidence=1.5,
        )

    # Inverted span
    with pytest.raises(ValidationError):
        Finding(
            detector_name="test",
            threat_type=ThreatType.CUSTOM,
            description="test",
            severity=Severity.LOW,
            start_pos=20,
            end_pos=10,
        )


def test_risk_score_valid_creation():
    risk = RiskScore(
        score=0.75,
        max_severity=Severity.HIGH,
        category_scores={"prompt_injection": 0.75},
    )
    assert risk.score == 0.75
    assert risk.max_severity == Severity.HIGH
    assert risk.category_scores["prompt_injection"] == 0.75


def test_risk_score_invalid():
    with pytest.raises(ValidationError):
        RiskScore(score=1.2, max_severity=Severity.HIGH)


def test_firewall_result_helpers():
    decision_allow = PolicyDecision(action=Action.ALLOW, reason="All checks passed")
    risk_low = RiskScore(score=0.1, max_severity=Severity.LOW)
    res_allow = FirewallResult(
        request_id="req-1",
        decision=decision_allow,
        risk_score=risk_low,
        original_text="Hello world",
        processed_text="Hello world",
    )
    assert res_allow.is_allowed is True
    assert res_allow.is_blocked is False
    assert res_allow.text == "Hello world"

    decision_block = PolicyDecision(
        action=Action.BLOCK,
        reason="Injection detected",
        triggered_rules=["block_on_high_injection"],
    )
    risk_high = RiskScore(score=0.9, max_severity=Severity.CRITICAL)
    res_block = FirewallResult(
        request_id="req-2",
        decision=decision_block,
        risk_score=risk_high,
        original_text="Ignore previous instructions",
        processed_text="",
    )
    assert res_block.is_allowed is False
    assert res_block.is_blocked is True


def test_interface_compliance():
    class DummyDetector(BaseDetector):
        @property
        def name(self) -> str:
            return "dummy"

        def detect(self, text, context=None):
            return [
                Finding(
                    detector_name=self.name,
                    threat_type=ThreatType.CUSTOM,
                    description="test",
                    severity=Severity.INFO,
                )
            ]

    class DummyRiskEngine(BaseRiskEngine):
        def evaluate(self, findings, context=None):
            return RiskScore(score=0.0, max_severity=Severity.INFO)

    class DummyPolicyEngine(BasePolicyEngine):
        def decide(self, text, findings, risk_score, context=None):
            return PolicyDecision(action=Action.ALLOW, reason="Dummy pass")

    detector = DummyDetector()
    findings = detector.detect("sample")
    assert len(findings) == 1

    risk_engine = DummyRiskEngine()
    score = risk_engine.evaluate(findings)
    assert score.score == 0.0

    policy_engine = DummyPolicyEngine()
    decision = policy_engine.decide("sample", findings, score)
    assert decision.action == Action.ALLOW


def test_exceptions_hierarchy():
    assert issubclass(ConfigurationError, LLMFirewallError)
    assert issubclass(BlockedPromptError, LLMFirewallError)
    assert issubclass(BlockedOutputError, LLMFirewallError)

    err = BlockedPromptError("Forbidden", decision={"action": "block"})
    assert str(err) == "Forbidden"
    assert err.decision == {"action": "block"}
