"""Comprehensive Unit & Integration Tests for Security Intelligence & Risk 2.0 (Phase 50)."""

import time
import pytest

from llmfirewall.core.models import Finding, RiskScore, Severity, ThreatType
from llmfirewall.risk import (
    AttackChainType,
    BlastRadiusEstimator,
    BlastRadiusReport,
    FindingCorrelationEngine,
    RiskEngine,
    SessionRiskTracker,
)


@pytest.fixture
def risk_engine() -> RiskEngine:
    return RiskEngine()


def test_correlation_exfiltration_chain(risk_engine: RiskEngine) -> None:
    """Prompt injection combined with secret disclosure should form an Exfiltration Chain."""
    findings = [
        Finding(
            detector_name="injection_detector",
            threat_type=ThreatType.PROMPT_INJECTION,
            description="System prompt override detected",
            severity=Severity.HIGH,
            confidence=0.9,
        ),
        Finding(
            detector_name="secret_detector",
            threat_type=ThreatType.SECRET,
            description="AWS Secret Access Key leak",
            severity=Severity.CRITICAL,
            confidence=0.95,
        ),
    ]

    report = risk_engine.correlate(findings)
    assert report.is_compound_attack is True
    assert report.correlation_multiplier > 1.0
    assert report.highest_severity == Severity.CRITICAL
    chain_types = [c.chain_type for c in report.chains]
    assert AttackChainType.EXFILTRATION_CHAIN in chain_types


def test_correlation_remote_execution_chain(risk_engine: RiskEngine) -> None:
    """Prompt injection combined with execution tooling context triggers execution chain."""
    findings = [
        Finding(
            detector_name="injection_detector",
            threat_type=ThreatType.PROMPT_INJECTION,
            description="Jailbreak payload",
            severity=Severity.HIGH,
            confidence=0.85,
        )
    ]
    context = {"tool_name": "bash_executor", "tool_args": "rm -rf /tmp/data"}

    report = risk_engine.correlate(findings, context=context)
    assert report.is_compound_attack is True
    assert any(c.chain_type == AttackChainType.REMOTE_EXECUTION_CHAIN for c in report.chains)


def test_correlation_indirect_rag_poisoning(risk_engine: RiskEngine) -> None:
    """Untrusted RAG source + injection should trigger indirect RAG poisoning chain."""
    findings = [
        Finding(
            detector_name="injection_detector",
            threat_type=ThreatType.PROMPT_INJECTION,
            description="Context instruction hijacking",
            severity=Severity.HIGH,
            confidence=0.88,
        )
    ]
    context = {"source": "untrusted_rag_chunk_42", "is_rag": True}

    report = risk_engine.correlate(findings, context=context)
    assert report.is_compound_attack is True
    assert any(c.chain_type == AttackChainType.INDIRECT_RAG_POISONING for c in report.chains)


def test_correlation_multi_vector_flood(risk_engine: RiskEngine) -> None:
    """Three or more distinct threat categories should trigger multi-vector flood."""
    findings = [
        Finding(
            detector_name="d1",
            threat_type=ThreatType.PROMPT_INJECTION,
            description="Injection attempt",
            severity=Severity.HIGH,
            confidence=0.8,
        ),
        Finding(
            detector_name="d2",
            threat_type=ThreatType.TOXICITY,
            description="Abusive content",
            severity=Severity.MEDIUM,
            confidence=0.75,
        ),
        Finding(
            detector_name="d3",
            threat_type=ThreatType.PII,
            description="SSN leak",
            severity=Severity.HIGH,
            confidence=0.9,
        ),
    ]

    report = risk_engine.correlate(findings)
    assert report.is_compound_attack is True
    assert any(c.chain_type == AttackChainType.MULTI_VECTOR_FLOOD for c in report.chains)


def test_correlation_adjacent_spans_collusion(risk_engine: RiskEngine) -> None:
    """Threat findings within 50 characters of each other trigger adjacent spans collusion."""
    findings = [
        Finding(
            detector_name="d1",
            threat_type=ThreatType.PROMPT_INJECTION,
            description="Prefix override",
            severity=Severity.MEDIUM,
            confidence=0.8,
            start_pos=10,
            end_pos=25,
        ),
        Finding(
            detector_name="d2",
            threat_type=ThreatType.SECRET,
            description="Token disclosure",
            severity=Severity.HIGH,
            confidence=0.9,
            start_pos=35,
            end_pos=60,
        ),
    ]

    report = risk_engine.correlate(findings)
    assert report.is_compound_attack is True
    assert any(c.chain_type == AttackChainType.ADJACENT_SPANS_COLLUSION for c in report.chains)


def test_contextual_dynamic_scoring_adjustments(risk_engine: RiskEngine) -> None:
    """Production and trust boundary traversal should scale risk score compared to dev."""
    finding = Finding(
        detector_name="pii",
        threat_type=ThreatType.PII,
        description="Internal IP address",
        severity=Severity.MEDIUM,
        confidence=0.8,
    )

    score_dev = risk_engine.evaluate([finding], context={"environment": "development"})
    score_prod = risk_engine.evaluate(
        [finding],
        context={
            "environment": "production",
            "trust_boundary_traversed": True,
            "asset_criticality": 1.0,
        },
    )

    assert score_prod.score > score_dev.score
    assert "blast_radius" in score_prod.metadata
    assert "contextual_multiplier" in score_prod.metadata


def test_blast_radius_estimation(risk_engine: RiskEngine) -> None:
    """Dangerous tools and credentials in production produce critical blast radius."""
    findings = [
        Finding(
            detector_name="secret_detector",
            threat_type=ThreatType.SECRET,
            description="Prod master database credential",
            severity=Severity.CRITICAL,
            confidence=0.99,
        )
    ]
    context = {
        "environment": "production",
        "user_role": "admin",
        "tool_name": "db_query",
        "asset_id": "payment-gateway",
    }

    report: BlastRadiusReport = risk_engine.estimate_blast_radius(findings, context=context)
    assert report.score >= 0.75
    assert report.privilege_elevation_risk is True
    assert "API_KEYS_AND_CREDENTIALS" in report.exposed_data_types
    assert len(report.containment_steps) > 0


def test_session_risk_temporal_decay(risk_engine: RiskEngine) -> None:
    """Session risk tracker accumulates scores and decays over time."""
    session_id = "test-session-123"
    t0 = 1000000.0

    finding = Finding(
        detector_name="inj",
        threat_type=ThreatType.PROMPT_INJECTION,
        description="Turn 1 attack",
        severity=Severity.MEDIUM,
        confidence=0.8,
    )

    s1 = risk_engine.track_session(session_id, [finding], risk_score=0.6, timestamp=t0)
    assert s1.total_turns == 1
    assert s1.decayed_score > 0.0

    # 10 minutes later (600s = 2 half-lives of 300s)
    t1 = t0 + 600.0
    s_decayed = risk_engine.get_session_risk(session_id, current_time=t1)
    assert s_decayed.decayed_score < s1.decayed_score


def test_session_risk_probe_attack_detection(risk_engine: RiskEngine) -> None:
    """Repeated low-and-slow turns should be flagged as probe attack."""
    session_id = "probe-attacker-999"
    t = time.time()

    findings = [
        Finding(
            detector_name="test",
            threat_type=ThreatType.PROMPT_INJECTION,
            description="Probing defense limits",
            severity=Severity.LOW,
            confidence=0.7,
        )
    ]

    # Record 4 rapid turns with moderate risk score (0.40 each)
    for i in range(4):
        summary = risk_engine.track_session(session_id, findings, risk_score=0.40, timestamp=t + (i * 2))

    assert summary.total_turns == 4
    assert summary.is_probe_attack is True
    assert summary.alert_level == Severity.CRITICAL
