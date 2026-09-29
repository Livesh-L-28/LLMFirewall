"""Unit tests for Phase 8: Risk Engine."""

import pytest
from pydantic import ValidationError

from llmfirewall.core.models import Finding, Severity, ThreatType
from llmfirewall.detectors.collection import FindingCollection
from llmfirewall.risk.config import RiskConfig
from llmfirewall.risk.engine import RiskEngine


def test_empty_findings():
    engine = RiskEngine()
    result = engine.evaluate([])

    assert result.score == 0.0
    assert result.max_severity == Severity.INFO
    assert result.category_scores == {}
    assert result.metadata["risk_level"] == "info"
    assert result.metadata["findings_count"] == 0


def test_single_low_severity_finding():
    engine = RiskEngine()
    finding = Finding(
        detector_name="pii_detector",
        threat_type=ThreatType.PII,
        description="Low severity IP address found",
        severity=Severity.LOW,
        confidence=1.0,
    )
    result = engine.evaluate([finding])

    # Expected: severity_weight[LOW] = 0.20 * confidence 1.0 * pii_multiplier 0.9 = 0.18
    assert result.score == 0.18
    assert result.max_severity == Severity.LOW
    assert result.category_scores["pii"] == 0.18
    assert result.metadata["risk_level"] == "low"


def test_single_critical_finding():
    engine = RiskEngine()
    finding = Finding(
        detector_name="secret_detector",
        threat_type=ThreatType.SECRET,
        description="Leaked OpenAI secret key",
        severity=Severity.CRITICAL,
        confidence=1.0,
    )
    result = engine.evaluate([finding])

    # Expected: CRITICAL weight 1.0 * 1.0 * 1.0 = 1.0
    assert result.score == 1.0
    assert result.max_severity == Severity.CRITICAL
    assert result.category_scores["secret"] == 1.0
    assert result.metadata["risk_level"] == "critical"


def test_multiple_findings_same_category_diminishing_returns():
    engine = RiskEngine()
    # 3 High Severity Injection findings (severity=0.80, multiplier=1.0, conf=1.0)
    # primary: 0.80
    # secondary: 0.80 * 0.5 = 0.40
    # tertiary: 0.80 * 0.25 = 0.20
    # total category score: min(1.0, 0.80 + 0.40 + 0.20) = 1.0
    f1 = Finding(
        detector_name="injection_detector",
        threat_type=ThreatType.PROMPT_INJECTION,
        description="Injection 1",
        severity=Severity.HIGH,
        confidence=1.0,
        start_pos=0,
        end_pos=10,
    )
    f2 = Finding(
        detector_name="injection_detector",
        threat_type=ThreatType.PROMPT_INJECTION,
        description="Injection 2",
        severity=Severity.HIGH,
        confidence=1.0,
        start_pos=15,
        end_pos=25,
    )
    f3 = Finding(
        detector_name="injection_detector",
        threat_type=ThreatType.PROMPT_INJECTION,
        description="Injection 3",
        severity=Severity.HIGH,
        confidence=1.0,
        start_pos=30,
        end_pos=40,
    )

    result = engine.evaluate([f1, f2, f3])
    assert result.score == 1.0
    assert result.category_scores["prompt_injection"] == 1.0
    assert result.max_severity == Severity.HIGH
    assert result.metadata["findings_count"] == 3


def test_multiple_findings_across_different_categories():
    engine = RiskEngine()
    # 1. Prompt Injection (Medium: 0.50 * 1.0 = 0.50)
    # 2. PII email (Medium: 0.50 * 0.9 = 0.45)
    f_inj = Finding(
        detector_name="injection_detector",
        threat_type=ThreatType.PROMPT_INJECTION,
        description="Role change",
        severity=Severity.MEDIUM,
        confidence=1.0,
    )
    f_pii = Finding(
        detector_name="pii_detector",
        threat_type=ThreatType.PII,
        description="Email address",
        severity=Severity.MEDIUM,
        confidence=1.0,
    )

    result = engine.evaluate([f_inj, f_pii])

    # Expected: primary category = 0.50; secondary category = 0.45 * 0.2 = 0.09
    # Composite = 0.50 + 0.09 = 0.59
    assert result.score == 0.59
    assert result.category_scores["prompt_injection"] == 0.50
    assert result.category_scores["pii"] == 0.45
    assert result.metadata["risk_level"] == "medium"


def test_duplicate_findings_deduplication():
    engine = RiskEngine()
    # Two identical findings on the exact same span
    f1 = Finding(
        detector_name="det1",
        threat_type=ThreatType.SECRET,
        description="Key found",
        severity=Severity.HIGH,
        confidence=0.8,
        start_pos=10,
        end_pos=30,
    )
    f2 = Finding(
        detector_name="det2",
        threat_type=ThreatType.SECRET,
        description="Key found by second rule",
        severity=Severity.HIGH,
        confidence=0.95,  # higher confidence
        start_pos=10,
        end_pos=30,
    )

    result = engine.evaluate([f1, f2])
    # The duplicate span should be consolidated, retaining the highest impact finding (conf=0.95)
    assert result.metadata["findings_count"] == 2
    assert result.metadata["deduplicated_count"] == 1
    # 0.80 * 0.95 * 1.0 = 0.76
    assert result.score == 0.76


def test_finding_collection_input():
    engine = RiskEngine()
    collection = FindingCollection(
        findings=[
            Finding(
                detector_name="d1",
                threat_type=ThreatType.TOXICITY,
                description="Toxic remark",
                severity=Severity.LOW,
                confidence=0.9,
            )
        ]
    )
    result = engine.evaluate(collection)
    assert result.score > 0.0
    assert result.max_severity == Severity.LOW


def test_invalid_config_values():
    with pytest.raises(ValidationError):
        RiskConfig(decay_factor=1.5)  # decay must be <= 1.0

    with pytest.raises(ValidationError):
        RiskConfig(critical_threshold=1.2)  # threshold must be <= 1.0
