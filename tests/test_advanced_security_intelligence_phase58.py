"""Unit, integration, and security tests for Phase 58 — Advanced Security Intelligence."""

import pytest
from llmfirewall.core.models import Finding, Severity, ThreatType
from llmfirewall.risk.advanced_correlation import (
    AdvancedSecurityCorrelator,
    AttackProgressionStage,
    CorrelatedEntityRef,
    ExplainableCorrelation,
    IncidentSecurityContext,
)
from llmfirewall.risk.correlation import FindingCorrelationEngine
from llmfirewall.inventory.models import Asset, AssetType


def test_correlator_empty_findings():
    """Verify correlator produces benign posture context when no findings are present."""
    correlator = AdvancedSecurityCorrelator()
    ctx = correlator.correlate_incident(findings=[])
    assert isinstance(ctx, IncidentSecurityContext)
    assert ctx.total_findings == 0
    assert len(ctx.correlations) == 0
    assert ctx.peak_severity == Severity.INFO
    assert ctx.composite_risk_score == 0.0
    assert "No findings or compound attack patterns" in ctx.narrative_summary


def test_correlator_single_isolated_finding():
    """Verify single finding is recognized as isolated activity without artificial compound chains."""
    correlator = AdvancedSecurityCorrelator()
    f = Finding(
        id="f-pii-1",
        detector_name="pii_detector",
        threat_type=ThreatType.PII,
        severity=Severity.LOW,
        confidence=0.85,
        description="Detected email address",
    )
    ctx = correlator.correlate_incident(findings=[f], session_id="sess-100")
    assert ctx.total_findings == 1
    assert len(ctx.correlations) == 0
    assert ctx.session_id == "sess-100"
    assert "Isolated activity: 1 atomic finding(s)" in ctx.narrative_summary


def test_correlator_compound_exfiltration_with_assets_and_paths():
    """Verify prompt injection + secret finding connects to assets, attack paths, and progression stage."""
    correlator = AdvancedSecurityCorrelator()

    f1 = Finding(
        id="f-inj-1",
        detector_name="prompt_injection_detector",
        threat_type=ThreatType.PROMPT_INJECTION,
        severity=Severity.HIGH,
        confidence=0.92,
        description="System prompt override directive detected",
    )
    f2 = Finding(
        id="f-sec-1",
        detector_name="secret_detector",
        threat_type=ThreatType.SECRET,
        severity=Severity.CRITICAL,
        confidence=0.98,
        description="AWS Access Key detected in content",
    )

    asset1 = Asset(
        id="asset-crm-db",
        name="Customer CRM Database",
        type=AssetType.DATABASE,
    )

    attack_path_ids = ["path-pi-to-db-exfil"]

    ctx = correlator.correlate_incident(
        findings=[f1, f2],
        session_id="sess-adversary-42",
        assets=[asset1],
        attack_paths=attack_path_ids,
    )

    assert ctx.total_findings == 2
    assert len(ctx.correlations) == 1
    corr = ctx.correlations[0]

    assert corr.progression_stage == AttackProgressionStage.EXFILTRATION
    assert corr.severity == Severity.CRITICAL
    assert corr.confidence > 0.90
    assert "asset-crm-db" in corr.affected_asset_ids
    assert "path-pi-to-db-exfil" in corr.attack_path_ids
    assert "sess-adversary-42" in corr.session_ids

    # Verify explainability fields
    assert "prompt_injection" in corr.root_cause_explanation
    assert "secret" in corr.root_cause_explanation
    assert len(corr.evidence_timeline) == 2
    assert len(corr.recommended_containment) > 0
    assert len(ctx.containment_steps) > 0
    assert "Active security incident identified" in ctx.narrative_summary


def test_correlator_execution_chain_with_tool_context():
    """Verify injection + dangerous tool context produces execution progression stage."""
    correlator = AdvancedSecurityCorrelator()
    f = Finding(
        id="f-inj-exec",
        detector_name="prompt_injection_detector",
        threat_type=ThreatType.PROMPT_INJECTION,
        severity=Severity.HIGH,
        confidence=0.95,
        description="Shell escape command sequence",
    )

    ctx = correlator.correlate_incident(
        findings=[f],
        session_id="sess-terminal-01",
        context={"tool_name": "bash", "tool_args": "rm -rf /"},
    )

    assert len(ctx.correlations) == 1
    corr = ctx.correlations[0]
    assert corr.progression_stage == AttackProgressionStage.EXECUTION
    assert corr.severity == Severity.CRITICAL
    assert "tool:bash" in ctx.affected_assets or "default-llm-service" in ctx.affected_assets


def test_correlator_deterministic_reproducibility():
    """Verify identical inputs yield exact deterministic scores and correlation IDs."""
    correlator = AdvancedSecurityCorrelator()
    f1 = Finding(
        id="f-det-1",
        detector_name="prompt_injection_detector",
        threat_type=ThreatType.PROMPT_INJECTION,
        severity=Severity.HIGH,
        confidence=0.88,
        description="Ignore instructions",
    )
    f2 = Finding(
        id="f-det-2",
        detector_name="secret_detector",
        threat_type=ThreatType.SECRET,
        severity=Severity.CRITICAL,
        confidence=0.95,
        description="API token detected",
    )

    r1 = correlator.correlate_incident([f1, f2], session_id="sess-rep")
    r2 = correlator.correlate_incident([f1, f2], session_id="sess-rep")

    assert r1.composite_risk_score == r2.composite_risk_score
    assert r1.peak_severity == r2.peak_severity
    assert len(r1.correlations) == len(r2.correlations)
    assert r1.correlations[0].title == r2.correlations[0].title
    assert r1.correlations[0].confidence == r2.correlations[0].confidence
