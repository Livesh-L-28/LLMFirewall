"""Comprehensive test suite for Phase 36 — AI Security Compliance & Control Mapping."""

import json
import os
from pathlib import Path
import time
import pytest
import yaml

from llmfirewall.compliance import (
    AI_SECURITY_BASELINE_CONTROLS,
    ApplicabilityStatus,
    ComplianceControl,
    ComplianceDiff,
    ComplianceEngine,
    ComplianceEvidence,
    ComplianceException,
    ComplianceFramework,
    ComplianceGap,
    ComplianceMetrics,
    ComplianceRule,
    ComplianceRuleContext,
    ComplianceRuleRegistry,
    ComplianceSnapshot,
    ControlAssessment,
    ControlCatalog,
    ControlMapping,
    ControlState,
    CrossFrameworkMapping,
    EvidenceType,
    EvidenceValidity,
    ExceptionStatus,
    MappingType,
    RemediationStatus,
    STANDARD_COMPLIANCE_RULES,
    format_compliance_human,
    format_compliance_json,
    format_compliance_yaml,
    format_control_detail_human,
    format_diff_human,
    format_evidence_human,
    format_gaps_human,
    sanitize_compliance_metadata,
)
from llmfirewall.core.models import Severity


# =============================================================================
# 1. Unit Tests — Models & Schemas (Section 71)
# =============================================================================

def test_control_state_enum_semantics():
    """Verify all 9 standardized control states exist."""
    expected_states = {
        "NOT_ASSESSED",
        "NOT_APPLICABLE",
        "NOT_IMPLEMENTED",
        "PARTIALLY_IMPLEMENTED",
        "IMPLEMENTED",
        "PARTIALLY_EVIDENCED",
        "EVIDENCED",
        "FAILED",
        "UNKNOWN",
    }
    actual_states = {s.value for s in ControlState}
    assert actual_states == expected_states


def test_compliance_control_creation_and_validation():
    """Verify ComplianceControl creation and field validation."""
    ctrl = ComplianceControl(
        id="ai-baseline:AC-01",
        framework_id="ai-security-baseline",
        control_id="AC-01",
        title="Tool Authorization",
        description="Verify tool authorizations",
        category="access_control",
        domain="Access Control",
        requirements=["Require policy enforcement", "Audit invocations"],
        evidence_requirements=["authorization_policy", "authorization_test"],
        applicability={"asset_types": ["agent", "tool"]},
    )
    assert ctrl.id == "ai-baseline:AC-01"
    assert ctrl.control_id == "AC-01"
    assert len(ctrl.requirements) == 2
    assert "authorization_policy" in ctrl.evidence_requirements

    # Reject empty ID
    with pytest.raises(ValueError):
        ComplianceControl(
            id="   ",
            framework_id="f",
            control_id="c",
            title="t",
        )


def test_compliance_framework_pack_and_checksum():
    """Verify framework calculation of checksum and validation."""
    ctrl = ComplianceControl(
        id="test-fw:C-01",
        framework_id="test-fw",
        control_id="C-01",
        title="Test Control",
    )
    fw = ComplianceFramework(
        id="test-fw",
        name="Test Framework",
        version="1.0.0",
        controls={ctrl.id: ctrl},
    )
    assert fw.id == "test-fw"
    assert len(fw.checksum) == 64  # SHA-256


def test_compliance_evidence_freshness_and_expiry():
    """Verify evidence expiration logic."""
    now = time.time()
    valid_evid = ComplianceEvidence(
        type=EvidenceType.SECURITY_TEST,
        source="test_suite",
        asset_id="agent:support",
        control_id="ai-baseline:AC-01",
        collected_at=now,
        expires_at=now + 3600,
        content_reference="test:passed",
    )
    assert valid_evid.is_expired is False

    expired_evid = ComplianceEvidence(
        type=EvidenceType.SECURITY_TEST,
        source="test_suite",
        asset_id="agent:support",
        control_id="ai-baseline:AC-01",
        collected_at=now - 5000,
        expires_at=now - 100,
        content_reference="test:old",
    )
    assert expired_evid.is_expired is True


def test_compliance_exception_lifecycle():
    """Verify formal compliance exception and expiration check."""
    now = time.time()
    active_exc = ComplianceException(
        control_id="ai-baseline:AC-01",
        asset_id="agent:support",
        reason="Approved temporary migration waiver",
        approved_by="CISO Office",
        expires_at=now + 3600,
    )
    assert active_exc.is_active is True

    expired_exc = ComplianceException(
        control_id="ai-baseline:AC-01",
        asset_id="agent:support",
        reason="Expired exception",
        approved_by="CISO Office",
        expires_at=now - 100,
    )
    assert expired_exc.is_active is False

    # Empty approval rejected
    with pytest.raises(ValueError):
        ComplianceException(
            control_id="ai-baseline:AC-01",
            asset_id="agent:support",
            reason="No approver",
            approved_by="",
            expires_at=now + 3600,
        )


def test_sanitize_compliance_metadata_scrubs_secrets():
    """Verify secrets and API keys are recursively redacted."""
    raw = {
        "api_key": "sk-123456789012345678901234",
        "description": "Safe description",
        "nested": {
            "token": "ghp_abcdefghijklmnopqrstuvwxyz",
            "password": "supersecretpassword",
            "safe_control_id": "ai-baseline:AC-01",
        },
    }
    clean = sanitize_compliance_metadata(raw)
    assert clean["api_key"] == "[REDACTED_CREDENTIAL]"
    assert clean["description"] == "Safe description"
    assert clean["nested"]["token"] == "[REDACTED_CREDENTIAL]"
    assert clean["nested"]["password"] == "[REDACTED_CREDENTIAL]"
    assert clean["nested"]["safe_control_id"] == "ai-baseline:AC-01"


# =============================================================================
# 2. Control Catalog & Safe Parsing (Sections 8, 9, 10, 27, 28, 29, 30)
# =============================================================================

def test_starter_catalog_loading():
    """Verify built-in starter catalog has 15 AI domains."""
    cat = ControlCatalog()
    fw = cat.get_framework("ai-security-baseline")
    assert fw is not None
    assert len(fw.controls) >= 15
    # Verify key domains are present
    categories = {c.category for c in fw.controls.values()}
    assert "asset_management" in categories
    assert "access_control" in categories
    assert "prompt_security" in categories
    assert "rag_security" in categories


def test_load_custom_yaml_framework_pack(tmp_path):
    """Verify declarative YAML framework pack loading with safe parsing."""
    pack_data = {
        "framework": {
            "id": "company-ai-security",
            "name": "Acme AI Security Baseline",
            "version": "2.1.0",
            "description": "Custom organizational AI compliance controls",
            "source": "Acme Infosec",
        },
        "controls": [
            {
                "id": "CUSTOM-01",
                "title": "Model Sandboxing",
                "category": "model_security",
                "domain": "Model Security",
                "requirements": ["Models must run in isolated namespaces"],
                "evidence": ["namespace_config", "isolation_test"],
                "applicability": {"asset_types": ["model"]},
            }
        ],
    }
    pack_file = tmp_path / "custom_pack.yaml"
    pack_file.write_text(yaml.safe_dump(pack_data), encoding="utf-8")

    cat = ControlCatalog()
    fw = cat.load_pack_from_file(str(pack_file))
    assert fw.id == "company-ai-security"
    assert fw.version == "2.1.0"
    assert "company-ai-security:CUSTOM-01" in fw.controls


def test_duplicate_control_ids_rejected(tmp_path):
    """Verify duplicate control IDs within the same pack are strictly rejected."""
    pack_data = {
        "framework": {"id": "bad-pack", "name": "Bad Pack", "version": "1.0"},
        "controls": [
            {"id": "AC-01", "title": "First AC-01"},
            {"id": "AC-01", "title": "Duplicate AC-01"},
        ],
    }
    pack_file = tmp_path / "dup.json"
    pack_file.write_text(json.dumps(pack_data), encoding="utf-8")

    cat = ControlCatalog()
    with pytest.raises(ValueError, match="Duplicate control ID"):
        cat.load_pack_from_file(str(pack_file))


def test_oversized_pack_rejected(tmp_path):
    """Verify packs exceeding 5MB are rejected."""
    huge_data = {
        "framework": {"id": "huge", "name": "Huge", "version": "1.0"},
        "controls": [
            {"id": f"CTRL-{i:05d}", "title": "X" * 1000} for i in range(6000)
        ],
    }
    huge_file = tmp_path / "huge.json"
    huge_file.write_text(json.dumps(huge_data), encoding="utf-8")

    cat = ControlCatalog()
    with pytest.raises(ValueError, match="maximum limit"):
        cat.load_pack_from_file(str(huge_file))


def test_cross_framework_mapping():
    """Verify many-to-many cross-framework mappings."""
    cat = ControlCatalog()
    cat.add_cross_mapping(
        source_control_id="company-ai:AC-01",
        target_control_id="ai-baseline:AC-01",
        mapping_type=MappingType.EXACT,
        rationale="Both enforce agent tool invocation authorization policies.",
    )
    maps = cat.get_cross_mappings("company-ai:AC-01")
    assert len(maps) == 1
    assert maps[0].target_control_id == "ai-baseline:AC-01"
    assert maps[0].mapping_type == MappingType.EXACT


# =============================================================================
# 3. Assessment Logic & States (Sections 20, 25, 72)
# =============================================================================

def test_control_applicability_filtering():
    """Verify control is marked NOT_APPLICABLE for irrelevant asset types."""
    engine = ComplianceEngine()
    # AC-01 applies only to agents and tools
    res = engine.assess_control("ai-baseline:AC-01", "model:gpt-4o")
    assert res.status == ControlState.NOT_APPLICABLE
    assert res.applicability == ApplicabilityStatus.NOT_APPLICABLE
    assert "Control applies to asset types [agent, tool]" in res.applicability_reason


def test_unimplemented_control_assessment():
    """Applicable asset with zero defensive controls is marked NOT_IMPLEMENTED."""
    engine = ComplianceEngine()
    # agent:support with no registered evidence or controls
    res = engine.assess_control("ai-baseline:AC-01", "agent:unconfigured-support")
    assert res.status == ControlState.NOT_IMPLEMENTED
    assert len(res.gaps) >= 1
    assert res.gaps[0].severity == Severity.HIGH


def test_fully_evidenced_control():
    """Control with all required evidence present and fresh is marked EVIDENCED."""
    engine = ComplianceEngine()
    aid = "agent:protected-support"
    cid = "ai-baseline:AC-01"

    now = time.time()
    # AC-01 requires authorization_policy, authorization_test, production_configuration
    engine.add_evidence(ComplianceEvidence(
        type=EvidenceType.POLICY,
        source="governance",
        asset_id=aid,
        control_id=cid,
        content_reference="authorization_policy:enforced",
        status=EvidenceValidity.VALID,
    ))
    engine.add_evidence(ComplianceEvidence(
        type=EvidenceType.SECURITY_TEST,
        source="test_runner",
        asset_id=aid,
        control_id=cid,
        content_reference="authorization_test:passed",
        status=EvidenceValidity.VALID,
    ))
    engine.add_evidence(ComplianceEvidence(
        type=EvidenceType.CONFIGURATION,
        source="runtime",
        asset_id=aid,
        control_id=cid,
        content_reference="production_configuration:verified",
        status=EvidenceValidity.VALID,
    ))

    res = engine.assess_control(cid, aid)
    assert res.status == ControlState.EVIDENCED
    assert len(res.missing_evidence) == 0
    assert len(res.gaps) == 0
    # Verify Section 63 Evidence Chain Traceability
    assert res.evidence_chain["framework_control"] == cid
    assert res.evidence_chain["asset"] == aid
    assert len(res.evidence_chain["evidence"]) == 3


def test_partially_evidenced_control():
    """Control missing one of its required evidence items is PARTIALLY_EVIDENCED."""
    engine = ComplianceEngine()
    aid = "agent:partial-support"
    cid = "ai-baseline:AC-01"

    # Only policy is provided, test and production configuration are missing
    engine.add_evidence(ComplianceEvidence(
        type=EvidenceType.POLICY,
        source="governance",
        asset_id=aid,
        control_id=cid,
        content_reference="authorization_policy:enforced",
        status=EvidenceValidity.VALID,
    ))

    res = engine.assess_control(cid, aid)
    assert res.status == ControlState.PARTIALLY_EVIDENCED
    assert len(res.gaps) >= 1
    assert "authorization_test" in res.missing_evidence
    assert "production_configuration" in res.missing_evidence


# =============================================================================
# 4. Evidence Freshness, Staleness, Conflicts, Expiry (Sections 16, 17, 18, 73)
# =============================================================================

def test_conflicting_evidence_fails_control():
    """Conflicting policy vs runtime evidence fails the control (Section 18)."""
    engine = ComplianceEngine()
    aid = "agent:conflicted"
    cid = "ai-baseline:AC-01"

    # 1. Policy evidence says enabled
    engine.add_evidence(ComplianceEvidence(
        type=EvidenceType.POLICY,
        source="governance",
        asset_id=aid,
        control_id=cid,
        content_reference="authorization_policy:enabled",
        status=EvidenceValidity.VALID,
    ))
    # 2. Runtime evidence says disabled
    engine.add_evidence(ComplianceEvidence(
        type=EvidenceType.RUNTIME_EVENT,
        source="runtime",
        asset_id=aid,
        control_id=cid,
        content_reference="authorization_policy:disabled",
        status=EvidenceValidity.VALID,
    ))

    res = engine.assess_control(cid, aid)
    assert res.status == ControlState.FAILED
    assert any("Conflicting Evidence Detected" in g.title for g in res.gaps)


def test_failed_security_test_fails_control():
    """Negative evidence from a failing security test marks control FAILED."""
    engine = ComplianceEngine()
    aid = "agent:failing-tool"
    cid = "ai-baseline:AC-01"

    # Attach failing test in rule context by mocking spm test result
    class MockSPM:
        _ingested_test_results = [
            {"test_id": "TEST-TOOL-AUTH-01", "asset_id": aid, "name": "Tool bypass", "passed": False}
        ]
        _ingested_findings = []
        def evaluate(self, aid):
            return None

    engine.spm = MockSPM()
    res = engine.assess_control(cid, aid)
    assert res.status == ControlState.FAILED
    assert any("Security Test Failed" in g.title for g in res.gaps)


# =============================================================================
# 5. Exceptions, Waivers & Expiration (Sections 38, 39, 75)
# =============================================================================

def test_active_exception_mitigates_control():
    """Active approved exception provides valid waiver."""
    engine = ComplianceEngine()
    aid = "agent:waived-agent"
    cid = "ai-baseline:AC-01"

    exc = engine.add_exception(
        control_id=cid,
        asset_id=aid,
        reason="Approved temporary migration",
        approved_by="Security Architecture Board",
        duration_seconds=3600,
    )
    assert exc.is_active is True

    res = engine.assess_control(cid, aid)
    assert res.status == ControlState.IMPLEMENTED
    assert "Formally waived" in res.applicability_reason
    assert len(res.exceptions) == 1


def test_expired_exception_triggers_reassessment():
    """Expired exception triggers reassessment and gap creation."""
    engine = ComplianceEngine()
    aid = "agent:expired-waived-agent"
    cid = "ai-baseline:AC-01"

    # Create exception that expired in the past
    exc = engine.add_exception(
        control_id=cid,
        asset_id=aid,
        reason="Temporary waiver",
        approved_by="CISO",
        duration_seconds=-10,  # Expired
    )
    assert exc.is_active is False

    res = engine.assess_control(cid, aid)
    assert res.status != ControlState.IMPLEMENTED
    assert res.status in (ControlState.NOT_IMPLEMENTED, ControlState.PARTIALLY_EVIDENCED)


# =============================================================================
# 6. Manual Attestations (Section 40)
# =============================================================================

def test_manual_attestation_registration():
    """Verify explicit human attestation tracking."""
    engine = ComplianceEngine()
    aid = "agent:support"
    cid = "ai-baseline:AC-01"

    evid = engine.add_manual_attestation(
        control_id=cid,
        asset_id=aid,
        attestor="alice@company.com",
        statement="Reviewed IAM permissions and confirmed least privilege RBAC.",
        scope="agent",
        duration_seconds=86400 * 30,
    )
    assert evid.type == EvidenceType.MANUAL_ATTESTATION
    assert evid.attestation["attestor"] == "alice@company.com"
    assert evid.is_expired is False


# =============================================================================
# 7. Snapshots, Diffing & Regression Detection (Sections 47, 48, 49, 76)
# =============================================================================

def test_compliance_snapshot_and_regression_diff():
    """Verify cryptographic snapshots and compliance regression detection."""
    engine = ComplianceEngine()
    aid = "agent:regression-test"
    cid = "ai-baseline:AC-01"

    # Day 1: Fully Evidenced
    now = time.time()
    for ref in ["authorization_policy", "authorization_test", "production_configuration"]:
        engine.add_evidence(ComplianceEvidence(
            type=EvidenceType.SECURITY_TEST if "test" in ref else EvidenceType.POLICY,
            source="test",
            asset_id=aid,
            control_id=cid,
            content_reference=ref,
            status=EvidenceValidity.VALID,
        ))

    snap1 = engine.snapshot()
    assert f"{cid}@{aid}" in snap1.assessments
    assert snap1.assessments[f"{cid}@{aid}"].status == ControlState.EVIDENCED

    # Day 2: Test expires or is removed, degrading control to PARTIALLY_EVIDENCED
    engine2 = ComplianceEngine()
    engine2.add_evidence(ComplianceEvidence(
        type=EvidenceType.POLICY,
        source="test",
        asset_id=aid,
        control_id=cid,
        content_reference="authorization_policy",
        status=EvidenceValidity.VALID,
    ))

    snap2 = engine2.snapshot()
    assert snap2.assessments[f"{cid}@{aid}"].status == ControlState.PARTIALLY_EVIDENCED

    diff = engine.diff(snap1, snap2)
    assert diff.is_identical is False
    assert len(diff.regressions) >= 1
    assert "COMPLIANCE_REGRESSION" in diff.regressions[0]
    assert len(diff.new_gaps) >= 1


# =============================================================================
# 8. SARIF Export (Section 61)
# =============================================================================

def test_sarif_export_format():
    """Verify SARIF 2.1.0 output formatting for actionable gaps."""
    engine = ComplianceEngine()
    aid = "agent:sarif-test"
    cid = "ai-baseline:AC-01"

    # Force gap creation
    assessment = engine.assess_control(cid, aid)
    sarif = engine.export_sarif(assessment.gaps)
    assert sarif["version"] == "2.1.0"
    assert len(sarif["runs"]) == 1
    assert len(sarif["runs"][0]["results"]) >= 1
    first_res = sarif["runs"][0]["results"][0]
    assert first_res["ruleId"] == cid
    assert f"asset://{aid}" in first_res["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]


# =============================================================================
# 9. Factual Coverage Calculation (Section 33)
# =============================================================================

def test_factual_coverage_calculation():
    """Verify factual coverage metrics without deceptive compliance scores."""
    engine = ComplianceEngine()
    assessments = [
        ControlAssessment(framework_id="f", control_id="c1", asset_id="a1", status=ControlState.EVIDENCED, applicability=ApplicabilityStatus.APPLICABLE),
        ControlAssessment(framework_id="f", control_id="c2", asset_id="a1", status=ControlState.PARTIALLY_EVIDENCED, applicability=ApplicabilityStatus.APPLICABLE),
        ControlAssessment(framework_id="f", control_id="c3", asset_id="a1", status=ControlState.NOT_IMPLEMENTED, applicability=ApplicabilityStatus.APPLICABLE),
        ControlAssessment(framework_id="f", control_id="c4", asset_id="a1", status=ControlState.NOT_APPLICABLE, applicability=ApplicabilityStatus.NOT_APPLICABLE),
    ]
    cov = engine.calculate_coverage(assessments)
    assert cov["total_controls"] == 4
    assert cov["applicable_controls"] == 3
    assert cov["not_applicable_controls"] == 1
    assert cov["evidenced"] == 1
    assert cov["partially_evidenced"] == 1
    assert cov["not_implemented"] == 1
    assert "NOT legal or regulatory certification" in cov["methodology_disclaimer"]
