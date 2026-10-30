"""Comprehensive test suite for Phase 31: AI Security Governance, Security Gates & Continuous Assurance."""

import asyncio
import json
import os
import tempfile
import threading
import time
import pytest

from llmfirewall.audit import AuditLogger
from llmfirewall.core.models import Action, Severity
from llmfirewall.eval.models import AttackCategory, SecurityFinding, SecurityTestResult, TargetType
from llmfirewall.firewall import Firewall
from llmfirewall.governance import (
    BaselineCategory,
    BaselineDiff,
    EvidenceArtifactRecord,
    EvidenceManifest,
    FindingStatus,
    GateEvaluationResult,
    GateType,
    GovernanceDecision,
    GovernanceEngine,
    GovernanceFinding,
    GovernanceMetrics,
    GovernanceOverride,
    GovernancePolicy,
    GovernanceResult,
    ReasonCode,
    ReleaseProfile,
    SecurityBaseline,
    SecurityChangeClassification,
    SecurityEvidence,
    SecurityGate,
    SecurityGateFailure,
    SecurityReleaseManifest,
    SecurityWaiver,
    format_governance_human,
    format_governance_json,
    format_governance_sarif,
)
from llmfirewall.supply_chain.models import ConfigArtifact, SecuritySnapshot, SnapshotDiff


# ---------------------------------------------------------------------------
# 1. Governance Decision & Enums Tests
# ---------------------------------------------------------------------------

def test_governance_decision_values():
    assert GovernanceDecision.PASS == "PASS"
    assert GovernanceDecision.FAIL == "FAIL"
    assert GovernanceDecision.REVIEW == "REVIEW"
    assert GovernanceDecision.BLOCK == "BLOCK"
    assert GovernanceDecision.NOT_EVALUATED == "NOT_EVALUATED"


def test_reason_code_values():
    assert ReasonCode.REQUIRED_GATE_FAILED == "REQUIRED_GATE_FAILED"
    assert ReasonCode.CRITICAL_FINDING == "CRITICAL_FINDING"
    assert ReasonCode.MISSING_EVIDENCE == "MISSING_EVIDENCE"
    assert ReasonCode.BASELINE_REGRESSION == "BASELINE_REGRESSION"
    assert ReasonCode.TAMPERING_DETECTED == "TAMPERING_DETECTED"
    assert ReasonCode.CAPABILITY_EXPANSION == "CAPABILITY_EXPANSION"


# ---------------------------------------------------------------------------
# 2. SecurityGate Specification & Validation Tests
# ---------------------------------------------------------------------------

def test_security_gate_validation():
    gate = SecurityGate(
        id="test-pi",
        type=GateType.TEST_GATE,
        name="Prompt Injection Gate",
        required=True,
        minimum_pass_rate=0.95,
        required_tests=["PI-001", "PI-002"],
        block_on=[Severity.CRITICAL],
        max_allowed_severity=Severity.HIGH,
    )
    assert gate.id == "test-pi"
    assert gate.minimum_pass_rate == 0.95
    assert "PI-001" in gate.required_tests

    # Invalid empty ID
    with pytest.raises(ValueError):
        SecurityGate(id="   ", type=GateType.TEST_GATE)


# ---------------------------------------------------------------------------
# 3. Finding Lifecycle & Fingerprinting Tests
# ---------------------------------------------------------------------------

def test_finding_deterministic_fingerprint():
    fp1 = GovernanceFinding.compute_fingerprint(
        category="prompt_injection",
        test_id="PI-001",
        rule_id="RULE-1",
        resource="llm_input",
    )
    fp2 = GovernanceFinding.compute_fingerprint(
        category="prompt_injection",
        test_id="PI-001",
        rule_id="RULE-1",
        resource="llm_input",
    )
    assert fp1 == fp2
    assert len(fp1) == 24

    # Different resource yields different fingerprint
    fp3 = GovernanceFinding.compute_fingerprint(
        category="prompt_injection",
        test_id="PI-001",
        rule_id="RULE-1",
        resource="different_resource",
    )
    assert fp1 != fp3


def test_finding_lifecycle_transitions():
    finding = GovernanceFinding.from_test_finding(
        category="secret_exposure",
        description="Potential secret detected in output",
        severity=Severity.HIGH,
        test_id="SEC-001",
    )
    assert finding.status == FindingStatus.OPEN

    accepted = finding.with_status(
        new_status=FindingStatus.ACCEPTED,
        owner="secops-team",
        reason="Test environment only",
        expires_at=time.time() + 3600,
        waiver_id="WAIVER-001",
    )
    assert accepted.status == FindingStatus.ACCEPTED
    assert accepted.owner == "secops-team"
    assert accepted.waiver_id == "WAIVER-001"
    assert accepted.fingerprint == finding.fingerprint


# ---------------------------------------------------------------------------
# 4. Security Waiver Creation, Scoping, Expiration & Tamper Resistance
# ---------------------------------------------------------------------------

def test_waiver_creation_and_integrity():
    future = time.time() + 86400
    waiver = SecurityWaiver.create(
        owner="security-lead",
        reason="Low-impact benign edge case",
        expires_at=future,
        test_id="PI-001",
    )
    assert waiver.verify_integrity() is True
    assert waiver.is_expired() is False

    finding_pi = GovernanceFinding.from_test_finding(
        category="prompt_injection",
        description="Edge case injection",
        severity=Severity.MEDIUM,
        test_id="PI-001",
    )
    assert waiver.matches_finding(finding_pi) is True

    # Waiver for PI-001 must NOT match TOOL-001 (scope isolation)
    finding_tool = GovernanceFinding.from_test_finding(
        category="tool_abuse",
        description="Tool command injection",
        severity=Severity.HIGH,
        test_id="TOOL-001",
    )
    assert waiver.matches_finding(finding_tool) is False


def test_waiver_expiration():
    past = time.time() - 3600
    waiver = SecurityWaiver.create(
        owner="security-lead",
        reason="Expired exception",
        expires_at=past,
        test_id="PI-001",
    )
    assert waiver.is_expired() is True
    finding = GovernanceFinding.from_test_finding(
        category="prompt_injection",
        description="Issue",
        severity=Severity.MEDIUM,
        test_id="PI-001",
    )
    # Expired waiver must not match as active
    assert waiver.matches_finding(finding) is False


def test_waiver_tampering_detection():
    future = time.time() + 86400
    waiver = SecurityWaiver.create(
        owner="security-lead",
        reason="Authorized scope",
        expires_at=future,
        test_id="PI-001",
    )
    assert waiver.verify_integrity() is True

    # Tampered waiver: modifying test_id scope without recalculating digest
    tampered_data = waiver.model_dump()
    tampered_data["test_id"] = "TOOL-001"
    tampered = SecurityWaiver(**tampered_data)
    assert tampered.verify_integrity() is False


# ---------------------------------------------------------------------------
# 5. Security Baseline Creation, Tamper Resistance & Diff
# ---------------------------------------------------------------------------

def test_baseline_creation_and_integrity():
    baseline = SecurityBaseline.create(
        baseline_id="BASE-001",
        version="1.0",
        policy_version="1.0",
        configuration_hash="abc123hash",
        findings=[],
    )
    assert baseline.baseline_id == "BASE-001"
    assert baseline.verify_integrity() is True

    # Tampering with baseline configuration_hash
    raw = json.loads(baseline.to_json())
    raw["configuration_hash"] = "malicious_change"
    tampered = SecurityBaseline(**raw)
    assert tampered.verify_integrity() is False


def test_baseline_diff_comparison():
    f1 = GovernanceFinding.from_test_finding(
        category="prompt_injection",
        description="Injection 1",
        severity=Severity.LOW,
        test_id="PI-001",
    )
    baseline = SecurityBaseline.create(
        baseline_id="BASE-REG",
        findings=[f1],
    )

    # Run 1: Same finding -> unchanged, identical
    diff_same = baseline.compare_findings([f1])
    assert diff_same.is_identical is True
    assert len(diff_same.unchanged_findings) == 1

    # Run 2: New finding added -> regression
    f2 = GovernanceFinding.from_test_finding(
        category="tool_abuse",
        description="Tool abuse finding",
        severity=Severity.HIGH,
        test_id="TOOL-001",
    )
    diff_new = baseline.compare_findings([f1, f2])
    assert diff_new.is_identical is False
    assert len(diff_new.new_findings) == 1
    assert len(diff_new.regressions) >= 1

    # Run 3: f1 resolved -> resolved_findings
    diff_resolved = baseline.compare_findings([])
    assert len(diff_resolved.resolved_findings) == 1


# ---------------------------------------------------------------------------
# 6. Governance Engine: Test Gate & Required Tests Evaluation
# ---------------------------------------------------------------------------

def test_engine_test_gate_pass():
    policy = GovernancePolicy(
        name="test-policy",
        version="1.0",
        gates=[
            SecurityGate(
                id="core-tests",
                type=GateType.TEST_GATE,
                required=True,
                minimum_pass_rate=1.0,
            )
        ],
        require=["core-tests"],
    )
    engine = GovernanceEngine()

    result_pass = SecurityTestResult(
        test_id="PI-001",
        category=AttackCategory.PROMPT_INJECTION,
        target_type=TargetType.PROMPT,
        severity=Severity.MEDIUM,
        passed=True,
        actual_action=Action.BLOCK,
        expected_action=Action.BLOCK,
    )
    evidence = SecurityEvidence(test_results=[result_pass])
    res = engine.evaluate(evidence, policy=policy)
    assert res.decision == GovernanceDecision.PASS
    assert res.passed is True
    assert res.blocked is False
    assert ReasonCode.ALL_CONTROLS_SATISFIED in res.reason_codes


def test_engine_missing_evidence_not_pass():
    """Missing required evidence must yield BLOCK or REVIEW, NEVER silent PASS!"""
    policy = GovernancePolicy(
        name="test-policy",
        version="1.0",
        gates=[
            SecurityGate(
                id="mandatory-tests",
                type=GateType.TEST_GATE,
                required=True,
            )
        ],
        require=["mandatory-tests"],
    )
    engine = GovernanceEngine()
    empty_evidence = SecurityEvidence(test_results=[])
    res = engine.evaluate(empty_evidence, policy=policy)

    assert res.decision != GovernanceDecision.PASS
    assert res.decision in (GovernanceDecision.BLOCK, GovernanceDecision.FAIL)
    assert ReasonCode.MISSING_EVIDENCE in res.reason_codes
    assert "mandatory-tests" in res.missing_evidence


def test_engine_required_tests_missing():
    policy = GovernancePolicy(
        name="test-policy",
        version="1.0",
        gates=[
            SecurityGate(
                id="req-gate",
                type=GateType.TEST_GATE,
                required=True,
                required_tests=["PI-001", "PI-002"],
            )
        ],
    )
    engine = GovernanceEngine()
    # Only PI-001 executed, PI-002 is missing
    r1 = SecurityTestResult(
        test_id="PI-001",
        category=AttackCategory.PROMPT_INJECTION,
        target_type=TargetType.PROMPT,
        severity=Severity.MEDIUM,
        passed=True,
        actual_action=Action.BLOCK,
        expected_action=Action.BLOCK,
    )
    res = engine.evaluate(SecurityEvidence(test_results=[r1]), policy=policy)
    assert res.decision in (GovernanceDecision.BLOCK, GovernanceDecision.FAIL)
    assert ReasonCode.MISSING_REQUIRED_TEST in res.reason_codes


def test_engine_pass_rate_threshold():
    policy = GovernancePolicy(
        name="test-policy",
        version="1.0",
        gates=[
            SecurityGate(
                id="rate-gate",
                type=GateType.TEST_GATE,
                required=True,
                minimum_pass_rate=0.90,
            )
        ],
    )
    engine = GovernanceEngine()
    # 1 pass, 1 fail -> 50% pass rate < 90%
    r1 = SecurityTestResult(
        test_id="PI-001",
        category=AttackCategory.PROMPT_INJECTION,
        target_type=TargetType.PROMPT,
        severity=Severity.LOW,
        passed=True,
        actual_action=Action.BLOCK,
        expected_action=Action.BLOCK,
    )
    r2 = SecurityTestResult(
        test_id="PI-002",
        category=AttackCategory.PROMPT_INJECTION,
        target_type=TargetType.PROMPT,
        severity=Severity.LOW,
        passed=False,
        actual_action=Action.ALLOW,
        expected_action=Action.BLOCK,
    )
    res = engine.evaluate(SecurityEvidence(test_results=[r1, r2]), policy=policy)
    assert res.decision == GovernanceDecision.FAIL
    assert ReasonCode.PASS_RATE_BELOW_THRESHOLD in res.reason_codes


# ---------------------------------------------------------------------------
# 7. Severity Gate, Block-On & Expired Waivers
# ---------------------------------------------------------------------------

def test_engine_critical_finding_blocks():
    policy = GovernancePolicy(
        name="test-policy",
        version="1.0",
        block_on=[Severity.CRITICAL],
        gates=[
            SecurityGate(
                id="sec-tests",
                type=GateType.TEST_GATE,
                required=True,
                block_on=[Severity.CRITICAL],
            )
        ],
    )
    engine = GovernanceEngine()
    crit_fail = SecurityTestResult(
        test_id="SEC-001",
        category=AttackCategory.SECRET_EXPOSURE,
        target_type=TargetType.OUTPUT,
        severity=Severity.CRITICAL,
        passed=False,
        actual_action=Action.ALLOW,
        expected_action=Action.BLOCK,
    )
    res = engine.evaluate(SecurityEvidence(test_results=[crit_fail]), policy=policy)
    assert res.decision == GovernanceDecision.BLOCK
    assert res.blocked is True
    assert ReasonCode.CRITICAL_FINDING in res.reason_codes


def test_engine_active_waiver_allows():
    future = time.time() + 86400
    waiver = SecurityWaiver.create(
        owner="security-team",
        reason="Known low-risk prompt variance under review",
        expires_at=future,
        test_id="PI-001",
    )
    policy = GovernancePolicy(
        name="test-policy",
        version="1.0",
        waivers=[waiver],
        gates=[
            SecurityGate(
                id="pi-gate",
                type=GateType.TEST_GATE,
                required=True,
                block_on=[Severity.HIGH],
            )
        ],
    )
    engine = GovernanceEngine()
    pi_fail = SecurityTestResult(
        test_id="PI-001",
        category=AttackCategory.PROMPT_INJECTION,
        target_type=TargetType.PROMPT,
        severity=Severity.HIGH,
        passed=False,
        actual_action=Action.ALLOW,
        expected_action=Action.BLOCK,
    )
    res = engine.evaluate(SecurityEvidence(test_results=[pi_fail]), policy=policy)
    # Active waiver waives the finding -> PASS
    assert res.decision == GovernanceDecision.PASS
    assert res.findings[0].status == FindingStatus.ACCEPTED


def test_engine_expired_waiver_reevaluated():
    """When a waiver expires, it must be re-evaluated as active finding, not ignored!"""
    past = time.time() - 3600
    expired_waiver = SecurityWaiver.create(
        owner="security-team",
        reason="Temporary exception now expired",
        expires_at=past,
        test_id="PI-001",
    )
    policy = GovernancePolicy(
        name="test-policy",
        version="1.0",
        waivers=[expired_waiver],
        gates=[
            SecurityGate(
                id="pi-gate",
                type=GateType.TEST_GATE,
                required=True,
                block_on=[Severity.HIGH],
            )
        ],
    )
    engine = GovernanceEngine()
    pi_fail = SecurityTestResult(
        test_id="PI-001",
        category=AttackCategory.PROMPT_INJECTION,
        target_type=TargetType.PROMPT,
        severity=Severity.HIGH,
        passed=False,
        actual_action=Action.ALLOW,
        expected_action=Action.BLOCK,
    )
    res = engine.evaluate(SecurityEvidence(test_results=[pi_fail]), policy=policy)
    assert res.decision == GovernanceDecision.BLOCK
    assert ReasonCode.WAIVER_EXPIRED in res.reason_codes
    assert res.findings[0].status == FindingStatus.EXPIRED


# ---------------------------------------------------------------------------
# 8. Model Gate & Model Change Detection
# ---------------------------------------------------------------------------

def test_engine_model_change_gate():
    policy = GovernancePolicy(
        name="model-policy",
        version="1.0",
        gates=[
            SecurityGate(
                id="model-integrity",
                type=GateType.MODEL_GATE,
                required=True,
            )
        ],
    )
    baseline = SecurityBaseline.create(
        baseline_id="BASE-MOD",
        model_identity={"name": "gpt-4o", "sha256": "hash_a"},
    )
    engine = GovernanceEngine()

    # Evidence has changed model
    evidence = SecurityEvidence(
        model_identity={"name": "claude-3-opus", "sha256": "hash_b"},
    )
    res = engine.evaluate(evidence, policy=policy, baseline=baseline)
    assert ReasonCode.MODEL_CHANGED in res.reason_codes
    assert res.decision == GovernanceDecision.REVIEW


# ---------------------------------------------------------------------------
# 9. Agent Gate & Capability Expansion Detection
# ---------------------------------------------------------------------------

def test_engine_capability_expansion():
    policy = GovernancePolicy(
        name="agent-policy",
        version="1.0",
        gates=[
            SecurityGate(
                id="agent-gate",
                type=GateType.AGENT_GATE,
                required=True,
            )
        ],
    )
    baseline = SecurityBaseline.create(
        baseline_id="BASE-CAPS",
        test_configuration={"agent_capabilities": ["filesystem.read"]},
    )
    engine = GovernanceEngine()

    # Evidence has added filesystem.write (capability expansion!)
    evidence = SecurityEvidence(
        agent_capabilities=["filesystem.read", "filesystem.write"],
    )
    res = engine.evaluate(evidence, policy=policy, baseline=baseline)
    assert ReasonCode.CAPABILITY_EXPANSION in res.reason_codes
    assert res.decision == GovernanceDecision.REVIEW


# ---------------------------------------------------------------------------
# 10. Baseline Tampering Detection in Engine
# ---------------------------------------------------------------------------

def test_engine_tampered_baseline_blocked():
    policy = GovernancePolicy.default_production_policy()
    baseline = SecurityBaseline.create(
        baseline_id="BASE-LEGIT",
        configuration_hash="goodhash",
    )
    # Tamper with baseline
    tampered_data = baseline.model_dump()
    tampered_data["configuration_hash"] = "hacked_hash"
    tampered = SecurityBaseline(**tampered_data)

    engine = GovernanceEngine()
    evidence = SecurityEvidence()
    res = engine.evaluate(evidence, policy=policy, baseline=tampered)

    assert res.decision == GovernanceDecision.BLOCK
    assert ReasonCode.TAMPERING_DETECTED in res.reason_codes


# ---------------------------------------------------------------------------
# 11. Emergency Release Override
# ---------------------------------------------------------------------------

def test_engine_emergency_override():
    policy = GovernancePolicy(
        name="test-policy",
        version="1.0",
        allow_emergency_override=True,
        gates=[
            SecurityGate(
                id="strict-gate",
                type=GateType.TEST_GATE,
                required=True,
                block_on=[Severity.HIGH],
            )
        ],
    )
    engine = GovernanceEngine()
    fail_result = SecurityTestResult(
        test_id="SEC-001",
        category=AttackCategory.SECRET_EXPOSURE,
        target_type=TargetType.OUTPUT,
        severity=Severity.HIGH,
        passed=False,
        actual_action=Action.ALLOW,
        expected_action=Action.BLOCK,
    )
    evidence = SecurityEvidence(test_results=[fail_result])

    override = GovernanceOverride(
        owner="cto@company.org",
        reason="Emergency hotfix release for CVE-1234",
        emergency=True,
    )
    res = engine.evaluate(evidence, policy=policy, override=override)

    # Release proceeds with exception
    assert res.passed is True
    assert res.blocked is False
    assert ReasonCode.OVERRIDE_APPLIED in res.reason_codes
    assert res.override is not None
    assert res.override["owner"] == "cto@company.org"

    # Failed gates are preserved (NOT erased!)
    assert len(res.failed_gates) >= 1
    assert res.failed_gates[0].gate_id == "strict-gate"


# ---------------------------------------------------------------------------
# 12. Programmatic Release Check & Exception
# ---------------------------------------------------------------------------

def test_programmatic_release_check():
    fw = Firewall()
    policy = GovernancePolicy(
        name="strict-policy",
        version="1.0",
        gates=[
            SecurityGate(
                id="mandatory-test",
                type=GateType.TEST_GATE,
                required=True,
            )
        ],
    )
    evidence = fw.collect_security_evidence(test_results=[])

    # Without raise_on_blocked -> returns result
    res = fw.evaluate_governance(evidence, policy=policy, raise_on_blocked=False)
    assert res.blocked is True

    # With raise_on_blocked -> raises SecurityGateFailure
    with pytest.raises(SecurityGateFailure) as exc_info:
        fw.evaluate_governance(evidence, policy=policy, raise_on_blocked=True)
    assert "mandatory-test" in str(exc_info.value)


# ---------------------------------------------------------------------------
# 13. Reports: Human, JSON, and SARIF
# ---------------------------------------------------------------------------

def test_governance_reports():
    policy = GovernancePolicy.default_production_policy()
    engine = GovernanceEngine()
    result = SecurityTestResult(
        test_id="PI-001",
        category=AttackCategory.PROMPT_INJECTION,
        target_type=TargetType.PROMPT,
        severity=Severity.MEDIUM,
        passed=True,
        actual_action=Action.BLOCK,
        expected_action=Action.BLOCK,
    )
    res = engine.evaluate(SecurityEvidence(test_results=[result]), policy=policy)

    # 1. Human Report
    human = format_governance_human(res)
    assert "LLMFirewall Security Governance Report" in human
    assert res.release_id in human

    # 2. JSON Report
    json_out = format_governance_json(res)
    parsed = json.loads(json_out)
    assert parsed["release_id"] == res.release_id
    assert "manifest" in parsed

    # 3. SARIF Report
    sarif = format_governance_sarif(res)
    assert sarif["version"] == "2.1.0"
    assert len(sarif["runs"]) == 1


# ---------------------------------------------------------------------------
# 14. Audit Events & Telemetry Metrics
# ---------------------------------------------------------------------------

def test_governance_telemetry_and_audit():
    audit = AuditLogger()
    engine = GovernanceEngine(audit_logger=audit)
    policy = GovernancePolicy(
        name="telemetry-policy",
        version="1.0",
        gates=[
            SecurityGate(
                id="simple-gate",
                type=GateType.TEST_GATE,
                required=True,
            )
        ],
    )
    result = SecurityTestResult(
        test_id="PI-001",
        category=AttackCategory.PROMPT_INJECTION,
        target_type=TargetType.PROMPT,
        severity=Severity.MEDIUM,
        passed=True,
        actual_action=Action.BLOCK,
        expected_action=Action.BLOCK,
    )
    res = engine.evaluate(SecurityEvidence(test_results=[result]), policy=policy)
    metrics = engine.metrics.to_dict()

    assert metrics["governance_runs_total"] == 1
    assert metrics["governance_pass_total"] == 1
    assert len(audit.buffered_events) >= 2


# ---------------------------------------------------------------------------
# 15. Async Evaluation & Thread Safety
# ---------------------------------------------------------------------------

def test_async_governance_evaluation():
    engine = GovernanceEngine()
    policy = GovernancePolicy.default_development_policy()
    evidence = SecurityEvidence()
    res = asyncio.run(engine.evaluate_async(evidence, policy=policy))
    assert res is not None
    assert isinstance(res, GovernanceResult)


def test_concurrent_governance_evaluations():
    engine = GovernanceEngine()
    policy = GovernancePolicy.default_development_policy()

    errors = []

    def run_worker(worker_id: int):
        try:
            for _ in range(5):
                ev = SecurityEvidence(release_id=f"CONCUR-{worker_id}")
                res = engine.evaluate(ev, policy=policy)
                assert res.release_id == f"CONCUR-{worker_id}"
        except Exception as exc:
            errors.append(exc)

    threads = [threading.Thread(target=run_worker, args=(i,)) for i in range(5)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert len(errors) == 0
    assert engine.metrics.governance_runs_total == 25


# ---------------------------------------------------------------------------
# 16. CLI Gate & Baseline Subcommands
# ---------------------------------------------------------------------------

def test_cli_gate_and_baseline_commands():
    from llmfirewall.cli.commands import handle_baseline_compare, handle_baseline_create, handle_governance_gate

    with tempfile.TemporaryDirectory() as tmpdir:
        baseline_path = os.path.join(tmpdir, "baseline.json")

        # 1. Baseline Create
        code_create = handle_baseline_create(
            output_path=baseline_path,
            baseline_id="BASE-CLI-01",
            json_mode=True,
        )
        assert code_create == 0
        assert os.path.exists(baseline_path)

        # 2. Baseline Compare (against itself)
        code_comp = handle_baseline_compare(
            current_file=baseline_path,
            baseline_file=baseline_path,
            json_mode=True,
        )
        assert code_comp == 0

        # 3. Governance Gate
        code_gate = handle_governance_gate(
            baseline_file=baseline_path,
            ci=False,
            format_type="json",
        )
        assert code_gate in (0, 1)


def test_cli_governance_gate_snapshot_evidence():
    from llmfirewall.cli.commands import handle_governance_gate, handle_supply_chain_snapshot
    from llmfirewall.supply_chain.models import ModelArtifact

    with tempfile.TemporaryDirectory() as tmpdir:
        valid_snap_path = os.path.join(tmpdir, "valid_snap.json")
        invalid_json_path = os.path.join(tmpdir, "invalid.json")
        missing_snap_path = os.path.join(tmpdir, "nonexistent.json")
        out_report_path = os.path.join(tmpdir, "gov_out.json")

        # 1. Generate valid snapshot via genuine CLI command
        code_snap = handle_supply_chain_snapshot(output_path=valid_snap_path)
        assert code_snap == 0
        assert os.path.exists(valid_snap_path)

        # 2. Create invalid JSON file
        with open(invalid_json_path, "w", encoding="utf-8") as f:
            f.write("{invalid-json-content")

        # 3. Test invalid snapshot path returns usage error (code 2)
        code_missing = handle_governance_gate(
            snapshot_file=missing_snap_path,
            ci=False,
            format_type="json",
        )
        assert code_missing == 2

        # 4. Test corrupted snapshot file returns system error (code 3)
        code_corrupt = handle_governance_gate(
            snapshot_file=invalid_json_path,
            ci=False,
            format_type="json",
        )
        assert code_corrupt == 3

        # 5. Test missing snapshot evidence vs valid snapshot evidence
        # Missing snapshot: configuration & dependency gates missing evidence
        handle_governance_gate(
            snapshot_file=None,
            ci=False,
            format_type="json",
            output_file=out_report_path,
        )
        assert os.path.exists(out_report_path)
        res_no_snap = json.loads(open(out_report_path, encoding="utf-8").read())
        failed_gate_ids = [g["gate_id"] for g in res_no_snap.get("failed_gates", [])]
        assert "dependency-security" in failed_gate_ids
        assert "configuration-integrity" in failed_gate_ids

        # 6. Valid snapshot: dependency & configuration gates succeed
        handle_governance_gate(
            snapshot_file=valid_snap_path,
            ci=False,
            format_type="json",
            output_file=out_report_path,
        )
        assert os.path.exists(out_report_path)
        res_valid = json.loads(open(out_report_path, encoding="utf-8").read())
        passed_gate_ids = [g["gate_id"] for g in res_valid.get("passed_gates", [])]
        assert "dependency-security" in passed_gate_ids
        assert "configuration-integrity" in passed_gate_ids

        # 7. Snapshot with model identity: verifies propagation to model gate
        snap_data = json.loads(open(valid_snap_path, encoding="utf-8").read())
        model_art = ModelArtifact(
            name="test-llama-3",
            version="1.0.0",
            sha256="abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
            provider="local",
        )
        snap_data["models"] = [model_art.model_dump(mode="json")]
        model_snap_path = os.path.join(tmpdir, "model_snap.json")
        with open(model_snap_path, "w", encoding="utf-8") as f:
            json.dump(snap_data, f)

        handle_governance_gate(
            snapshot_file=model_snap_path,
            ci=False,
            format_type="json",
            output_file=out_report_path,
        )
        res_model = json.loads(open(out_report_path, encoding="utf-8").read())
        passed_with_model = [g["gate_id"] for g in res_model.get("passed_gates", [])]
        assert "model-integrity" in passed_with_model


# ---------------------------------------------------------------------------
# 28. Scoped Governance Policy & CI Workflow Verification Tests
# ---------------------------------------------------------------------------

def test_governance_policy_definitions_and_loading():
    """Verify production and library governance policy invariants and declarative YAML loading."""
    from pathlib import Path

    # 1. Production policy mandates model-integrity
    prod_policy = GovernancePolicy.default_production_policy()
    assert prod_policy.name == "production-standard-governance"
    assert "model-integrity" in prod_policy.require
    assert any(g.id == "model-integrity" and g.required for g in prod_policy.gates)

    # 2. Library policy excludes model-integrity while keeping all library gates strictly required
    lib_policy = GovernancePolicy.default_library_policy()
    assert lib_policy.name == "library-release-governance"
    assert lib_policy.profile == ReleaseProfile.PRODUCTION
    assert "model-integrity" not in lib_policy.require
    assert not any(g.id == "model-integrity" for g in lib_policy.gates)
    for req_gate in ["core-security", "dependency-security", "configuration-integrity", "agent-security"]:
        assert req_gate in lib_policy.require
        gate_obj = next(g for g in lib_policy.gates if g.id == req_gate)
        assert gate_obj.required is True
        assert Severity.CRITICAL in gate_obj.block_on

    # 3. Declarative YAML file exists and matches requirements
    yaml_path = Path("policies/governance/library-policy.yaml")
    assert yaml_path.exists(), "policies/governance/library-policy.yaml must exist"
    loaded_yaml = GovernancePolicy.from_file(str(yaml_path))
    assert loaded_yaml.name == "library-release-governance"
    assert loaded_yaml.profile == ReleaseProfile.PRODUCTION
    assert "model-integrity" not in loaded_yaml.require
    for req_gate in ["core-security", "dependency-security", "configuration-integrity", "agent-security"]:
        assert req_gate in loaded_yaml.require


def test_library_governance_policy_evaluation_with_genuine_evidence():
    """Verify library policy PASS on genuine library evidence without models, and BLOCK on missing required evidence."""
    from llmfirewall.cli.commands import (
        handle_governance_gate,
        handle_supply_chain_snapshot,
        handle_test_security,
    )

    with tempfile.TemporaryDirectory() as tmpdir:
        results_path = os.path.join(tmpdir, "security_results.json")
        snapshot_path = os.path.join(tmpdir, "security_snapshot.json")
        out_report_path = os.path.join(tmpdir, "gov_out.json")

        # 1. Generate genuine security test results (100% pass rate)
        code_test = handle_test_security(
            suite="core",
            format_type="json",
            output_file=results_path,
        )
        assert code_test == 0
        assert os.path.exists(results_path)

        # 2. Generate genuine supply chain snapshot
        code_snap = handle_supply_chain_snapshot(output_path=snapshot_path)
        assert code_snap == 0
        assert os.path.exists(snapshot_path)

        # Confirm snapshot contains no models (library contains no model weights)
        snap_data = json.loads(open(snapshot_path, encoding="utf-8").read())
        assert len(snap_data.get("models", [])) == 0

        # 3. Evaluate against library policy via file path
        code_gate_path = handle_governance_gate(
            policy_file="policies/governance/library-policy.yaml",
            results_file=results_path,
            snapshot_file=snapshot_path,
            ci=True,
            format_type="json",
            output_file=out_report_path,
        )
        assert code_gate_path == 0
        report = json.loads(open(out_report_path, encoding="utf-8").read())
        assert report["decision"] == "PASS"
        assert report["passed"] is True
        assert len(report["failed_gates"]) == 0
        assert len(report["missing_evidence"]) == 0
        passed_ids = [g["gate_id"] for g in report["passed_gates"]]
        assert "core-security" in passed_ids
        assert "dependency-security" in passed_ids
        assert "configuration-integrity" in passed_ids
        assert "agent-security" in passed_ids
        assert "model-integrity" not in passed_ids

        # 4. Evaluate against library policy via CLI alias 'library'
        code_gate_alias = handle_governance_gate(
            policy_file="library",
            results_file=results_path,
            snapshot_file=snapshot_path,
            ci=True,
            format_type="json",
            output_file=out_report_path,
        )
        assert code_gate_alias == 0

        # 5. Evaluate library policy with missing snapshot -> BLOCK on dependency & configuration
        code_missing_snap = handle_governance_gate(
            policy_file="policies/governance/library-policy.yaml",
            results_file=results_path,
            snapshot_file=None,
            ci=True,
            format_type="json",
            output_file=out_report_path,
        )
        assert code_missing_snap != 0
        report_missing = json.loads(open(out_report_path, encoding="utf-8").read())
        assert report_missing["decision"] == "BLOCK"
        assert report_missing["passed"] is False
        failed_ids = [g["gate_id"] for g in report_missing["failed_gates"]]
        assert "dependency-security" in failed_ids
        assert "configuration-integrity" in failed_ids

        # 6. Evaluate library policy with corrupted/malformed JSON snapshot -> error
        corrupt_snap_path = os.path.join(tmpdir, "corrupt_snap.json")
        with open(corrupt_snap_path, "w", encoding="utf-8") as f:
            f.write("{invalid_json: malformed...")
        code_corrupt = handle_governance_gate(
            policy_file="policies/governance/library-policy.yaml",
            results_file=results_path,
            snapshot_file=corrupt_snap_path,
            ci=True,
            format_type="json",
            output_file=out_report_path,
        )
        assert code_corrupt != 0

        # 7. Evaluate library policy with schema-invalid snapshot -> error
        invalid_snap_path = os.path.join(tmpdir, "invalid_snap.json")
        with open(invalid_snap_path, "w", encoding="utf-8") as f:
            f.write(json.dumps({"snapshot_id": 12345, "created_at": "invalid", "deployment": "not-dict"}))
        code_invalid_schema = handle_governance_gate(
            policy_file="policies/governance/library-policy.yaml",
            results_file=results_path,
            snapshot_file=invalid_snap_path,
            ci=True,
            format_type="json",
            output_file=out_report_path,
        )
        assert code_invalid_schema != 0


def test_production_policy_strictly_blocks_without_model_identity():
    """Verify production-standard-governance remains unchanged and blocks without model evidence."""
    from llmfirewall.cli.commands import (
        handle_governance_gate,
        handle_supply_chain_snapshot,
        handle_test_security,
    )
    from llmfirewall.supply_chain.models import ModelArtifact

    with tempfile.TemporaryDirectory() as tmpdir:
        results_path = os.path.join(tmpdir, "security_results.json")
        snapshot_path = os.path.join(tmpdir, "security_snapshot.json")
        out_report_path = os.path.join(tmpdir, "gov_out.json")

        # 1. Genuine evidence without models
        handle_test_security(suite="core", format_type="json", output_file=results_path)
        handle_supply_chain_snapshot(output_path=snapshot_path)

        # 2. Production policy evaluation MUST block when model-identity is missing
        code_prod = handle_governance_gate(
            policy_file=None,  # default is production-standard-governance
            results_file=results_path,
            snapshot_file=snapshot_path,
            ci=True,
            format_type="json",
            output_file=out_report_path,
        )
        assert code_prod != 0
        report = json.loads(open(out_report_path, encoding="utf-8").read())
        assert report["decision"] == "BLOCK"
        assert report["passed"] is False
        failed_ids = [g["gate_id"] for g in report["failed_gates"]]
        assert "model-integrity" in failed_ids
        assert "model-integrity" in report["missing_evidence"]

        # 3. Supply valid model artifact -> production policy model gate passes
        valid_model = ModelArtifact(
            name="deepseek-coder-6.7b",
            version="1.0.0",
            sha256="1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
            provider="local",
        )
        snap_data = json.loads(open(snapshot_path, encoding="utf-8").read())
        snap_data["models"] = [valid_model.model_dump(mode="json")]
        model_snap_path = os.path.join(tmpdir, "model_snap.json")
        with open(model_snap_path, "w", encoding="utf-8") as f:
            json.dump(snap_data, f)

        code_prod_valid = handle_governance_gate(
            policy_file=None,
            results_file=results_path,
            snapshot_file=model_snap_path,
            ci=True,
            format_type="json",
            output_file=out_report_path,
        )
        assert code_prod_valid == 0
        report_valid = json.loads(open(out_report_path, encoding="utf-8").read())
        assert report_valid["decision"] == "PASS"
        passed_ids = [g["gate_id"] for g in report_valid["passed_gates"]]
        assert "model-integrity" in passed_ids

        # 4. Model change against baseline -> triggers review / gate failure
        from llmfirewall.governance.baseline import SecurityBaseline
        baseline = SecurityBaseline(
            baseline_id="BASE-MODEL-001",
            version="1.0",
            created_by="security-team",
            model_identity={
                "name": "deepseek-coder-6.7b",
                "sha256": "original_baseline_hash_00000000000000000000000000000000000000000000",
            },
        )
        baseline_path = os.path.join(tmpdir, "baseline.json")
        with open(baseline_path, "w", encoding="utf-8") as f:
            f.write(baseline.to_json())

        code_prod_drift = handle_governance_gate(
            policy_file=None,
            baseline_file=baseline_path,
            results_file=results_path,
            snapshot_file=model_snap_path,
            ci=True,
            format_type="json",
            output_file=out_report_path,
        )
        assert code_prod_drift != 0
        report_drift = json.loads(open(out_report_path, encoding="utf-8").read())
        assert report_drift["decision"] in ("BLOCK", "REVIEW")
        assert report_drift["passed"] is False
        review_or_failed = [g["gate_id"] for g in report_drift.get("failed_gates", [])] + [
            r["gate_id"] for r in report_drift.get("review_items", [])
        ]
        assert "model-integrity" in review_or_failed


def test_security_workflow_configuration_integrity():
    """Verify .github/workflows/llmfirewall-security.yml configuration integrity and safety."""
    from pathlib import Path
    import yaml

    workflow_path = Path(".github/workflows/llmfirewall-security.yml")
    assert workflow_path.exists(), "Workflow file must exist"

    content = workflow_path.read_text(encoding="utf-8")
    parsed = yaml.safe_load(content)

    # Job and steps verification
    jobs = parsed.get("jobs", {})
    assert "governance-gate" in jobs
    steps = jobs["governance-gate"].get("steps", [])

    # Step: evaluate governance release gate must use library policy and NOT continue-on-error
    gate_step = next((s for s in steps if "governance release gate" in s.get("name", "").lower()), None)
    assert gate_step is not None, "Gate evaluation step must exist"
    assert "continue-on-error" not in gate_step, "Gate step must not have continue-on-error"
    run_cmd = gate_step.get("run", "")
    assert "--policy policies/governance/library-policy.yaml" in run_cmd
    assert "--results security-results.json" in run_cmd
    assert "--snapshot security-snapshot.json" in run_cmd
    assert "--ci" in run_cmd

    # Step: test security and supply-chain snapshot must NOT have blanket continue-on-error
    test_step = next((s for s in steps if "security test suite" in s.get("name", "").lower()), None)
    assert test_step is not None
    assert "continue-on-error" not in test_step

    snap_step = next((s for s in steps if "security snapshot" in s.get("name", "").lower()), None)
    assert snap_step is not None
    assert "continue-on-error" not in snap_step

    # Step: artifact upload step must upload all 3 evidence artifacts
    upload_step = next((s for s in steps if "upload evidence" in s.get("name", "").lower()), None)
    assert upload_step is not None
    with_params = upload_step.get("with", {})
    artifact_paths = with_params.get("path", "")
    assert "security-results.json" in artifact_paths
    assert "security-snapshot.json" in artifact_paths
    assert "governance-result.json" in artifact_paths
    assert with_params.get("retention-days") == 90


def test_release_workflow_governance_ancestry_enforcement():
    """Verify that .github/workflows/release.yml enforces least privilege and tag ancestry on main branch."""
    import yaml
    from pathlib import Path

    workflow_path = Path(__file__).resolve().parent.parent / ".github" / "workflows" / "release.yml"
    assert workflow_path.exists(), "release.yml workflow must exist"

    with open(workflow_path, "r", encoding="utf-8") as f:
        wf = yaml.safe_load(f)

    # 1. Workflow-level permissions must be minimal (no id-token: write)
    assert wf.get("permissions") == {"contents": "read"}, "Default permissions must be read-only"

    # 2. Build-and-verify job must NOT have id-token: write
    build_job = wf["jobs"]["build-and-verify"]
    assert build_job.get("permissions") == {"contents": "read"}, "Build job must have only contents: read"

    # 3. Publish job must require build-and-verify and be isolated with id-token: write
    publish_job = wf["jobs"]["publish"]
    assert publish_job.get("needs") == "build-and-verify"
    assert publish_job.get("permissions") == {"contents": "read", "id-token": "write"}
    assert publish_job.get("environment", {}).get("name") == "pypi"

    steps = build_job["steps"]

    # 4. Checkout step must specify fetch-depth: 0 (not shallow) to allow ancestry verification
    checkout_step = next(s for s in steps if "Checkout" in s.get("name", ""))
    assert checkout_step.get("with", {}).get("fetch-depth") == 0, (
        "Checkout step in release.yml must specify 'fetch-depth: 0' to preserve git commit ancestry."
    )

    # 5. Ancestry enforcement step must exist BEFORE Python setup and build
    ancestry_idx = next(i for i, s in enumerate(steps) if "Ancestry" in s.get("name", ""))
    setup_py_idx = next(i for i, s in enumerate(steps) if "Set up Python" in s.get("name", ""))
    build_idx = next(i for i, s in enumerate(steps) if "Build" in s.get("name", ""))

    assert ancestry_idx < setup_py_idx < build_idx, (
        "Ancestry enforcement must run before setup and build steps."
    )

    # 6. Step run script must verify peeled commit and ancestry against origin/main
    ancestry_step = steps[ancestry_idx]
    run_script = ancestry_step.get("run", "")
    assert 'git rev-parse "${RELEASE_TAG}^{commit}"' in run_script
    assert "git merge-base --is-ancestor" in run_script
    assert "origin/main" in run_script

    # 7. Checksum verification in publish job
    pub_steps = publish_job["steps"]
    integrity_step = next(s for s in pub_steps if "Integrity" in s.get("name", ""))
    assert "sha256sum -c" in integrity_step.get("run", "")



def test_git_ancestry_logic_validation():
    """Verify git ancestry check fails-closed for unmerged development commits and succeeds for main commits."""
    import subprocess
    from pathlib import Path

    repo_dir = Path(__file__).resolve().parent.parent

    # 1. Commit on main branch (origin/main) is an ancestor of origin/main
    main_head = subprocess.check_output(
        ["git", "rev-parse", "origin/main"],
        cwd=repo_dir,
        text=True,
    ).strip()

    res_main = subprocess.run(
        ["git", "merge-base", "--is-ancestor", main_head, "origin/main"],
        cwd=repo_dir,
    )
    assert res_main.returncode == 0, "Commit on main must be recognized as ancestor of main"

    # 2. Unmerged commit on v1.2.0-dev (aad745c) is NOT an ancestor of origin/main
    dev_commit = "aad745ca9c98fe9542372b64abb1932555789600"
    res_dev = subprocess.run(
        ["git", "merge-base", "--is-ancestor", dev_commit, "origin/main"],
        cwd=repo_dir,
    )
    assert res_dev.returncode == 1, "Unmerged development commit must NOT be recognized as ancestor of main"

    # 3. Peeling annotated or lightweight tag
    tag_peeled = subprocess.check_output(
        ["git", "rev-parse", "v1.3.1^{commit}"],
        cwd=repo_dir,
        text=True,
    ).strip()
    assert len(tag_peeled) == 40


def test_governance_policy_missing_mandatory_gate_fails_closed():
    """Verify that referencing a non-existent gate in 'require' raises ValueError (fail-closed)."""
    with pytest.raises(ValueError, match="Mandatory gate 'dangling-mandatory-gate' referenced in 'require' is not defined"):
        GovernancePolicy(
            name="invalid-policy",
            version="1.0",
            require=["dangling-mandatory-gate"],
            gates=[],
        )

