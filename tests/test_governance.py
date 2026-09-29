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
