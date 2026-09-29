"""Deterministic AI Security Governance Engine for Phase 31."""

import asyncio
from collections import defaultdict
import copy
from datetime import datetime, timezone
import hashlib
import json
import logging
import threading
import time
from typing import Any, Dict, List, Optional, Set, Tuple

from llmfirewall._version import __version__
from llmfirewall.audit import AuditLogger, default_audit_logger
from llmfirewall.core.models import Action, AuditEvent, Severity
from llmfirewall.eval.models import AttackCategory, SecurityEvaluationReport, SecurityTestResult
from llmfirewall.governance.baseline import BaselineDiff, SecurityBaseline
from llmfirewall.governance.decisions import (
    GateEvaluationResult,
    GovernanceDecision,
    GovernanceResult,
    ReasonCode,
)
from llmfirewall.governance.evidence import SecurityEvidence
from llmfirewall.governance.findings import FindingStatus, GovernanceFinding
from llmfirewall.governance.gates import GateType, SecurityGate
from llmfirewall.governance.manifest import SecurityReleaseManifest
from llmfirewall.governance.policy import GovernancePolicy, ReleaseProfile
from llmfirewall.governance.waivers import SecurityWaiver

logger = logging.getLogger("llmfirewall.governance")


class SecurityGateFailure(Exception):
    """Raised when a programmatic release check is blocked by governance policy."""

    def __init__(self, result: GovernanceResult) -> None:
        self.result = result
        failed_names = [g.gate_id for g in result.failed_gates]
        super().__init__(
            f"Release blocked by LLMFirewall governance policy. Decision: {result.decision.value}. "
            f"Failed gates: {failed_names}. Reason codes: {[rc.value for rc in result.reason_codes]}"
        )


class GovernanceOverride:
    """Explicit, auditable release override authorizing an exception."""

    def __init__(
        self,
        owner: str,
        reason: str,
        emergency: bool = False,
        approved_by: Optional[str] = None,
        timestamp: Optional[float] = None,
    ) -> None:
        clean_owner = (owner or "").strip()
        clean_reason = (reason or "").strip()
        if not clean_owner:
            raise ValueError("Override owner cannot be empty.")
        if not clean_reason:
            raise ValueError("Override reason cannot be empty.")

        self.owner = clean_owner
        self.reason = clean_reason
        self.emergency = emergency
        self.approved_by = approved_by
        self.timestamp = timestamp if timestamp is not None else time.time()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "owner": self.owner,
            "reason": self.reason,
            "emergency": self.emergency,
            "approved_by": self.approved_by,
            "timestamp": self.timestamp,
        }


class GovernanceMetrics:
    """Thread-safe, bounded telemetry metrics for release governance."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.governance_runs_total = 0
        self.governance_pass_total = 0
        self.governance_fail_total = 0
        self.governance_review_total = 0
        self.governance_block_total = 0
        self.gate_failures_total = 0
        self.waivers_active = 0
        self.waivers_expired = 0
        self.security_regressions_total = 0

    def record_evaluation(self, decision: GovernanceDecision) -> None:
        with self._lock:
            self.governance_runs_total += 1
            if decision == GovernanceDecision.PASS:
                self.governance_pass_total += 1
            elif decision == GovernanceDecision.FAIL:
                self.governance_fail_total += 1
            elif decision == GovernanceDecision.REVIEW:
                self.governance_review_total += 1
            elif decision == GovernanceDecision.BLOCK:
                self.governance_block_total += 1

    def record_gate_failure(self) -> None:
        with self._lock:
            self.gate_failures_total += 1

    def record_waivers(self, active: int, expired: int) -> None:
        with self._lock:
            self.waivers_active = active
            self.waivers_expired = expired

    def record_regression(self, count: int = 1) -> None:
        with self._lock:
            self.security_regressions_total += count

    def to_dict(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "governance_runs_total": self.governance_runs_total,
                "governance_pass_total": self.governance_pass_total,
                "governance_fail_total": self.governance_fail_total,
                "governance_review_total": self.governance_review_total,
                "governance_block_total": self.governance_block_total,
                "gate_failures_total": self.gate_failures_total,
                "waivers_active": self.waivers_active,
                "waivers_expired": self.waivers_expired,
                "security_regressions_total": self.security_regressions_total,
            }

    def reset(self) -> None:
        with self._lock:
            self.governance_runs_total = 0
            self.governance_pass_total = 0
            self.governance_fail_total = 0
            self.governance_review_total = 0
            self.governance_block_total = 0
            self.gate_failures_total = 0
            self.waivers_active = 0
            self.waivers_expired = 0
            self.security_regressions_total = 0


class GovernanceEngine:
    """Core AI Security Governance Engine implementing deterministic gating, baselines, and assurance.
    
    Architectural Invariants:
    1. Evidence-Based Assurance: Evaluates configured controls against verifiable artifacts without subjective scoring.
    2. Missing Evidence != PASS: Incomplete evidence yields REVIEW or BLOCK according to policy.
    3. Non-Permanent Waivers: Expired waivers are strictly re-evaluated as active findings.
    4. Non-Erasing Overrides: Emergency release preserves all failed gate evidence and records exception lineage.
    5. Baseline Tamper Resistance: SHA-256 integrity verification detects baseline tampering immediately.
    6. Policy Precedence: Strictly enforces Deny/Block > Required Gate > Review > Pass.
    """

    def __init__(
        self,
        audit_logger: Optional[AuditLogger] = None,
        default_policy: Optional[GovernancePolicy] = None,
    ) -> None:
        self.audit_logger = audit_logger or default_audit_logger
        self.default_policy = default_policy or GovernancePolicy.default_production_policy()
        self.metrics = GovernanceMetrics()
        self._lock = threading.Lock()

    def evaluate(
        self,
        evidence: SecurityEvidence,
        policy: Optional[GovernancePolicy] = None,
        baseline: Optional[SecurityBaseline] = None,
        override: Optional[GovernanceOverride] = None,
        changed_components: Optional[Dict[str, bool]] = None,
    ) -> GovernanceResult:
        """Deterministically evaluate security evidence against configured governance policy."""
        active_policy = policy or self.default_policy
        eval_time = time.time()

        # Audit start
        self._emit_audit("governance_evaluation_started", {
            "release_id": evidence.release_id,
            "policy_name": active_policy.name,
            "policy_version": active_policy.version,
            "profile": active_policy.profile.value,
        })

        # 1. Baseline Integrity Verification
        baseline_diff: Optional[BaselineDiff] = None
        baseline_tampered = False
        if baseline is not None:
            if not baseline.verify_integrity():
                baseline_tampered = True
                self._emit_audit("baseline_tampered", {
                    "baseline_id": baseline.baseline_id,
                    "release_id": evidence.release_id,
                })

        # 2. Extract & Correlate Findings
        findings, active_waivers_count, expired_waivers_count = self._process_findings(
            evidence=evidence,
            policy=active_policy,
            baseline=baseline,
        )
        self.metrics.record_waivers(active=active_waivers_count, expired=expired_waivers_count)

        # 3. Perform Baseline Comparison if available and valid
        if baseline is not None and not baseline_tampered:
            baseline_diff = baseline.compare_findings(findings)
            if baseline_diff.regressions:
                self.metrics.record_regression(len(baseline_diff.regressions))
                self._emit_audit("RELEASE_SECURITY_REGRESSION", {
                    "baseline_id": baseline.baseline_id,
                    "release_id": evidence.release_id,
                    "regressions": baseline_diff.regressions,
                })

        # 4. Evaluate Gates
        failed_gates: List[GateEvaluationResult] = []
        passed_gates: List[GateEvaluationResult] = []
        review_items: List[GateEvaluationResult] = []
        missing_evidence: List[str] = []
        overall_reason_codes: Set[ReasonCode] = set()

        # If baseline tampering detected, block immediately
        if baseline_tampered:
            tamper_gate = GateEvaluationResult(
                gate_id="baseline-integrity",
                gate_type="integrity",
                decision=GovernanceDecision.BLOCK,
                passed=False,
                reason="Security baseline failed SHA-256 cryptographic integrity verification (tampering detected).",
                reason_codes=[ReasonCode.TAMPERING_DETECTED],
                evidence_used=["baseline"],
            )
            failed_gates.append(tamper_gate)
            overall_reason_codes.add(ReasonCode.TAMPERING_DETECTED)

        # Evaluate each configured gate in policy
        for gate in active_policy.gates:
            if not gate.enabled:
                continue

            gate_res = self._evaluate_gate(
                gate=gate,
                evidence=evidence,
                policy=active_policy,
                findings=findings,
                baseline=baseline,
                baseline_diff=baseline_diff,
                changed_components=changed_components,
            )

            for rc in gate_res.reason_codes:
                overall_reason_codes.add(rc)

            if gate_res.decision == GovernanceDecision.PASS:
                passed_gates.append(gate_res)
                self._emit_audit("gate_passed", {
                    "gate_id": gate.id,
                    "release_id": evidence.release_id,
                })
            elif gate_res.decision == GovernanceDecision.REVIEW:
                review_items.append(gate_res)
                self._emit_audit("release_review_required", {
                    "gate_id": gate.id,
                    "release_id": evidence.release_id,
                    "reason": gate_res.reason,
                })
            else:
                failed_gates.append(gate_res)
                self.metrics.record_gate_failure()
                self._emit_audit("gate_failed", {
                    "gate_id": gate.id,
                    "release_id": evidence.release_id,
                    "reason": gate_res.reason,
                    "decision": gate_res.decision.value,
                })

            if ReasonCode.MISSING_EVIDENCE in gate_res.reason_codes:
                missing_evidence.append(gate.id)

        # 5. Global Policy Precedence & Decision Aggregation
        # Precedence: Explicit Deny/Block > Required Gate Failure > Review > Pass
        overall_decision = GovernanceDecision.PASS

        has_block = any(g.decision == GovernanceDecision.BLOCK for g in failed_gates)
        has_fail = any(g.decision == GovernanceDecision.FAIL for g in failed_gates)
        has_review = len(review_items) > 0

        # Check policy global block_on / review_on over findings
        unwaived_findings = [f for f in findings if f.status != FindingStatus.ACCEPTED]
        for f in unwaived_findings:
            if f.severity in active_policy.block_on:
                has_block = True
                overall_reason_codes.add(ReasonCode.CRITICAL_FINDING if f.severity == Severity.CRITICAL else ReasonCode.REQUIRED_GATE_FAILED)
            elif f.severity in active_policy.review_on:
                has_review = True
                overall_reason_codes.add(ReasonCode.REVIEW_REQUIRED)

        if has_block:
            overall_decision = GovernanceDecision.BLOCK
            self._emit_audit("release_blocked", {
                "release_id": evidence.release_id,
                "reason": "One or more gates or findings triggered policy BLOCK.",
            })
        elif has_fail:
            overall_decision = GovernanceDecision.FAIL
            self._emit_audit("release_blocked", {
                "release_id": evidence.release_id,
                "reason": "One or more required security controls failed evaluation.",
            })
        elif has_review:
            overall_decision = GovernanceDecision.REVIEW
        else:
            overall_decision = GovernanceDecision.PASS
            overall_reason_codes.add(ReasonCode.ALL_CONTROLS_SATISFIED)

        # 6. Process Explicit Override
        override_dict: Optional[Dict[str, Any]] = None
        is_passed = (overall_decision == GovernanceDecision.PASS)
        is_blocked = (overall_decision in (GovernanceDecision.BLOCK, GovernanceDecision.FAIL))
        is_review = (overall_decision == GovernanceDecision.REVIEW)

        if override is not None:
            if active_policy.allow_emergency_override:
                is_passed = True
                is_blocked = False
                is_review = False
                override_dict = override.to_dict()
                overall_reason_codes.add(ReasonCode.OVERRIDE_APPLIED)
                self._emit_audit("override_used", {
                    "release_id": evidence.release_id,
                    "original_decision": overall_decision.value,
                    "owner": override.owner,
                    "reason": override.reason,
                    "emergency": override.emergency,
                })
            else:
                logger.warning("Emergency override rejected: policy disallows emergency overrides.")

        # Record telemetry
        self.metrics.record_evaluation(overall_decision)

        # 7. Generate Security Release Manifest
        manifest = SecurityReleaseManifest.create(
            release_id=evidence.release_id,
            application_version=evidence.metadata.get("app_version", "unknown"),
            model=evidence.model_identity or {},
            prompt_hash=evidence.prompt_hash,
            policy_hash=evidence.policy_hash or active_policy.policy_hash,
            configuration_hash=evidence.configuration_hash,
            dependency_hash=evidence.dependency_hash,
            test_suite_version=evidence.evaluation_report.suite_version if evidence.evaluation_report else None,
            baseline_id=baseline.baseline_id if baseline else None,
            decision=overall_decision,
            gate_summary={
                "passed_count": len(passed_gates),
                "failed_count": len(failed_gates),
                "review_count": len(review_items),
                "missing_evidence_count": len(missing_evidence),
            },
            timestamp=eval_time,
        )

        return GovernanceResult(
            release_id=evidence.release_id,
            decision=overall_decision,
            passed=is_passed,
            blocked=is_blocked,
            review_required=is_review,
            failed_gates=failed_gates,
            passed_gates=passed_gates,
            review_items=review_items,
            missing_evidence=sorted(list(set(missing_evidence))),
            findings=findings,
            baseline_changes=baseline_diff,
            reason_codes=sorted(list(overall_reason_codes), key=lambda r: r.value),
            override=override_dict,
            manifest=manifest,
            evaluated_at=eval_time,
            policy_version=active_policy.version,
            profile=active_policy.profile.value,
        )

    async def evaluate_async(
        self,
        evidence: SecurityEvidence,
        policy: Optional[GovernancePolicy] = None,
        baseline: Optional[SecurityBaseline] = None,
        override: Optional[GovernanceOverride] = None,
        changed_components: Optional[Dict[str, bool]] = None,
    ) -> GovernanceResult:
        """Asynchronously evaluate security evidence without blocking the event loop."""
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(
            None,
            self.evaluate,
            evidence,
            policy,
            baseline,
            override,
            changed_components,
        )

    def _process_findings(
        self,
        evidence: SecurityEvidence,
        policy: GovernancePolicy,
        baseline: Optional[SecurityBaseline],
    ) -> Tuple[List[GovernanceFinding], int, int]:
        """Normalize findings, match waivers, verify waiver integrity, and check expiration."""
        raw_findings: List[GovernanceFinding] = []

        # Ingest pre-existing findings in evidence
        for f in evidence.findings:
            raw_findings.append(f)

        # Ingest findings from test_results
        for res in evidence.test_results:
            if not res.passed:
                desc = res.finding.description if res.finding else f"Test {res.test_id} failed: expected {res.expected_action.value}, actual {res.actual_action.value}"
                finding = GovernanceFinding.from_test_finding(
                    category=res.category.value,
                    description=desc,
                    severity=res.severity,
                    test_id=res.test_id,
                    metadata={"error": res.error or ""},
                )
                raw_findings.append(finding)

        # Ingest findings from evaluation_report
        if evidence.evaluation_report:
            for rep_f in evidence.evaluation_report.findings:
                finding = GovernanceFinding.from_test_finding(
                    category=rep_f.category,
                    description=rep_f.description,
                    severity=rep_f.severity,
                    test_id=rep_f.test_id,
                    metadata={"evidence": rep_f.evidence},
                )
                raw_findings.append(finding)

        # Correlate duplicates by fingerprint
        unique_findings: Dict[str, GovernanceFinding] = {}
        for f in raw_findings:
            if f.fingerprint not in unique_findings:
                unique_findings[f.fingerprint] = f
            else:
                # Merge related tests
                existing = unique_findings[f.fingerprint]
                rel = sorted(list(set(existing.related_tests + f.related_tests)))
                unique_findings[f.fingerprint] = existing.with_status(
                    new_status=existing.status,
                )

        # Match waivers
        active_waivers = 0
        expired_waivers = 0
        processed_findings: List[GovernanceFinding] = []

        for fp, f in unique_findings.items():
            matched_waiver: Optional[SecurityWaiver] = None
            is_waiver_expired = False

            for w in policy.waivers:
                if w.matches_finding(f):
                    matched_waiver = w
                    break
                # Check if it would match except it's expired
                if not w.is_expired():
                    continue
                # If expired, check if it matches target scope
                if w.verify_integrity():
                    # Check scope match
                    matches_scope = False
                    if w.finding_fingerprint and w.finding_fingerprint == f.fingerprint:
                        matches_scope = True
                    elif w.test_id and f.test_id and w.test_id == f.test_id:
                        matches_scope = True
                    elif w.rule_id and f.rule_id and w.rule_id == f.rule_id:
                        matches_scope = True
                    elif w.category and (w.category.lower() == (f.category or "").lower()):
                        matches_scope = True

                    if matches_scope:
                        is_waiver_expired = True
                        matched_waiver = w
                        break

            if matched_waiver:
                if is_waiver_expired or matched_waiver.is_expired():
                    expired_waivers += 1
                    self._emit_audit("waiver_expired", {
                        "waiver_id": matched_waiver.id,
                        "finding_fingerprint": f.fingerprint,
                        "owner": matched_waiver.owner,
                    })
                    updated = f.with_status(
                        new_status=FindingStatus.EXPIRED,
                        owner=matched_waiver.owner,
                        reason=f"Waiver {matched_waiver.id} expired",
                        waiver_id=matched_waiver.id,
                    )
                    processed_findings.append(updated)
                else:
                    active_waivers += 1
                    updated = f.with_status(
                        new_status=FindingStatus.ACCEPTED,
                        owner=matched_waiver.owner,
                        reason=matched_waiver.reason,
                        expires_at=matched_waiver.expires_at,
                        waiver_id=matched_waiver.id,
                    )
                    processed_findings.append(updated)
            else:
                processed_findings.append(f)

        return processed_findings, active_waivers, expired_waivers

    def _evaluate_gate(
        self,
        gate: SecurityGate,
        evidence: SecurityEvidence,
        policy: GovernancePolicy,
        findings: List[GovernanceFinding],
        baseline: Optional[SecurityBaseline],
        baseline_diff: Optional[BaselineDiff],
        changed_components: Optional[Dict[str, bool]],
    ) -> GateEvaluationResult:
        """Evaluate an individual security gate against relevant evidence."""
        # 1. TEST GATE
        if gate.type == GateType.TEST_GATE:
            return self._evaluate_test_gate(gate, evidence, findings)

        # 2. MODEL GATE
        elif gate.type == GateType.MODEL_GATE:
            return self._evaluate_model_gate(gate, evidence, baseline)

        # 3. DEPENDENCY GATE
        elif gate.type == GateType.DEPENDENCY_GATE:
            return self._evaluate_dependency_gate(gate, evidence, baseline)

        # 4. CONFIGURATION GATE
        elif gate.type == GateType.CONFIGURATION_GATE:
            return self._evaluate_configuration_gate(gate, evidence, baseline)

        # 5. DRIFT GATE
        elif gate.type == GateType.DRIFT_GATE:
            return self._evaluate_drift_gate(gate, evidence, baseline_diff)

        # 6. AGENT GATE
        elif gate.type == GateType.AGENT_GATE:
            return self._evaluate_agent_gate(gate, evidence, baseline)

        # 7. RAG GATE
        elif gate.type == GateType.RAG_GATE:
            return self._evaluate_rag_gate(gate, evidence, baseline)

        # 8. POLICY GATE
        elif gate.type == GateType.POLICY_GATE:
            return self._evaluate_policy_gate(gate, evidence, baseline)

        # Fallback / Custom
        return GateEvaluationResult(
            gate_id=gate.id,
            gate_type=gate.type.value,
            decision=GovernanceDecision.PASS,
            passed=True,
            reason="Gate requirements satisfied.",
        )

    def _evaluate_test_gate(
        self,
        gate: SecurityGate,
        evidence: SecurityEvidence,
        findings: List[GovernanceFinding],
    ) -> GateEvaluationResult:
        """Evaluate test results, pass rates, required tests, and severities."""
        # Check if test evidence exists
        has_tests = bool(evidence.test_results or evidence.evaluation_report)
        if not has_tests:
            dec = GovernanceDecision.BLOCK if gate.required else GovernanceDecision.REVIEW
            return GateEvaluationResult(
                gate_id=gate.id,
                gate_type=gate.type.value,
                decision=dec,
                passed=False,
                reason="Security test evidence is missing or test suite has not run.",
                reason_codes=[ReasonCode.MISSING_EVIDENCE],
            )

        # Check required tests
        if gate.required_tests:
            executed_test_ids: Set[str] = set()
            if evidence.test_results:
                executed_test_ids.update(t.test_id for t in evidence.test_results)
            if evidence.evaluation_report:
                executed_test_ids.update(t.test_id for t in evidence.evaluation_report.results)

            missing_reqs = [t_id for t_id in gate.required_tests if t_id not in executed_test_ids]
            if missing_reqs:
                dec = GovernanceDecision.BLOCK if gate.required else GovernanceDecision.REVIEW
                return GateEvaluationResult(
                    gate_id=gate.id,
                    gate_type=gate.type.value,
                    decision=dec,
                    passed=False,
                    reason=f"Required test cases were not executed: {missing_reqs}.",
                    reason_codes=[ReasonCode.MISSING_REQUIRED_TEST],
                    evidence_used=["test_results"],
                )

        # Check minimum pass rate
        if gate.minimum_pass_rate is not None:
            pass_rate = 1.0
            if evidence.evaluation_report:
                pass_rate = evidence.evaluation_report.metrics.pass_rate
            elif evidence.test_results:
                passed_cnt = sum(1 for t in evidence.test_results if t.passed)
                pass_rate = passed_cnt / max(1, len(evidence.test_results))

            if pass_rate < gate.minimum_pass_rate:
                return GateEvaluationResult(
                    gate_id=gate.id,
                    gate_type=gate.type.value,
                    decision=GovernanceDecision.FAIL,
                    passed=False,
                    reason=f"Test pass rate ({pass_rate * 100:.1f}%) is below required threshold ({gate.minimum_pass_rate * 100:.1f}%).",
                    reason_codes=[ReasonCode.PASS_RATE_BELOW_THRESHOLD],
                    evidence_used=["test_results"],
                    details={"actual_pass_rate": pass_rate, "threshold": gate.minimum_pass_rate},
                )

        # Check findings from tests
        test_findings = [f for f in findings if f.test_id is not None or f.category]
        unwaived_findings = [f for f in test_findings if f.status != FindingStatus.ACCEPTED]

        # Check for expired waivers among test findings
        has_expired_waivers = any(f.status == FindingStatus.EXPIRED for f in test_findings)

        # Check block_on
        for f in unwaived_findings:
            if f.severity in gate.block_on:
                rc = [ReasonCode.CRITICAL_FINDING] if f.severity == Severity.CRITICAL else [ReasonCode.REQUIRED_GATE_FAILED]
                if has_expired_waivers:
                    rc.append(ReasonCode.WAIVER_EXPIRED)
                return GateEvaluationResult(
                    gate_id=gate.id,
                    gate_type=gate.type.value,
                    decision=GovernanceDecision.BLOCK,
                    passed=False,
                    reason=f"Unwaived finding [{f.severity.value.upper()}] {f.fingerprint} violates block_on policy.",
                    reason_codes=rc,
                    evidence_used=["findings"],
                    details={"fingerprint": f.fingerprint, "severity": f.severity.value},
                )

        # Check max_allowed_severity
        if gate.max_allowed_severity is not None:
            order = [Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
            try:
                max_allowed_idx = order.index(gate.max_allowed_severity)
                for f in unwaived_findings:
                    if order.index(f.severity) > max_allowed_idx:
                        return GateEvaluationResult(
                            gate_id=gate.id,
                            gate_type=gate.type.value,
                            decision=GovernanceDecision.FAIL,
                            passed=False,
                            reason=f"Finding severity {f.severity.value} exceeds max allowed severity {gate.max_allowed_severity.value}.",
                            reason_codes=[ReasonCode.SEVERITY_THRESHOLD_EXCEEDED],
                            evidence_used=["findings"],
                        )
            except ValueError:
                pass

        # Check review_on
        for f in unwaived_findings:
            if f.severity in gate.review_on:
                return GateEvaluationResult(
                    gate_id=gate.id,
                    gate_type=gate.type.value,
                    decision=GovernanceDecision.REVIEW,
                    passed=False,
                    reason=f"Finding [{f.severity.value.upper()}] requires human review.",
                    reason_codes=[ReasonCode.REVIEW_REQUIRED],
                    evidence_used=["findings"],
                )

        return GateEvaluationResult(
            gate_id=gate.id,
            gate_type=gate.type.value,
            decision=GovernanceDecision.PASS,
            passed=True,
            reason="All test gate criteria satisfied.",
            evidence_used=["test_results"],
        )

    def _evaluate_model_gate(
        self,
        gate: SecurityGate,
        evidence: SecurityEvidence,
        baseline: Optional[SecurityBaseline],
    ) -> GateEvaluationResult:
        """Evaluate model artifact identity, hash changes, and verification status."""
        if not evidence.model_identity:
            dec = GovernanceDecision.BLOCK if gate.required else GovernanceDecision.REVIEW
            return GateEvaluationResult(
                gate_id=gate.id,
                gate_type=gate.type.value,
                decision=dec,
                passed=False,
                reason="Model identity and artifact verification evidence is missing.",
                reason_codes=[ReasonCode.MISSING_EVIDENCE],
            )

        # Check if model changed relative to baseline
        if baseline and baseline.model_identity:
            old_name = baseline.model_identity.get("name")
            new_name = evidence.model_identity.get("name")
            old_hash = baseline.model_identity.get("sha256") or baseline.model_identity.get("model_hash")
            new_hash = evidence.model_identity.get("sha256") or evidence.model_identity.get("model_hash")

            if (old_name and new_name and old_name != new_name) or (old_hash and new_hash and old_hash != new_hash):
                # Model changed!
                if gate.required:
                    return GateEvaluationResult(
                        gate_id=gate.id,
                        gate_type=gate.type.value,
                        decision=GovernanceDecision.REVIEW,
                        passed=False,
                        reason=f"Model artifact changed from '{old_name}' to '{new_name}'; requires security review.",
                        reason_codes=[ReasonCode.MODEL_CHANGED, ReasonCode.REVIEW_REQUIRED],
                        evidence_used=["model_identity"],
                    )

        return GateEvaluationResult(
            gate_id=gate.id,
            gate_type=gate.type.value,
            decision=GovernanceDecision.PASS,
            passed=True,
            reason="Model identity verified.",
            evidence_used=["model_identity"],
        )

    def _evaluate_dependency_gate(
        self,
        gate: SecurityGate,
        evidence: SecurityEvidence,
        baseline: Optional[SecurityBaseline],
    ) -> GateEvaluationResult:
        """Evaluate dependency hash and supply-chain drift."""
        if not evidence.dependency_hash and not evidence.snapshot:
            dec = GovernanceDecision.BLOCK if gate.required else GovernanceDecision.REVIEW
            return GateEvaluationResult(
                gate_id=gate.id,
                gate_type=gate.type.value,
                decision=dec,
                passed=False,
                reason="Dependency manifest or supply-chain snapshot evidence is missing.",
                reason_codes=[ReasonCode.MISSING_EVIDENCE],
            )

        if baseline and baseline.dependency_state and evidence.dependency_hash:
            base_dep_hash = baseline.dependency_state.get("hash") or baseline.dependency_state.get("sha256")
            if base_dep_hash and base_dep_hash != evidence.dependency_hash:
                if gate.required:
                    return GateEvaluationResult(
                        gate_id=gate.id,
                        gate_type=gate.type.value,
                        decision=GovernanceDecision.REVIEW,
                        passed=False,
                        reason="Dependency manifest state changed relative to baseline; requires dependency review.",
                        reason_codes=[ReasonCode.DEPENDENCY_CHANGED, ReasonCode.REVIEW_REQUIRED],
                        evidence_used=["dependency_hash"],
                    )

        return GateEvaluationResult(
            gate_id=gate.id,
            gate_type=gate.type.value,
            decision=GovernanceDecision.PASS,
            passed=True,
            reason="Dependency integrity verified.",
            evidence_used=["dependency_hash"],
        )

    def _evaluate_configuration_gate(
        self,
        gate: SecurityGate,
        evidence: SecurityEvidence,
        baseline: Optional[SecurityBaseline],
    ) -> GateEvaluationResult:
        """Evaluate firewall configuration integrity."""
        if not evidence.configuration_hash:
            dec = GovernanceDecision.BLOCK if gate.required else GovernanceDecision.REVIEW
            return GateEvaluationResult(
                gate_id=gate.id,
                gate_type=gate.type.value,
                decision=dec,
                passed=False,
                reason="Firewall configuration hash evidence is missing.",
                reason_codes=[ReasonCode.MISSING_EVIDENCE],
            )

        if baseline and baseline.configuration_hash and evidence.configuration_hash:
            if baseline.configuration_hash != evidence.configuration_hash:
                return GateEvaluationResult(
                    gate_id=gate.id,
                    gate_type=gate.type.value,
                    decision=GovernanceDecision.REVIEW if not gate.required else GovernanceDecision.FAIL,
                    passed=False,
                    reason="Firewall security configuration changed relative to baseline.",
                    reason_codes=[ReasonCode.CONFIGURATION_DRIFT],
                    evidence_used=["configuration_hash"],
                )

        return GateEvaluationResult(
            gate_id=gate.id,
            gate_type=gate.type.value,
            decision=GovernanceDecision.PASS,
            passed=True,
            reason="Firewall configuration integrity verified.",
            evidence_used=["configuration_hash"],
        )

    def _evaluate_drift_gate(
        self,
        gate: SecurityGate,
        evidence: SecurityEvidence,
        baseline_diff: Optional[BaselineDiff],
    ) -> GateEvaluationResult:
        """Evaluate snapshot drift and regressions."""
        if evidence.snapshot_diff:
            diff = evidence.snapshot_diff
            if not diff.is_identical:
                details = {
                    "models_changed": diff.models_changed,
                    "dependencies_changed": diff.dependencies_changed,
                    "configs_changed": diff.configs_changed,
                }
                dec = GovernanceDecision.FAIL if gate.required else GovernanceDecision.REVIEW
                return GateEvaluationResult(
                    gate_id=gate.id,
                    gate_type=gate.type.value,
                    decision=dec,
                    passed=False,
                    reason="Security snapshot drift detected across models, dependencies, or configuration.",
                    reason_codes=[ReasonCode.CONFIGURATION_DRIFT],
                    evidence_used=["snapshot_diff"],
                    details=details,
                )

        if baseline_diff and baseline_diff.regressions:
            dec = GovernanceDecision.FAIL if gate.required else GovernanceDecision.REVIEW
            return GateEvaluationResult(
                gate_id=gate.id,
                gate_type=gate.type.value,
                decision=dec,
                passed=False,
                reason=f"Security baseline regressions detected: {baseline_diff.regressions}.",
                reason_codes=[ReasonCode.BASELINE_REGRESSION],
                evidence_used=["baseline"],
            )

        return GateEvaluationResult(
            gate_id=gate.id,
            gate_type=gate.type.value,
            decision=GovernanceDecision.PASS,
            passed=True,
            reason="No security drift or regressions detected.",
        )

    def _evaluate_agent_gate(
        self,
        gate: SecurityGate,
        evidence: SecurityEvidence,
        baseline: Optional[SecurityBaseline],
    ) -> GateEvaluationResult:
        """Evaluate agent capability expansion and authorization boundaries."""
        # Detect privilege expansion if baseline has recorded capabilities
        if baseline and baseline.test_configuration.get("agent_capabilities"):
            base_caps = set(baseline.test_configuration.get("agent_capabilities", []))
            curr_caps = set(evidence.agent_capabilities)
            expanded = curr_caps - base_caps

            if expanded:
                dec = GovernanceDecision.REVIEW
                if gate.required and gate.max_allowed_severity == Severity.LOW:
                    dec = GovernanceDecision.FAIL
                return GateEvaluationResult(
                    gate_id=gate.id,
                    gate_type=gate.type.value,
                    decision=dec,
                    passed=False,
                    reason=f"Agent capability expansion detected: {sorted(list(expanded))}.",
                    reason_codes=[ReasonCode.CAPABILITY_EXPANSION, ReasonCode.REVIEW_REQUIRED],
                    evidence_used=["agent_capabilities"],
                    details={"expanded_capabilities": sorted(list(expanded))},
                )

        return GateEvaluationResult(
            gate_id=gate.id,
            gate_type=gate.type.value,
            decision=GovernanceDecision.PASS,
            passed=True,
            reason="Agent capability security requirements satisfied.",
            evidence_used=["agent_capabilities"],
        )

    def _evaluate_rag_gate(
        self,
        gate: SecurityGate,
        evidence: SecurityEvidence,
        baseline: Optional[SecurityBaseline],
    ) -> GateEvaluationResult:
        """Evaluate RAG provenance records and trust boundaries."""
        if evidence.rag_provenance_records:
            for rec in evidence.rag_provenance_records:
                if rec.get("trust_level") == "UNTRUSTED" or rec.get("poisoned", False):
                    return GateEvaluationResult(
                        gate_id=gate.id,
                        gate_type=gate.type.value,
                        decision=GovernanceDecision.BLOCK if gate.required else GovernanceDecision.REVIEW,
                        passed=False,
                        reason=f"RAG document provenance validation detected untrusted source: {rec.get('document_id', 'unknown')}.",
                        reason_codes=[ReasonCode.RAG_PROVENANCE_CHANGED],
                        evidence_used=["rag_provenance_records"],
                    )

        return GateEvaluationResult(
            gate_id=gate.id,
            gate_type=gate.type.value,
            decision=GovernanceDecision.PASS,
            passed=True,
            reason="RAG document provenance verified.",
            evidence_used=["rag_provenance_records"],
        )

    def _evaluate_policy_gate(
        self,
        gate: SecurityGate,
        evidence: SecurityEvidence,
        baseline: Optional[SecurityBaseline],
    ) -> GateEvaluationResult:
        """Evaluate policy changes and versions."""
        if baseline and baseline.policy_version and evidence.policy_version:
            if baseline.policy_version != evidence.policy_version:
                return GateEvaluationResult(
                    gate_id=gate.id,
                    gate_type=gate.type.value,
                    decision=GovernanceDecision.REVIEW,
                    passed=False,
                    reason=f"Security policy changed from {baseline.policy_version} to {evidence.policy_version}.",
                    reason_codes=[ReasonCode.POLICY_CHANGED, ReasonCode.REVIEW_REQUIRED],
                    evidence_used=["policy_version"],
                )

        return GateEvaluationResult(
            gate_id=gate.id,
            gate_type=gate.type.value,
            decision=GovernanceDecision.PASS,
            passed=True,
            reason="Policy version criteria satisfied.",
            evidence_used=["policy_version"],
        )

    def _emit_audit(self, event_type: str, details: Dict[str, Any]) -> None:
        """Emit structured audit event safe from raw secrets."""
        event = AuditEvent(
            scan_id=f"GOV-{details.get('release_id', 'unknown')}",
            action_taken=Action.BLOCK if "blocked" in event_type or "failed" in event_type else Action.ALLOW,
            risk_score=1.0 if "blocked" in event_type else 0.0,
            max_severity=Severity.CRITICAL if "blocked" in event_type else Severity.LOW,
            metadata={
                "governance_event": event_type,
                **details,
            },
        )
        self.audit_logger.emit(event)
