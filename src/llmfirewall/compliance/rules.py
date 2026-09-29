"""Declarative compliance rules, rule context, and evaluation registry for Phase 36."""

from dataclasses import dataclass, field
import logging
import threading
import time
from typing import Any, Callable, Dict, List, Optional, Set

from llmfirewall.compliance.models import (
    ApplicabilityStatus,
    ComplianceControl,
    ComplianceEvidence,
    ComplianceException,
    ComplianceGap,
    ControlAssessment,
    ControlState,
    EvidenceType,
    EvidenceValidity,
    RemediationStatus,
)
from llmfirewall.core.models import Severity

logger = logging.getLogger("llmfirewall.compliance.rules")


# -----------------------------------------------------------------------------
# Evaluation Context
# -----------------------------------------------------------------------------

@dataclass
class ComplianceRuleContext:
    """Rich evaluation context provided to declarative compliance rules for assessing a control."""
    control: ComplianceControl
    asset: Any
    evidence: List[ComplianceEvidence] = field(default_factory=list)
    security_controls: Dict[str, Any] = field(default_factory=dict)
    posture: Optional[Any] = None
    tests: List[Dict[str, Any]] = field(default_factory=list)
    findings: List[Dict[str, Any]] = field(default_factory=list)
    attack_paths: List[Dict[str, Any]] = field(default_factory=list)
    policy_status: Dict[str, Any] = field(default_factory=dict)
    exceptions: List[ComplianceException] = field(default_factory=list)
    kg: Optional[Any] = None

    @property
    def asset_id(self) -> str:
        return getattr(self.asset, "id", str(self.asset))

    @property
    def asset_type(self) -> str:
        return getattr(self.asset, "type", "unknown")

    @property
    def environment(self) -> str:
        return getattr(self.asset, "environment", "unknown")


# -----------------------------------------------------------------------------
# Compliance Rule
# -----------------------------------------------------------------------------

class ComplianceRule:
    """Declarative compliance assessment rule evaluating evidence context."""

    def __init__(
        self,
        rule_id: str,
        name: str,
        description: str,
        evaluator: Callable[[ComplianceRuleContext], Optional[ControlAssessment]],
        enabled: bool = True,
    ) -> None:
        self.rule_id = rule_id.strip()
        self.name = name.strip()
        self.description = description.strip()
        self.evaluator = evaluator
        self.enabled = enabled

    def evaluate(self, context: ComplianceRuleContext) -> Optional[ControlAssessment]:
        if not self.enabled:
            return None
        try:
            return self.evaluator(context)
        except Exception as exc:
            logger.warning("Compliance rule '%s' evaluation error on control '%s': %s", self.rule_id, context.control.id, exc)
            return None


# -----------------------------------------------------------------------------
# Standard Rule Evaluators
# -----------------------------------------------------------------------------

def _eval_applicability(ctx: ComplianceRuleContext) -> Optional[ControlAssessment]:
    """Check applicability filters (asset_types, environments, tags)."""
    app = ctx.control.applicability
    if not app:
        return None

    # Check asset types
    target_types = app.get("asset_types")
    if target_types and ctx.asset_type not in target_types and "all" not in target_types:
        return ControlAssessment(
            framework_id=ctx.control.framework_id,
            control_id=ctx.control.id,
            asset_id=ctx.asset_id,
            status=ControlState.NOT_APPLICABLE,
            applicability=ApplicabilityStatus.NOT_APPLICABLE,
            applicability_reason=f"Control applies to asset types [{', '.join(target_types)}], but target is '{ctx.asset_type}'.",
            evidence=ctx.evidence,
        )

    # Check environments
    target_envs = app.get("environments")
    if target_envs and ctx.environment not in target_envs and "all" not in target_envs:
        return ControlAssessment(
            framework_id=ctx.control.framework_id,
            control_id=ctx.control.id,
            asset_id=ctx.asset_id,
            status=ControlState.NOT_APPLICABLE,
            applicability=ApplicabilityStatus.NOT_APPLICABLE,
            applicability_reason=f"Control applies to environments [{', '.join(target_envs)}], but target environment is '{ctx.environment}'.",
            evidence=ctx.evidence,
        )

    return None


def _eval_active_exception(ctx: ComplianceRuleContext) -> Optional[ControlAssessment]:
    """Check if an active, unexpired compliance exception or waiver exists."""
    for exc in ctx.exceptions:
        if exc.control_id.lower() == ctx.control.id.lower() and exc.is_active:
            return ControlAssessment(
                framework_id=ctx.control.framework_id,
                control_id=ctx.control.id,
                asset_id=ctx.asset_id,
                status=ControlState.IMPLEMENTED,  # Formally accepted waiver
                applicability=ApplicabilityStatus.APPLICABLE,
                applicability_reason=f"Formally waived via exception '{exc.exception_id}' approved by {exc.approved_by} until {exc.expires_at}.",
                evidence=ctx.evidence,
                exceptions=[exc],
            )
    return None


def _eval_failed_evidence(ctx: ComplianceRuleContext) -> Optional[ControlAssessment]:
    """Check for negative evidence: failed security tests, conflicting evidence, or active exploit findings."""
    # 1. Conflicting evidence check (Section 18)
    conflicting = [e for e in ctx.evidence if e.status == EvidenceValidity.CONFLICTING]
    if conflicting:
        gap = ComplianceGap(
            framework_id=ctx.control.framework_id,
            control_id=ctx.control.id,
            asset_id=ctx.asset_id,
            title="Conflicting Evidence Detected for Control",
            description=f"Contradictory evidence artifacts discovered for control '{ctx.control.id}': {[e.content_reference for e in conflicting]}.",
            severity=Severity.HIGH,
            missing_evidence=["consistent_configuration_and_telemetry"],
            remediation_guidance="Investigate discrepancies between configured policies and runtime telemetry.",
        )
        return ControlAssessment(
            framework_id=ctx.control.framework_id,
            control_id=ctx.control.id,
            asset_id=ctx.asset_id,
            status=ControlState.FAILED,
            applicability=ApplicabilityStatus.APPLICABLE,
            applicability_reason="Conflicting configuration and runtime evidence detected.",
            evidence=ctx.evidence,
            gaps=[gap],
        )

    # 2. Failing security tests (Section 44)
    failed_tests = [t for t in ctx.tests if not t.get("passed", True)]
    if failed_tests:
        gap = ComplianceGap(
            framework_id=ctx.control.framework_id,
            control_id=ctx.control.id,
            asset_id=ctx.asset_id,
            title=f"Security Test Failed for Control '{ctx.control.control_id}'",
            description=f"Automated security testing identified failures evaluating control '{ctx.control.id}': {failed_tests[0].get('name', 'test')}.",
            severity=Severity.HIGH,
            related_findings=[t.get("test_id", "test") for t in failed_tests],
            remediation_guidance="Fix underlying vulnerability and re-run empirical security test suite.",
        )
        return ControlAssessment(
            framework_id=ctx.control.framework_id,
            control_id=ctx.control.id,
            asset_id=ctx.asset_id,
            status=ControlState.FAILED,
            applicability=ApplicabilityStatus.APPLICABLE,
            applicability_reason="Empirical security tests failed for this control.",
            evidence=ctx.evidence,
            gaps=[gap],
        )

    # 3. Active Critical/High Findings (Section 43)
    critical_findings = [f for f in ctx.findings if str(f.get("severity", "")).upper() in ("CRITICAL", "HIGH")]
    if critical_findings:
        gap = ComplianceGap(
            framework_id=ctx.control.framework_id,
            control_id=ctx.control.id,
            asset_id=ctx.asset_id,
            title=f"Open Critical Finding Impairing Control '{ctx.control.control_id}'",
            description=f"Open high-severity security finding impairs control '{ctx.control.id}': {critical_findings[0].get('description', '')}.",
            severity=Severity.HIGH,
            related_findings=[f.get("finding_id", "finding") for f in critical_findings],
            remediation_guidance="Remediate open governance finding or obtain approved security waiver.",
        )
        return ControlAssessment(
            framework_id=ctx.control.framework_id,
            control_id=ctx.control.id,
            asset_id=ctx.asset_id,
            status=ControlState.FAILED,
            applicability=ApplicabilityStatus.APPLICABLE,
            applicability_reason="Active security finding compromises control effectiveness.",
            evidence=ctx.evidence,
            gaps=[gap],
        )

    return None


def _eval_evidence_synthesis(ctx: ComplianceRuleContext) -> ControlAssessment:
    """Synthesize evidence artifacts against control requirements to determine state (EVIDENCED, PARTIAL, IMPLEMENTED, UNKNOWN)."""
    now = time.time()
    req_evids = set(r.lower() for r in ctx.control.evidence_requirements)

    valid_evids = [e for e in ctx.evidence if e.status == EvidenceValidity.VALID and not e.is_expired]
    stale_evids = [e for e in ctx.evidence if e.status == EvidenceValidity.STALE or e.is_expired]

    # Map matched evidence requirement tokens
    matched_reqs: Set[str] = set()
    for e in valid_evids:
        e_type_token = e.type.value.lower()
        matched_reqs.add(e_type_token)
        # Check source or metadata tokens
        for token in req_evids:
            if token in e.content_reference.lower() or token in e_type_token or token in e.source.lower():
                matched_reqs.add(token)

    missing = sorted(list(req_evids - matched_reqs))

    # Defensive controls check
    has_defensive_controls = len(ctx.security_controls) > 0
    all_ctrls_validated = (
        has_defensive_controls and
        all(getattr(c, "effectiveness", None) == "VALIDATED" or getattr(c, "effectiveness", None) == 1 for c in ctx.security_controls.values())
    )

    # 1. Full Evidence (EVIDENCED)
    if (len(missing) == 0 and len(valid_evids) > 0) or (req_evids and matched_reqs.issuperset(req_evids)):
        return ControlAssessment(
            framework_id=ctx.control.framework_id,
            control_id=ctx.control.id,
            asset_id=ctx.asset_id,
            status=ControlState.EVIDENCED,
            applicability=ApplicabilityStatus.APPLICABLE,
            applicability_reason="All required evidence artifacts are verified present, fresh, and valid.",
            evidence=ctx.evidence,
            missing_evidence=[],
            gaps=[],
        )

    # 2. Partially Evidenced
    if len(valid_evids) > 0 or len(stale_evids) > 0 or len(matched_reqs) > 0:
        gap_desc = f"Control '{ctx.control.id}' is partially evidenced. Missing evidence: {', '.join(missing) if missing else 'stale test refresh required'}."
        gap = ComplianceGap(
            framework_id=ctx.control.framework_id,
            control_id=ctx.control.id,
            asset_id=ctx.asset_id,
            title=f"Missing Verification Evidence for Control '{ctx.control.control_id}'",
            description=gap_desc,
            severity=Severity.MEDIUM,
            missing_evidence=missing,
            remediation_guidance=f"Collect and attach required evidence artifacts: {', '.join(missing) if missing else 're-execute empirical security tests'}.",
        )
        return ControlAssessment(
            framework_id=ctx.control.framework_id,
            control_id=ctx.control.id,
            asset_id=ctx.asset_id,
            status=ControlState.PARTIALLY_EVIDENCED,
            applicability=ApplicabilityStatus.APPLICABLE,
            applicability_reason="Some evidence exists, but required verification evidence is incomplete or stale.",
            evidence=ctx.evidence,
            missing_evidence=missing,
            gaps=[gap],
        )

    # 3. Implemented but Untested (Controls configured, no empirical evidence)
    if has_defensive_controls or ctx.policy_status.get("assigned_policies"):
        gap = ComplianceGap(
            framework_id=ctx.control.framework_id,
            control_id=ctx.control.id,
            asset_id=ctx.asset_id,
            title=f"Defensive Control Configured but Untested ('{ctx.control.control_id}')",
            description=f"Defensive security controls or policies exist for '{ctx.control.id}', but zero empirical tests or runtime validation evidence have been recorded.",
            severity=Severity.MEDIUM,
            missing_evidence=missing or ["security_test_validation"],
            remediation_guidance="Execute automated security evaluation tests to validate defensive control efficacy.",
        )
        return ControlAssessment(
            framework_id=ctx.control.framework_id,
            control_id=ctx.control.id,
            asset_id=ctx.asset_id,
            status=ControlState.IMPLEMENTED,
            applicability=ApplicabilityStatus.APPLICABLE,
            applicability_reason="Control is configured in policy or inventory, but lacks empirical test evidence.",
            evidence=ctx.evidence,
            missing_evidence=missing,
            gaps=[gap],
        )

    # 4. Not Implemented
    if ctx.asset_type in ("agent", "tool", "application", "model", "rag_source"):
        gap = ComplianceGap(
            framework_id=ctx.control.framework_id,
            control_id=ctx.control.id,
            asset_id=ctx.asset_id,
            title=f"Required Control Not Implemented ('{ctx.control.control_id}')",
            description=f"Applicable compliance control '{ctx.control.id}' is not implemented in configuration, policy, or defensive guardrails.",
            severity=Severity.HIGH,
            missing_evidence=missing or list(req_evids),
            remediation_guidance=f"Configure defensive security guardrail satisfying requirements: {'; '.join(ctx.control.requirements[:2])}.",
        )
        return ControlAssessment(
            framework_id=ctx.control.framework_id,
            control_id=ctx.control.id,
            asset_id=ctx.asset_id,
            status=ControlState.NOT_IMPLEMENTED,
            applicability=ApplicabilityStatus.APPLICABLE,
            applicability_reason="No defensive controls or policies exist addressing this requirement.",
            evidence=ctx.evidence,
            missing_evidence=missing or list(req_evids),
            gaps=[gap],
        )

    # 5. Unknown
    return ControlAssessment(
        framework_id=ctx.control.framework_id,
        control_id=ctx.control.id,
        asset_id=ctx.asset_id,
        status=ControlState.UNKNOWN,
        applicability=ApplicabilityStatus.UNKNOWN,
        applicability_reason="Insufficient telemetry or unobserved asset state.",
        evidence=[],
        missing_evidence=list(req_evids),
        gaps=[],
    )


# -----------------------------------------------------------------------------
# Rule Registry
# -----------------------------------------------------------------------------

STANDARD_COMPLIANCE_RULES: List[ComplianceRule] = [
    ComplianceRule(
        rule_id="R-COMPL-01-APPLICABILITY",
        name="Control Applicability Filter",
        description="Determines if control applies to target asset type and environment.",
        evaluator=_eval_applicability,
    ),
    ComplianceRule(
        rule_id="R-COMPL-02-ACTIVE-EXCEPTION",
        name="Active Exception Resolution",
        description="Checks for active approved compliance waivers and exceptions.",
        evaluator=_eval_active_exception,
    ),
    ComplianceRule(
        rule_id="R-COMPL-03-FAILED-EVIDENCE",
        name="Failed Test or Finding Detection",
        description="Evaluates whether negative evidence (failed test, bypass finding, or conflict) fails the control.",
        evaluator=_eval_failed_evidence,
    ),
    ComplianceRule(
        rule_id="R-COMPL-04-EVIDENCE-SYNTHESIS",
        name="Evidence Synthesis & State Resolution",
        description="Synthesizes evidence artifacts against requirements to determine EVIDENCED, PARTIAL, or NOT_IMPLEMENTED.",
        evaluator=_eval_evidence_synthesis,
    ),
]


class ComplianceRuleRegistry:
    """Thread-safe versioned registry for compliance assessment rules."""

    def __init__(self, rules_version: str = "1.0.0", load_defaults: bool = True) -> None:
        self.rules_version = rules_version
        self._lock = threading.RLock()
        self._rules: Dict[str, ComplianceRule] = {}

        if load_defaults:
            for r in STANDARD_COMPLIANCE_RULES:
                self.register(r)

    def register(self, rule: ComplianceRule) -> None:
        with self._lock:
            self._rules[rule.rule_id] = rule

    def remove(self, rule_id: str) -> bool:
        with self._lock:
            return self._rules.pop(rule_id, None) is not None

    def get(self, rule_id: str) -> Optional[ComplianceRule]:
        with self._lock:
            return self._rules.get(rule_id)

    def list_rules(self) -> List[ComplianceRule]:
        with self._lock:
            return list(self._rules.values())

    def evaluate(self, context: ComplianceRuleContext) -> ControlAssessment:
        """Run registered rules sequentially; the first rule returning an assessment wins."""
        with self._lock:
            rules_to_run = list(self._rules.values())

        for r in rules_to_run:
            res = r.evaluate(context)
            if res is not None:
                return res

        # Fallback to evidence synthesis
        return _eval_evidence_synthesis(context)
