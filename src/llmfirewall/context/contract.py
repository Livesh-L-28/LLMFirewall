"""Decision Contracts for Context-Aware Security Enforcement.

Phase 5: Context-Aware Security Decisions.
Formalizes:
- Input signals and verified context bindings.
- Non-overridable policy rules (BLOCK can never be overridden by context).
- Contextual risk modulation (elevation on taint/untrusted content; bounded de-escalation on internal docs).
- Failure behavior contracts (fail-safe fallback, fail-closed enforcement, missing context).
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Set, Tuple

from llmfirewall.core.models import Action, Finding, RiskScore, Severity
from llmfirewall.context.models import TrustLevel, VerifiedSecurityContext
from llmfirewall.workflow.models import WorkflowThreatState

# List of high-risk tools that are strictly denied whenever workflow taint is elevated
RESTRICTED_TOOLS_ON_TAINT: Set[str] = {
    "shell_exec",
    "bash",
    "terminal",
    "cmd",
    "eval",
    "system_shutdown",
    "database_delete",
    "drop_table",
    "delete_file",
    "rm",
    "send_email",
    "raw_sql_exec",
    "export_db",
    "modify_iam_policy",
    "transfer_funds",
}


class ContextDecisionContract:
    """Enforces deterministic decision rules governing how verified application context modulates outcomes."""

    @staticmethod
    def evaluate_contract(
        findings: List[Finding],
        risk_score: RiskScore,
        context: Optional[VerifiedSecurityContext] = None,
        tool_name: Optional[str] = None,
    ) -> Tuple[float, List[Finding], Optional[Action], List[str]]:
        """Evaluate contextual contracts against findings and verified context.

        Returns:
            (contextual_multiplier, elevated_findings, forced_action, applied_rules)
        """
        if context is None:
            return 1.0, [], None, ["NO_CONTEXT_FALLBACK_STRICT"]

        contextual_multiplier = 1.0
        elevated_findings: List[Finding] = []
        forced_action: Optional[Action] = None
        applied_rules: List[str] = []

        # ---------------------------------------------------------------------
        # Rule 1: Non-Overridable Blocking Invariant
        # Any confirmed critical finding (e.g. prompt injection, leaked secret)
        # must NEVER be downgraded, regardless of caller reputation or trust.
        # ---------------------------------------------------------------------
        has_critical_finding = any(
            f.severity in (Severity.HIGH, Severity.CRITICAL) for f in findings
        )

        # ---------------------------------------------------------------------
        # Rule 2: Taint Propagation & Restricted Tool Gating
        # If workflow was tainted by an earlier injection or secret violation,
        # sensitive tools are unconditionally blocked.
        # ---------------------------------------------------------------------
        if context.workflow_threat_state in (WorkflowThreatState.TAINTED, WorkflowThreatState.CRITICAL) or context.has_prior_injection:
            contextual_multiplier *= 1.4
            applied_rules.append("TAINT_PROPAGATION_ACTIVE")

            if tool_name and tool_name.strip().lower() in RESTRICTED_TOOLS_ON_TAINT:
                forced_action = Action.BLOCK
                applied_rules.append(f"RESTRICTED_TOOL_ON_TAINT_BLOCKED:{tool_name}")

        # ---------------------------------------------------------------------
        # Rule 3: Retrieved Document Trust Gating
        # If document is unverified or external, elevate scrutiny for instructions
        # ---------------------------------------------------------------------
        if context.document_trust is not None:
            doc = context.document_trust
            if doc.trust_level in (TrustLevel.UNTRUSTED_EXTERNAL, TrustLevel.ANONYMOUS_PUBLIC) and not doc.is_verified:
                contextual_multiplier *= 1.25
                applied_rules.append("UNVERIFIED_EXTERNAL_RAG_SCRUTINY")

        # ---------------------------------------------------------------------
        # Rule 4: Caller Trust Level Modulation
        # Anonymous or unauthenticated endpoints face lower risk tolerance
        # ---------------------------------------------------------------------
        if context.caller_trust_level == TrustLevel.ANONYMOUS_PUBLIC and not context.is_authenticated:
            contextual_multiplier *= 1.20
            applied_rules.append("ANONYMOUS_CALLER_STRICT_POSTURE")

        # ---------------------------------------------------------------------
        # Rule 5: Bounded Safe Contextual De-escalation
        # Only low-confidence, non-critical warnings on verified internal documents
        # may be softened, NEVER confirmed injection or credential leakage.
        # ---------------------------------------------------------------------
        if (
            context.document_trust is not None
            and context.document_trust.trust_level == TrustLevel.TRUSTED_INTERNAL
            and context.document_trust.is_verified
            and not has_critical_finding
            and not context.has_prior_injection
        ):
            # Soften low-severity heuristic noise on internal signed docs
            contextual_multiplier *= 0.85
            applied_rules.append("INTERNAL_VERIFIED_DOC_DEESCALATION")

        return round(contextual_multiplier, 3), elevated_findings, forced_action, applied_rules
