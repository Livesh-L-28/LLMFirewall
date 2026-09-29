"""Deterministic Policy Engine implementation adhering strictly to 'Policy engine decides'."""

from typing import Any, Dict, List, Optional

from llmfirewall.core.interfaces import BasePolicyEngine
from llmfirewall.core.models import Action, Finding, PolicyDecision, RiskScore
from llmfirewall.policy.config import Policy, PolicyConfig, PolicyRule
from llmfirewall.policy.redactor import redact_text_spans

# Action Precedence Ranking: Higher rank strictly supersedes lower rank
# BLOCK > REDACT > WARN > ALLOW
ACTION_PRECEDENCE: Dict[Action, int] = {
    Action.BLOCK: 4,
    Action.REDACT: 3,
    Action.WARN: 2,
    Action.ALLOW: 1,
}


def get_default_policy() -> Policy:
    """Return the default production security policy for LLMFirewall."""
    from llmfirewall.core.models import ThreatType
    return Policy(
        name="default_ai_security_policy",
        version="1.0",
        description="Standard production guardrail policy: blocks injection & secrets, redacts PII",
        rules=[
            PolicyRule(
                id="block_prompt_injection",
                name="Block Prompt Injection",
                description="Block any prompt injection or jailbreak attempt",
                threat_type=ThreatType.PROMPT_INJECTION,
                action=Action.BLOCK,
                priority=100,
            ),
            PolicyRule(
                id="block_secrets",
                name="Block Leaked Secrets",
                description="Block raw secrets and credentials from leaking",
                threat_type=ThreatType.SECRET,
                action=Action.BLOCK,
                priority=90,
            ),
            PolicyRule(
                id="redact_pii",
                name="Redact PII",
                description="Redact Personally Identifiable Information (emails, cards, phones, IPs)",
                threat_type=ThreatType.PII,
                action=Action.REDACT,
                priority=80,
            ),
            PolicyRule(
                id="block_critical_risk_score",
                name="Block Critical Risk",
                description="Block requests with a composite risk score >= 0.85",
                min_risk_score=0.85,
                action=Action.BLOCK,
                priority=70,
            ),
            PolicyRule(
                id="warn_high_risk_score",
                name="Warn High Risk",
                description="Warn and log telemetry when composite risk score >= 0.65",
                min_risk_score=0.65,
                action=Action.WARN,
                priority=60,
            ),
        ],
        default_action=Action.ALLOW,
        auto_redact_on_warn=True,
    )


class PolicyEngine(BasePolicyEngine):
    """Deterministic, provider-agnostic policy decision engine.
    
    Adheres strictly to the architectural contract: 'Policy engine decides.'
    Converts findings and risk scores into an explicit PolicyDecision with actionable outcomes:
    - ALLOW: Proceed unaltered.
    - WARN: Flag risk for telemetry/logging, but allow flow to proceed.
    - BLOCK: Terminate execution immediately.
    - REDACT: Sanitize sensitive text spans while allowing downstream execution.
    
    Conflict Resolution Architecture:
    1. Precedence Hierarchy:
       BLOCK (4) > REDACT (3) > WARN (2) > ALLOW (1).
    2. Rule Priority:
       Among rules resulting in the highest action, rule with highest priority (and deterministic ID order) wins.
    3. Explainability:
       Constructs structured explanations detailing matched rules, criteria, and precedence outcomes.
    """

    def __init__(self, config: Optional[Policy] = None) -> None:
        self._policy = config or get_default_policy()

    @property
    def policy(self) -> Policy:
        """Active policy document."""
        return self._policy

    @property
    def config(self) -> Policy:
        """Backward-compatibility property returning active policy."""
        return self._policy

    def decide(
        self,
        text: str,
        findings: List[Finding],
        risk_score: RiskScore,
        context: Optional[Dict[str, Any]] = None,
    ) -> PolicyDecision:
        """Evaluate findings, risk score, and rules to choose a PolicyDecision with explainability.
        
        Args:
            text: Raw input or output text.
            findings: List of atomic Finding objects emitted by detectors.
            risk_score: Quantified RiskScore produced by RiskEngine.
            context: Optional contextual parameters.
            
        Returns:
            PolicyDecision: Action, rationale, triggered rules, explanations, and redacted text.
        """
        matched_rules: List[PolicyRule] = []
        explanations: List[Dict[str, Any]] = []

        # Sort rules by priority descending, then id ascending for determinism
        sorted_rules = sorted(
            [r for r in self._policy.rules if r.enabled],
            key=lambda r: (-r.priority, r.id),
        )

        for rule in sorted_rules:
            if rule.evaluate(findings, risk_score, context=context):
                matched_rules.append(rule)
                explanations.append({
                    "rule_id": rule.id,
                    "rule_name": rule.name or rule.id,
                    "action": rule.action.value,
                    "priority": rule.priority,
                    "description": rule.description,
                })

        # Edge Case 1: No rules triggered -> return configured default action
        if not matched_rules:
            return PolicyDecision(
                action=self._policy.default_action,
                reason="No policy violations or risk thresholds triggered; default allow.",
                triggered_rules=[],
                redacted_text=text if self._policy.default_action == Action.REDACT else None,
                policy_id=self._policy.name,
                policy_version=self._policy.version,
                explanations=[],
                metadata={
                    "conflict_resolved": False,
                    "policy_name": self._policy.name,
                    "policy_version": self._policy.version,
                },
            )

        # Conflict Resolution: Select the action with highest precedence
        # Tie-breaker: rule priority (first in sorted list for that action)
        winning_rule = max(
            matched_rules,
            key=lambda r: (ACTION_PRECEDENCE.get(r.action, 0), r.priority),
        )
        winning_action = winning_rule.action

        triggered_rule_ids = [r.id for r in matched_rules]
        reason = (
            f"Action '{winning_action.value.upper()}' determined by rule '{winning_rule.id}': "
            f"{winning_rule.description}."
        )

        if len(matched_rules) > 1:
            all_actions = sorted(list({r.action.value for r in matched_rules}))
            conflict_msg = f" Conflicting actions resolved [{', '.join(all_actions)}] -> {winning_action.value}."
            reason += conflict_msg

        # Redaction Execution
        redacted_content: Optional[str] = None
        if winning_action == Action.REDACT or (
            winning_action == Action.WARN and self._policy.auto_redact_on_warn
        ):
            redactable_findings = [f for f in findings if f.start_pos is not None and f.end_pos is not None]
            if redactable_findings:
                redacted_content = redact_text_spans(
                    text,
                    redactable_findings,
                    config=self._policy.redaction_config,
                )
            else:
                redacted_content = text

        return PolicyDecision(
            action=winning_action,
            reason=reason,
            triggered_rules=triggered_rule_ids,
            redacted_text=redacted_content,
            policy_id=self._policy.name,
            policy_version=self._policy.version,
            explanations=explanations,
            metadata={
                "winning_rule_id": winning_rule.id,
                "conflict_resolved": len(matched_rules) > 1,
                "triggered_rules_count": len(matched_rules),
                "policy_name": self._policy.name,
                "policy_version": self._policy.version,
            },
        )
