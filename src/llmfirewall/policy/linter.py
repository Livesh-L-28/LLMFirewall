"""Policy-as-Code linter and static validation engine for LLMFirewall."""

from enum import Enum
from typing import Any, Dict, List, Optional, Set
from pydantic import BaseModel, ConfigDict, Field

from llmfirewall.core.models import Action, Severity
from llmfirewall.policy.config import Policy, PolicyRule, RuleCondition


class LintSeverity(str, Enum):
    """Severity classification for policy linting findings."""
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"


class PolicyLintIssue(BaseModel):
    """An individual issue, warning, or recommendation detected in a Policy document."""
    model_config = ConfigDict(frozen=True, extra="forbid")

    rule_id: Optional[str] = Field(default=None, description="Rule ID associated with this issue, if applicable")
    severity: LintSeverity = Field(..., description="Severity level of the linting finding")
    code: str = Field(..., description="Machine-readable rule code (e.g. 'ERR_INVERTED_SEVERITY')")
    message: str = Field(..., description="Human-readable explanation of the issue")
    recommendation: Optional[str] = Field(default=None, description="Guidance to resolve the issue")


class PolicyLintReport(BaseModel):
    """Comprehensive policy linting and static analysis report."""
    model_config = ConfigDict(frozen=True, extra="forbid")

    policy_name: str = Field(..., description="Name of the analyzed policy")
    policy_version: str = Field(..., description="Version of the analyzed policy")
    valid: bool = Field(..., description="True if policy contains zero ERROR-level issues")
    issues: List[PolicyLintIssue] = Field(default_factory=list, description="All lint issues detected")
    rules_analyzed: int = Field(default=0, description="Total number of rules inspected")

    @property
    def is_valid(self) -> bool:
        """Alias for valid."""
        return self.valid

    @property
    def errors(self) -> List[PolicyLintIssue]:
        """List of all ERROR-level issues."""
        return [i for i in self.issues if i.severity == LintSeverity.ERROR]

    @property
    def warnings(self) -> List[PolicyLintIssue]:
        """List of all WARNING-level issues."""
        return [i for i in self.issues if i.severity == LintSeverity.WARNING]

    @property
    def has_errors(self) -> bool:
        """Check if any ERROR-level issues exist."""
        return any(i.severity == LintSeverity.ERROR for i in self.issues)

    @property
    def has_warnings(self) -> bool:
        """Check if any WARNING-level issues exist."""
        return any(i.severity == LintSeverity.WARNING for i in self.issues)


class PolicyLinter:
    """Static analysis and linting engine for LLMFirewall Policy-as-Code documents.
    
    Checks for:
    - Inverted severity or risk score boundaries (min > max).
    - Unreachable/shadowed rules due to precedence and identical conditions.
    - Conflicting tool definitions (tool in both allowlist and denylist).
    - Unconditional rules that unintentionally match all traffic.
    - Inactive/disabled rules.
    - Incomplete policy enforcement (permissive defaults with no blocking rules).
    """

    @classmethod
    def lint(cls, policy: Policy) -> PolicyLintReport:
        """Perform static analysis on a Policy document."""
        issues: List[PolicyLintIssue] = []

        # 1. Tool allowlist / denylist conflict check
        if policy.allowed_tools and policy.denied_tools:
            overlap = set(policy.allowed_tools) & set(policy.denied_tools)
            for tool in sorted(overlap):
                issues.append(
                    PolicyLintIssue(
                        severity=LintSeverity.ERROR,
                        code="ERR_TOOL_CONFLICT",
                        message=f"Tool '{tool}' is present in both allowed_tools and denied_tools.",
                        recommendation=f"Remove '{tool}' from either allowed_tools or denied_tools.",
                    )
                )

        # 2. Inspect individual rules and conditions
        has_block_rule = False
        active_rules: List[PolicyRule] = []

        for rule in policy.rules:
            if not rule.enabled:
                issues.append(
                    PolicyLintIssue(
                        rule_id=rule.id,
                        severity=LintSeverity.INFO,
                        code="INFO_RULE_DISABLED",
                        message=f"Rule '{rule.id}' is disabled and will not be evaluated at runtime.",
                        recommendation="Enable the rule or remove it if no longer needed.",
                    )
                )
                continue

            active_rules.append(rule)
            if rule.action == Action.BLOCK:
                has_block_rule = True

            # Check condition criteria within the rule
            conditions_to_check: List[RuleCondition] = list(rule.conditions)
            if not rule.conditions:
                # Direct condition
                direct = RuleCondition(
                    threat_type=rule.threat_type,
                    min_severity=rule.min_severity,
                    min_risk_score=rule.min_risk_score,
                    direction=rule.direction,
                )
                conditions_to_check.append(direct)

            # Check for unconditional rule (matches EVERYTHING)
            is_unconditional = True
            for cond in conditions_to_check:
                if any([
                    cond.threat_type is not None,
                    cond.detector is not None,
                    cond.category is not None,
                    cond.min_severity is not None,
                    cond.max_severity is not None,
                    cond.min_risk_score is not None,
                    cond.max_risk_score is not None,
                    cond.min_findings_count is not None,
                    cond.direction is not None,
                    cond.tool is not None,
                    cond.tool_permission is not None,
                    cond.destination_class is not None,
                    cond.source_type is not None,
                    cond.trust_level is not None,
                    cond.source_id is not None,
                    cond.min_confidence is not None,
                    cond.source is not None,
                    cond.user_id is not None,
                    bool(cond.custom_predicates),
                ]):
                    is_unconditional = False
                    break

            if is_unconditional:
                issues.append(
                    PolicyLintIssue(
                        rule_id=rule.id,
                        severity=LintSeverity.WARNING,
                        code="WARN_UNCONDITIONAL_RULE",
                        message=f"Rule '{rule.id}' has no criteria defined; it will match all traffic unconditionally.",
                        recommendation="Specify at least one condition (e.g. threat_type, min_severity, or source).",
                    )
                )

            # Check inverted bounds
            for cond in conditions_to_check:
                if cond.min_severity is not None and cond.max_severity is not None:
                    if cond.min_severity > cond.max_severity:
                        issues.append(
                            PolicyLintIssue(
                                rule_id=rule.id,
                                severity=LintSeverity.ERROR,
                                code="ERR_INVERTED_SEVERITY",
                                message=(
                                    f"Rule '{rule.id}' has inverted severity bounds: "
                                    f"min_severity ({cond.min_severity.value}) > max_severity ({cond.max_severity.value})."
                                ),
                                recommendation="Ensure min_severity is less than or equal to max_severity.",
                            )
                        )

                if cond.min_risk_score is not None and cond.max_risk_score is not None:
                    if cond.min_risk_score > cond.max_risk_score:
                        issues.append(
                            PolicyLintIssue(
                                rule_id=rule.id,
                                severity=LintSeverity.ERROR,
                                code="ERR_INVERTED_RISK_BOUNDS",
                                message=(
                                    f"Rule '{rule.id}' has inverted risk bounds: "
                                    f"min_risk_score ({cond.min_risk_score}) > max_risk_score ({cond.max_risk_score})."
                                ),
                                recommendation="Ensure min_risk_score is less than or equal to max_risk_score.",
                            )
                        )

        # 3. Check for shadowed / unreachable rules
        # Sort active rules by priority descending
        sorted_rules = sorted(active_rules, key=lambda r: (-r.priority, r.id))
        for i, higher_rule in enumerate(sorted_rules):
            if higher_rule.action != Action.BLOCK:
                continue
            for lower_rule in sorted_rules[i + 1:]:
                # If identical direct criteria or identical single condition and lower has <= priority
                if higher_rule.conditions == lower_rule.conditions and (
                    higher_rule.threat_type == lower_rule.threat_type
                    and higher_rule.min_severity == lower_rule.min_severity
                    and higher_rule.min_risk_score == lower_rule.min_risk_score
                    and higher_rule.direction == lower_rule.direction
                ):
                    issues.append(
                        PolicyLintIssue(
                            rule_id=lower_rule.id,
                            severity=LintSeverity.WARNING,
                            code="WARN_SHADOWED_RULE",
                            message=(
                                f"Rule '{lower_rule.id}' is shadowed by higher-priority BLOCK rule '{higher_rule.id}' "
                                f"with identical criteria."
                            ),
                            recommendation="Remove the redundant rule or refine its conditions.",
                        )
                    )

        # 4. Check for permissive default with no active blocking rules
        if policy.default_action == Action.ALLOW and not has_block_rule:
            issues.append(
                PolicyLintIssue(
                    severity=LintSeverity.WARNING,
                    code="WARN_PERMISSIVE_POLICY",
                    message="Policy has default_action=ALLOW and zero active BLOCK rules. No threats will be blocked.",
                    recommendation="Add at least one active BLOCK rule for critical threats (e.g. prompt injection, secrets).",
                )
            )

        valid = not any(i.severity == LintSeverity.ERROR for i in issues)

        return PolicyLintReport(
            policy_name=policy.name,
            policy_version=policy.version,
            valid=valid,
            issues=issues,
            rules_analyzed=len(policy.rules),
        )


def lint_policy(policy: Policy) -> PolicyLintReport:
    """Convenience helper to lint a Policy document."""
    return PolicyLinter.lint(policy)
