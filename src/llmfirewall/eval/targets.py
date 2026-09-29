"""Target abstractions allowing the evaluation engine to test firewalls, pipelines, and agents."""

from abc import ABC, abstractmethod
from typing import Any, Dict, Optional, Tuple, Union

from llmfirewall.core.models import Action, Finding, PolicyDecision, RiskScore, ScanResult
from llmfirewall.eval.models import SecurityTestCase, TargetType
from llmfirewall.firewall import Firewall
from llmfirewall.tools.models import ToolCall, ToolResult, ToolSecurityDecision


class EvaluationTarget(ABC):
    """Abstract target evaluated by the security red-team runner."""

    @abstractmethod
    def evaluate_test_case(
        self,
        test_case: SecurityTestCase,
    ) -> Tuple[Action, float, list[str], list[str], list[str]]:
        """Execute a test case against the target.
        
        Returns:
            Tuple of:
            - action: Action taken (ALLOW, WARN, BLOCK, REDACT)
            - risk_score: Numeric risk score (0.0 to 1.0)
            - detected_threats: List of ThreatType values detected
            - detector_names: List of detector identifiers that triggered
            - matched_rules: List of policy rule IDs triggered
        """
        pass


class FirewallTarget(EvaluationTarget):
    """Concrete target evaluating SecurityTestCases directly against an LLMFirewall instance."""

    def __init__(self, firewall: Optional[Firewall] = None) -> None:
        self._firewall = firewall or Firewall()

    @property
    def firewall(self) -> Firewall:
        return self._firewall

    def evaluate_test_case(
        self,
        test_case: SecurityTestCase,
    ) -> Tuple[Action, float, list[str], list[str], list[str]]:
        if test_case.target_type == TargetType.PROMPT:
            result = self._firewall.check_prompt(test_case.input_payload)
            return (
                result.decision.action,
                result.risk_score.score,
                [f.threat_type.value for f in result.findings],
                [f.detector_name for f in result.findings],
                result.decision.triggered_rules,
            )

        elif test_case.target_type == TargetType.OUTPUT:
            result = self._firewall.check_output(test_case.input_payload)
            return (
                result.decision.action,
                result.risk_score.score,
                [f.threat_type.value for f in result.findings],
                [f.detector_name for f in result.findings],
                result.decision.triggered_rules,
            )

        elif test_case.target_type == TargetType.TOOL_CALL:
            tool_name = test_case.tool_name or "default_tool"
            args = test_case.tool_arguments or {}
            decision = self._firewall.check_tool_call(tool_call_or_name=tool_name, arguments=args)
            return (
                decision.action,
                decision.risk_score.score if decision.risk_score else 0.0,
                [f.threat_type.value for f in decision.findings],
                [f.detector_name for f in decision.findings],
                decision.triggered_rules,
            )

        elif test_case.target_type == TargetType.TOOL_RESULT:
            tool_name = test_case.tool_name or "default_tool"
            decision = self._firewall.check_tool_result(
                tool_result_or_name=tool_name,
                output=test_case.input_payload,
            )
            return (
                decision.action,
                decision.risk_score.score if decision.risk_score else 0.0,
                [f.threat_type.value for f in decision.findings],
                [f.detector_name for f in decision.findings],
                decision.triggered_rules,
            )

        elif test_case.target_type == TargetType.AGENT:
            cap = test_case.agent_capability or "filesystem.read"
            res_scope = test_case.agent_resource or "./documents/*"
            dec = self._firewall.authorize_action(
                capability_name=cap,
                agent_id="test_agent",
                resource=res_scope,
                tool_name=test_case.tool_name or "default_tool",
            )
            act = Action.ALLOW if dec.is_allowed else Action.BLOCK
            threats = [] if dec.is_allowed else ["CAPABILITY_DENIED"]
            return (
                act,
                0.0 if dec.is_allowed else 1.0,
                threats,
                ["capability_engine"],
                [],
            )

        elif test_case.target_type == TargetType.RAG:
            p_res = self._firewall.check_prompt(test_case.input_payload)
            return (
                p_res.decision.action,
                p_res.risk_score.score,
                [f.threat_type.value for f in p_res.findings],
                [f.detector_name for f in p_res.findings],
                p_res.decision.triggered_rules,
            )

        else:
            raise ValueError(f"Unsupported target_type: {test_case.target_type}")


__all__ = [
    "EvaluationTarget",
    "FirewallTarget",
]

