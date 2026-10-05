"""Agent and tool-call security engine coordinating identity, permissions, arguments, and results."""

import time
from typing import Any, Dict, List, Optional, Set, Union
import json

from llmfirewall.core.exceptions import LLMFirewallError
from llmfirewall.core.models import (
    Action,
    AuditEvent,
    Finding,
    PolicyDecision,
    RiskScore,
    ScanRequest,
    Severity,
    ThreatType,
)
from llmfirewall.detectors.collection import FindingCollection
from llmfirewall.detectors.engine import DetectorEngine
from llmfirewall.policy.config import Policy
from llmfirewall.policy.engine import ACTION_PRECEDENCE, PolicyEngine
from llmfirewall.risk.engine import RiskEngine
from llmfirewall.capabilities.approval import ApprovalProvider
from llmfirewall.capabilities.budget import BudgetManager
from llmfirewall.capabilities.engine import CapabilityEngine
from llmfirewall.capabilities.models import (
    ActionDecisionStatus,
    ActionRequest,
)
from llmfirewall.tools.command_security import inspect_command_safety, inspect_sql_safety
from llmfirewall.tools.models import (
    ResultTrustLevel,
    ToolCall,
    ToolPermission,
    ToolResult,
    ToolSecurityDecision,
)
from llmfirewall.tools.path_security import validate_path_safety
from llmfirewall.tools.registry import ToolDefinition, ToolRegistry, default_tool_registry
from llmfirewall.tools.url_security import validate_url_safety
from llmfirewall.tools.validator import (
    ArgumentLimits,
    validate_argument_limits,
    validate_json_schema,
)


class ToolSecurityEngine:
    """Security engine evaluating AI agent tool calls and tool results.
    
    Security Pipeline for Tool Calls (Agent & Tool Security 2.0):
    1. Tool Identity & Allowlist / Denylist Check
    2. Tool Definition & Granular Permissions Resolution
    3. Replay Protection & Action Nonce / Deduplication Validation
    4. Stateful Capability & Role Authorization (via CapabilityEngine)
    5. Action-Chain & Lineage Tracking (Preventing Unauthorized Escalation Across Multi-Step Chains)
    6. Typed Parameter & Schema Validation (Enum, Range, Type, Structure)
    7. Destination, URL (SSRF), File Path, and Command Inspection
    8. Sensitive Argument Scanning (PII, Secrets, Injection via Detector Engine)
    9. Risk Scoring & Policy-as-Code Evaluation with Explainability
    10. Human/Policy Approval Gates & Budget Enforcement
    11. Outcome Construction (ToolSecurityDecision) with Full Provenance
    
    Security Pipeline for Tool Results:
    1. Output Size Inspection
    2. Indirect Prompt Injection, PII, and Secret Detection
    3. Tool Result Provenance & Trust Classification (TRUSTED, UNTRUSTED, SANITIZED, QUARANTINED)
    4. Policy Engine Evaluation (ALLOW, REDACT, or BLOCK)
    5. Action-Chain History Update & Outcome Construction
    """

    def __init__(
        self,
        registry: Optional[ToolRegistry] = None,
        policy_engine: Optional[PolicyEngine] = None,
        detector_engine: Optional[DetectorEngine] = None,
        risk_engine: Optional[RiskEngine] = None,
        capability_engine: Optional[CapabilityEngine] = None,
        enforce_registry: bool = False,
        enforce_capabilities: Optional[bool] = None,
        argument_limits: Optional[ArgumentLimits] = None,
        enable_replay_protection: bool = False,
    ) -> None:
        """
        Args:
            registry: ToolRegistry containing authorized tool definitions.
            policy_engine: PolicyEngine instance enforcing declarative rules.
            detector_engine: DetectorEngine running security detectors.
            risk_engine: RiskEngine scoring findings.
            capability_engine: CapabilityEngine resolving stateful permissions, scopes, and chains.
            enforce_registry: If True, reject any tool not explicitly in registry.
            enforce_capabilities: If True, require explicit capability grants for all mapped tools.
            argument_limits: Boundaries on tool argument sizes and nesting depth.
            enable_replay_protection: If True, detect and block repeated identical tool calls.
        """
        self._registry = registry or default_tool_registry
        self._policy_engine = policy_engine or PolicyEngine()
        self._detector_engine = detector_engine or DetectorEngine()
        self._risk_engine = risk_engine or RiskEngine()
        self._capability_engine = capability_engine or CapabilityEngine()
        self._enforce_registry = enforce_registry
        self._enforce_capabilities = enforce_capabilities if enforce_capabilities is not None else (capability_engine is not None)
        self._argument_limits = argument_limits or ArgumentLimits()
        self._enable_replay_protection = enable_replay_protection
        self._seen_invocations: Set[str] = set()

    @property
    def registry(self) -> ToolRegistry:
        return self._registry

    @property
    def policy_engine(self) -> PolicyEngine:
        return self._policy_engine

    @property
    def capability_engine(self) -> CapabilityEngine:
        return self._capability_engine

    def check_tool_call(
        self,
        tool_call: Union[ToolCall, Dict[str, Any]],
        context: Optional[Dict[str, Any]] = None,
        budget_manager: Optional[BudgetManager] = None,
    ) -> ToolSecurityDecision:
        """Inspect and enforce security controls on a requested tool call.
        
        Args:
            tool_call: ToolCall instance or dict with 'tool_name' and 'arguments'.
            context: Optional contextual parameters.
            budget_manager: Optional BudgetManager enforcing action ceilings.
            
        Returns:
            ToolSecurityDecision: Deterministic ALLOW, WARN, or BLOCK decision.
        """
        start_time = time.perf_counter()

        if isinstance(tool_call, dict):
            call = ToolCall(
                tool_name=tool_call.get("tool_name") or tool_call.get("name", ""),
                arguments=tool_call.get("arguments", {}),
                request_id=tool_call.get("request_id"),
                user_id=tool_call.get("user_id"),
                session_id=tool_call.get("session_id"),
                agent_id=tool_call.get("agent_id"),
                parent_action_id=tool_call.get("parent_action_id"),
                chain_id=tool_call.get("chain_id"),
                call_provenance=tool_call.get("call_provenance"),
                metadata=tool_call.get("metadata", {}),
            )
        else:
            call = tool_call

        findings: List[Finding] = []
        triggered_rules: List[str] = []
        explanations: List[Dict[str, Any]] = []
        active_policy = self._policy_engine.policy

        agent_id = call.agent_id or (context or {}).get("agent_id", "default_agent")
        session_id = call.session_id or (context or {}).get("session_id", "default_session")
        chain_id = call.chain_id or (context or {}).get("chain_id")

        # -------------------------------------------------------------
        # 0. Replay Protection (Optional Nonce / Deduplication Check)
        # -------------------------------------------------------------
        if self._enable_replay_protection:
            invocation_key = f"{session_id}:{call.tool_name}:{call.serialize_arguments()}"
            if invocation_key in self._seen_invocations:
                findings.append(
                    Finding(
                        detector_name="replay_guard",
                        threat_type=ThreatType.POLICY_VIOLATION,
                        description=f"Duplicate/replay tool call detected for tool '{call.tool_name}'.",
                        severity=Severity.HIGH,
                        confidence=1.0,
                        metadata={"tool": call.tool_name, "violation": "tool_replay_detected"},
                    )
                )
            else:
                self._seen_invocations.add(invocation_key)

        # -------------------------------------------------------------
        # 1. Tool Identity & Denylist / Allowlist Enforcement
        # -------------------------------------------------------------
        if active_policy.denied_tools:
            denied_normalized = {t.strip().lower() for t in active_policy.denied_tools}
            if call.tool_name in denied_normalized:
                findings.append(
                    Finding(
                        detector_name="tool_identity",
                        threat_type=ThreatType.POLICY_VIOLATION,
                        description=f"Tool '{call.tool_name}' is explicitly denied by policy.",
                        severity=Severity.CRITICAL,
                        confidence=1.0,
                        metadata={"tool": call.tool_name, "violation": "tool_denied"},
                    )
                )

        if active_policy.allowed_tools is not None:
            allowed_normalized = {t.strip().lower() for t in active_policy.allowed_tools}
            if call.tool_name not in allowed_normalized:
                findings.append(
                    Finding(
                        detector_name="tool_identity",
                        threat_type=ThreatType.POLICY_VIOLATION,
                        description=f"Tool '{call.tool_name}' is not in policy allowlist.",
                        severity=Severity.CRITICAL,
                        confidence=1.0,
                        metadata={"tool": call.tool_name, "violation": "tool_not_allowed"},
                    )
                )

        tool_def = self._registry.get(call.tool_name)
        if self._enforce_registry and tool_def is None:
            findings.append(
                Finding(
                    detector_name="tool_registry",
                    threat_type=ThreatType.POLICY_VIOLATION,
                    description=f"Tool '{call.tool_name}' is not registered in authorized ToolRegistry.",
                    severity=Severity.CRITICAL,
                    confidence=1.0,
                    metadata={"tool": call.tool_name, "violation": "unregistered_tool"},
                )
            )

        # -------------------------------------------------------------
        # 2. Stateful Capability Authorization & Action-Chain Tracking
        # -------------------------------------------------------------
        approval_needed_from_cap = False
        if self._enforce_capabilities:
            required_caps = self._capability_engine.tool_map.get(call.tool_name, [])
            primary_resource = None
            for k, v in call.arguments.items():
                if any(term in k.lower() for term in ("path", "file", "url", "table", "resource")) and isinstance(v, str):
                    primary_resource = v
                    break

            for cap_name in required_caps:
                act_req = ActionRequest(
                    action_id=call.id,
                    parent_action_id=call.parent_action_id,
                    agent_id=agent_id,
                    session_id=session_id,
                    capability_name=cap_name,
                    tool_name=call.tool_name,
                    resource=primary_resource,
                    arguments_metadata={"keys": list(call.arguments.keys())},
                )
                cap_dec = self._capability_engine.authorize_action(act_req, budget_manager=budget_manager)
                if cap_dec.decision == ActionDecisionStatus.DENY:
                    for f in cap_dec.findings:
                        findings.append(f)
                    break
                elif cap_dec.decision == ActionDecisionStatus.BUDGET_EXCEEDED:
                    for f in cap_dec.findings:
                        findings.append(f)
                    break
                elif cap_dec.decision == ActionDecisionStatus.REQUIRE_APPROVAL:
                    approval_needed_from_cap = True

        # -------------------------------------------------------------
        # 3. Argument Limits & Schema Validation
        # -------------------------------------------------------------
        limit_finding = validate_argument_limits(call.arguments, self._argument_limits)
        if limit_finding:
            findings.append(limit_finding)

        if tool_def and tool_def.schema:
            schema_finding = validate_json_schema(call.arguments, tool_def.schema)
            if schema_finding:
                findings.append(schema_finding)

        # -------------------------------------------------------------
        # 4. Destination, SSRF, File Path, Command & SQL Inspection
        # -------------------------------------------------------------
        dest_class: Optional[str] = None

        for key, val in call.arguments.items():
            if isinstance(val, str):
                if "url" in key.lower() or val.startswith(("http://", "https://", "ftp://", "file://")):
                    url_finding = validate_url_safety(val)
                    if url_finding:
                        findings.append(url_finding)
                        dest_class = url_finding.metadata.get("violation", "unsafe_url")
                    elif tool_def and tool_def.allowed_domains is not None:
                        from urllib.parse import urlparse
                        host = (urlparse(val).hostname or "").lower()
                        if host not in {d.lower() for d in tool_def.allowed_domains}:
                            findings.append(
                                Finding(
                                    detector_name="url_security",
                                    threat_type=ThreatType.POLICY_VIOLATION,
                                    description=f"Domain '{host}' is not in allowed domains for tool '{call.tool_name}'.",
                                    severity=Severity.HIGH,
                                    confidence=1.0,
                                    metadata={"host": host, "violation": "domain_not_allowed"},
                                )
                            )

                if "path" in key.lower() or "file" in key.lower() or "/" in val or "\\" in val:
                    allowed_paths = tool_def.allowed_paths if tool_def else None
                    path_finding = validate_path_safety(val, allowed_base_dirs=allowed_paths)
                    if path_finding:
                        findings.append(path_finding)

                if "cmd" in key.lower() or "command" in key.lower() or "exec" in key.lower() or "shell" in call.tool_name:
                    cmd_finding = inspect_command_safety(val)
                    if cmd_finding:
                        findings.append(cmd_finding)

                if "sql" in key.lower() or "query" in key.lower():
                    sql_finding = inspect_sql_safety(val)
                    if sql_finding:
                        findings.append(sql_finding)

        # -------------------------------------------------------------
        # 5. Sensitive Argument Scanning (PII, Secrets, Injection)
        # -------------------------------------------------------------
        serialized_args = call.serialize_arguments()
        scan_ctx = dict(context or {})
        scan_ctx["direction"] = "input"
        scan_ctx["tool"] = call.tool_name
        scan_ctx["agent_id"] = agent_id
        if tool_def:
            scan_ctx["tool_permissions"] = [p.value for p in tool_def.permissions]
        if dest_class:
            scan_ctx["destination_class"] = dest_class

        arg_findings_col = self._detector_engine.execute(
            text=serialized_args,
            direction="input",
            context=scan_ctx,
        )
        if arg_findings_col.findings:
            findings.extend(arg_findings_col.findings)

        # -------------------------------------------------------------
        # 6. Risk Scoring & Policy-as-Code Evaluation
        # -------------------------------------------------------------
        risk_score = self._risk_engine.evaluate(findings=findings, context=scan_ctx)

        policy_decision = self._policy_engine.decide(
            text=serialized_args,
            findings=findings,
            risk_score=risk_score,
            context=scan_ctx,
        )

        final_action = policy_decision.action
        final_reason = policy_decision.reason
        triggered_rules.extend(policy_decision.triggered_rules)
        explanations.extend(policy_decision.explanations)

        # -------------------------------------------------------------
        # 7. Human Approval & Dangerous Tool Hooks
        # -------------------------------------------------------------
        requires_approval = approval_needed_from_cap
        if tool_def and (tool_def.requires_approval or tool_def.is_dangerous):
            requires_approval = True

        blocking_findings = [f for f in findings if f.severity in (Severity.CRITICAL, Severity.HIGH)]
        if blocking_findings and final_action != Action.BLOCK:
            final_action = Action.BLOCK
            final_reason = f"Tool call blocked due to security finding: {blocking_findings[0].description}"

        elapsed_ms = (time.perf_counter() - start_time) * 1000.0

        decision_explanation = (
            f"Decision: {final_action.value.upper()}. Reason: {final_reason}. "
            f"Findings: {len(findings)}. Requires Approval: {requires_approval}."
        )

        return ToolSecurityDecision(
            tool_name=call.tool_name,
            action=final_action,
            reason=final_reason,
            triggered_rules=triggered_rules,
            findings=findings,
            risk_score=risk_score,
            require_approval=requires_approval,
            chain_id=chain_id,
            explanation=decision_explanation,
            policy_id=active_policy.name,
            policy_version=active_policy.version,
            explanations=explanations,
            execution_time_ms=round(elapsed_ms, 3),
            metadata={
                "tool_name": call.tool_name,
                "request_id": call.request_id,
                "user_id": call.user_id,
                "agent_id": agent_id,
                "session_id": session_id,
                "chain_id": chain_id,
                "has_findings": len(findings) > 0,
            },
        )

    def check_tool_result(
        self,
        tool_result: Union[ToolResult, Dict[str, Any]],
        context: Optional[Dict[str, Any]] = None,
    ) -> ToolSecurityDecision:
        """Inspect and enforce security controls on a tool's output before returning to LLM.
        
        Guards against indirect prompt injection, sensitive data leakage, and untrusted tool outputs.
        
        Args:
            tool_result: ToolResult instance or dict with 'tool_name' and 'output'.
            context: Contextual parameters.
            
        Returns:
            ToolSecurityDecision: ALLOW, WARN, REDACT, or BLOCK outcome.
        """
        start_time = time.perf_counter()

        if isinstance(tool_result, dict):
            raw_trust = tool_result.get("trust_level", ResultTrustLevel.UNTRUSTED)
            if isinstance(raw_trust, str):
                try:
                    res_trust = ResultTrustLevel(raw_trust)
                except ValueError:
                    res_trust = ResultTrustLevel.UNTRUSTED
            else:
                res_trust = raw_trust

            res = ToolResult(
                tool_name=tool_result.get("tool_name") or tool_result.get("name", ""),
                output=str(tool_result.get("output", "")),
                tool_call_id=tool_result.get("tool_call_id"),
                request_id=tool_result.get("request_id"),
                agent_id=tool_result.get("agent_id"),
                session_id=tool_result.get("session_id"),
                chain_id=tool_result.get("chain_id"),
                trust_level=res_trust,
                result_provenance=tool_result.get("result_provenance"),
                success=tool_result.get("success", True),
                error=tool_result.get("error"),
                metadata=tool_result.get("metadata", {}),
            )
        else:
            res = tool_result

        scan_ctx = dict(context or {})
        scan_ctx["direction"] = "output"
        scan_ctx["tool"] = res.tool_name
        scan_ctx["tool_result"] = True
        scan_ctx["trust_level"] = res.trust_level.value

        # 1. Run Detectors on Output (Prompt Injection, PII, Secrets)
        findings_col = self._detector_engine.execute(
            text=res.output,
            direction="output",
            context=scan_ctx,
        )
        findings = list(findings_col.findings)

        # Check for indirect prompt injection in tool result
        injection_detector = next(
            (d for d in self._detector_engine.detectors if d.metadata.name == "prompt_injection_detector"),
            None,
        )
        if injection_detector is not None:
            inj_findings = injection_detector.detect(res.output, context=scan_ctx)
            if inj_findings:
                findings.extend(inj_findings)

        # 2. Risk Engine Evaluation
        risk_score = self._risk_engine.evaluate(findings=findings, context=scan_ctx)

        # 3. Policy Engine Evaluation
        policy_decision = self._policy_engine.decide(
            text=res.output,
            findings=findings,
            risk_score=risk_score,
            context=scan_ctx,
        )

        sanitized_output = None
        evaluated_trust = res.trust_level
        if policy_decision.action == Action.REDACT:
            sanitized_output = policy_decision.redacted_text
            evaluated_trust = ResultTrustLevel.SANITIZED
        elif policy_decision.action == Action.WARN and self._policy_engine.policy.auto_redact_on_warn:
            sanitized_output = policy_decision.redacted_text
            evaluated_trust = ResultTrustLevel.SANITIZED
        elif policy_decision.action == Action.BLOCK:
            sanitized_output = ""
            evaluated_trust = ResultTrustLevel.QUARANTINED
        else:
            sanitized_output = res.output

        elapsed_ms = (time.perf_counter() - start_time) * 1000.0

        decision_explanation = (
            f"Result Decision: {policy_decision.action.value.upper()}. Reason: {policy_decision.reason}. "
            f"Trust: {evaluated_trust.value}. Findings: {len(findings)}."
        )

        return ToolSecurityDecision(
            tool_name=res.tool_name,
            action=policy_decision.action,
            reason=policy_decision.reason,
            triggered_rules=policy_decision.triggered_rules,
            findings=findings,
            risk_score=risk_score,
            sanitized_output=sanitized_output,
            trust_level=evaluated_trust,
            chain_id=res.chain_id,
            explanation=decision_explanation,
            policy_id=self._policy_engine.policy.name,
            policy_version=self._policy_engine.policy.version,
            explanations=policy_decision.explanations,
            execution_time_ms=round(elapsed_ms, 3),
            metadata={
                "tool_name": res.tool_name,
                "tool_call_id": res.tool_call_id,
                "request_id": res.request_id,
                "agent_id": res.agent_id,
                "session_id": res.session_id,
                "chain_id": res.chain_id,
                "provenance": res.result_provenance,
                "success": res.success,
            },
        )

