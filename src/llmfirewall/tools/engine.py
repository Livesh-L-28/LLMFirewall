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
from llmfirewall.tools.command_security import inspect_command_safety, inspect_sql_safety
from llmfirewall.tools.models import (
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
    
    Security Pipeline for Tool Calls:
    1. Tool Identity & Allowlist / Denylist Check
    2. Tool Definition & Granular Permissions Resolution
    3. Argument Limits & Schema Validation
    4. Destination, URL (SSRF), File Path, and Command Inspection
    5. Sensitive Argument Scanning (PII, Secrets, Injection via Detector Engine)
    6. Policy-as-Code Evaluation with explainability and strict conflict resolution
    7. Outcome Construction (ToolSecurityDecision) with approval hooks and audit/telemetry
    
    Security Pipeline for Tool Results:
    1. Output Size Inspection
    2. Indirect Prompt Injection, PII, and Secret Detection
    3. Policy Engine Evaluation (ALLOW, REDACT, or BLOCK)
    4. Outcome Construction with redacted/sanitized output
    """

    def __init__(
        self,
        registry: Optional[ToolRegistry] = None,
        policy_engine: Optional[PolicyEngine] = None,
        detector_engine: Optional[DetectorEngine] = None,
        risk_engine: Optional[RiskEngine] = None,
        enforce_registry: bool = False,
        argument_limits: Optional[ArgumentLimits] = None,
    ) -> None:
        """
        Args:
            registry: ToolRegistry containing authorized tool definitions.
            policy_engine: PolicyEngine instance enforcing declarative rules.
            detector_engine: DetectorEngine running security detectors.
            risk_engine: RiskEngine scoring findings.
            enforce_registry: If True, reject any tool not explicitly in registry.
            argument_limits: Boundaries on tool argument sizes and nesting depth.
        """
        self._registry = registry or default_tool_registry
        self._policy_engine = policy_engine or PolicyEngine()
        self._detector_engine = detector_engine or DetectorEngine()
        self._risk_engine = risk_engine or RiskEngine()
        self._enforce_registry = enforce_registry
        self._argument_limits = argument_limits or ArgumentLimits()

    @property
    def registry(self) -> ToolRegistry:
        return self._registry

    @property
    def policy_engine(self) -> PolicyEngine:
        return self._policy_engine

    def check_tool_call(
        self,
        tool_call: Union[ToolCall, Dict[str, Any]],
        context: Optional[Dict[str, Any]] = None,
    ) -> ToolSecurityDecision:
        """Inspect and enforce security controls on a requested tool call.
        
        Args:
            tool_call: ToolCall instance or dict with 'tool_name' and 'arguments'.
            context: Optional contextual parameters.
            
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
                metadata=tool_call.get("metadata", {}),
            )
        else:
            call = tool_call

        findings: List[Finding] = []
        triggered_rules: List[str] = []
        explanations: List[Dict[str, Any]] = []
        active_policy = self._policy_engine.policy

        # -------------------------------------------------------------
        # 1. Tool Identity & Denylist / Allowlist Enforcement
        # -------------------------------------------------------------
        # Denylist check
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

        # Allowlist check
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

        # Registry existence check if enforce_registry is active
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
        # 2. Argument Limits & Schema Validation
        # -------------------------------------------------------------
        limit_finding = validate_argument_limits(call.arguments, self._argument_limits)
        if limit_finding:
            findings.append(limit_finding)

        if tool_def and tool_def.schema:
            schema_finding = validate_json_schema(call.arguments, tool_def.schema)
            if schema_finding:
                findings.append(schema_finding)

        # -------------------------------------------------------------
        # 3. Destination, SSRF, File Path, Command & SQL Inspection
        # -------------------------------------------------------------
        dest_class: Optional[str] = None

        # Inspect any URL-like argument fields or explicit url keys
        for key, val in call.arguments.items():
            if isinstance(val, str):
                # If argument key suggests a URL or value starts with http:// or https://
                if "url" in key.lower() or val.startswith(("http://", "https://", "ftp://", "file://")):
                    url_finding = validate_url_safety(val)
                    if url_finding:
                        findings.append(url_finding)
                        dest_class = url_finding.metadata.get("violation", "unsafe_url")
                    elif tool_def and tool_def.allowed_domains is not None:
                        # Check allowed domains
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

                # If argument key suggests a filesystem path
                if "path" in key.lower() or "file" in key.lower() or "/" in val or "\\" in val:
                    allowed_paths = tool_def.allowed_paths if tool_def else None
                    path_finding = validate_path_safety(val, allowed_base_dirs=allowed_paths)
                    if path_finding:
                        findings.append(path_finding)

                # If argument key suggests shell/command execution
                if "cmd" in key.lower() or "command" in key.lower() or "exec" in key.lower() or "shell" in call.tool_name:
                    cmd_finding = inspect_command_safety(val)
                    if cmd_finding:
                        findings.append(cmd_finding)

                # If argument key suggests SQL
                if "sql" in key.lower() or "query" in key.lower():
                    sql_finding = inspect_sql_safety(val)
                    if sql_finding:
                        findings.append(sql_finding)

        # -------------------------------------------------------------
        # 4. Sensitive Argument Scanning (PII, Secrets, Injection)
        # -------------------------------------------------------------
        serialized_args = call.serialize_arguments()
        # Scan serialized arguments with detector engine
        scan_ctx = dict(context or {})
        scan_ctx["direction"] = "input"
        scan_ctx["tool"] = call.tool_name
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
        # 5. Risk Scoring & Policy-as-Code Evaluation
        # -------------------------------------------------------------
        risk_score = self._risk_engine.evaluate(findings=findings, context=scan_ctx)

        # Evaluate against PolicyEngine
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
        # 6. Human Approval & Dangerous Tool Hooks
        # -------------------------------------------------------------
        requires_approval = False
        if tool_def and (tool_def.requires_approval or tool_def.is_dangerous):
            requires_approval = True

        # If any findings were CRITICAL or HIGH, ensure BLOCK action
        blocking_findings = [f for f in findings if f.severity in (Severity.CRITICAL, Severity.HIGH)]
        if blocking_findings and final_action != Action.BLOCK:
            final_action = Action.BLOCK
            final_reason = f"Tool call blocked due to security finding: {blocking_findings[0].description}"

        elapsed_ms = (time.perf_counter() - start_time) * 1000.0

        return ToolSecurityDecision(
            tool_name=call.tool_name,
            action=final_action,
            reason=final_reason,
            triggered_rules=triggered_rules,
            findings=findings,
            risk_score=risk_score,
            require_approval=requires_approval,
            policy_id=active_policy.name,
            policy_version=active_policy.version,
            explanations=explanations,
            execution_time_ms=round(elapsed_ms, 3),
            metadata={
                "tool_name": call.tool_name,
                "request_id": call.request_id,
                "user_id": call.user_id,
                "has_findings": len(findings) > 0,
            },
        )

    def check_tool_result(
        self,
        tool_result: Union[ToolResult, Dict[str, Any]],
        context: Optional[Dict[str, Any]] = None,
    ) -> ToolSecurityDecision:
        """Inspect and enforce security controls on a tool's output before returning to LLM.
        
        Guards against indirect prompt injection, sensitive data leakage, and malformed outputs.
        
        Args:
            tool_result: ToolResult instance or dict with 'tool_name' and 'output'.
            context: Contextual parameters.
            
        Returns:
            ToolSecurityDecision: ALLOW, WARN, REDACT, or BLOCK outcome.
        """
        start_time = time.perf_counter()

        if isinstance(tool_result, dict):
            res = ToolResult(
                tool_name=tool_result.get("tool_name") or tool_result.get("name", ""),
                output=str(tool_result.get("output", "")),
                tool_call_id=tool_result.get("tool_call_id"),
                request_id=tool_result.get("request_id"),
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

        # 1. Run Detectors on Output (Prompt Injection, PII, Secrets)
        # Note: Tool results from external environments can carry indirect prompt injection.
        # Run standard output detectors, plus input prompt injection detectors if enabled.
        findings_col = self._detector_engine.execute(
            text=res.output,
            direction="output",
            context=scan_ctx,
        )
        findings = list(findings_col.findings)

        # Check for indirect prompt injection in untrusted tool result
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
        if policy_decision.action == Action.REDACT:
            sanitized_output = policy_decision.redacted_text
        elif policy_decision.action == Action.WARN and self._policy_engine.policy.auto_redact_on_warn:
            sanitized_output = policy_decision.redacted_text
        elif policy_decision.action == Action.BLOCK:
            sanitized_output = ""
        else:
            sanitized_output = res.output

        elapsed_ms = (time.perf_counter() - start_time) * 1000.0

        return ToolSecurityDecision(
            tool_name=res.tool_name,
            action=policy_decision.action,
            reason=policy_decision.reason,
            triggered_rules=policy_decision.triggered_rules,
            findings=findings,
            risk_score=risk_score,
            sanitized_output=sanitized_output,
            policy_id=self._policy_engine.policy.name,
            policy_version=self._policy_engine.policy.version,
            explanations=policy_decision.explanations,
            execution_time_ms=round(elapsed_ms, 3),
            metadata={
                "tool_name": res.tool_name,
                "tool_call_id": res.tool_call_id,
                "request_id": res.request_id,
                "success": res.success,
            },
        )
