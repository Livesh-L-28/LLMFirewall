"""Cross-step security enforcement engine correlating multi-step agent actions.

Phase 3: Cross-Step Agent Security.
Coordinates:
- Prompt scanning -> Workflow threat taint escalation.
- RAG context retrieval -> Indirect injection detection & taint propagation.
- Tool call gating -> Immediate pre-execution authorization check.
- Scoped tool permissions -> Path/URL/table whitelists and action restrictions.
- Tool result scanning -> Taint propagation from external tool outputs.
"""

from __future__ import annotations

import fnmatch
import hashlib
import logging
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Union

if TYPE_CHECKING:
    from llmfirewall.firewall import Firewall

from llmfirewall.core.models import Action, Finding, ScanResult, Severity, ThreatType
from llmfirewall.rag.models import ContextSecurityDecision
from llmfirewall.tools.command_security import inspect_command_safety
from llmfirewall.tools.models import ToolCall, ToolResult, ToolSecurityDecision
from llmfirewall.tools.path_security import validate_path_safety
from llmfirewall.tools.url_security import validate_url_safety
from llmfirewall.workflow.context import WorkflowContextManager
from llmfirewall.workflow.models import (
    CrossTenantViolationError,
    IdentityTamperingError,
    ScopedPermission,
    StepBoundary,
    ThreatObservation,
    ToolAuthorizationError,
    WorkflowCancelledError,
    WorkflowExpiredError,
    WorkflowLimitExceededError,
    WorkflowSecurityContext,
    WorkflowSecurityError,
    WorkflowStatus,
    WorkflowStepRecord,
    WorkflowThreatState,
)

logger = logging.getLogger("llmfirewall.workflow.enforcer")

DANGEROUS_TOOLS_ON_TAINT = {
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
}


class CrossStepEnforcer:
    """Executes multi-step security gating and correlates threat posture across agent workflows."""

    def __init__(
        self,
        firewall: Firewall,
        context_manager: Optional[WorkflowContextManager] = None,
    ) -> None:
        self.firewall = firewall
        self.context_manager = context_manager or WorkflowContextManager()

    # -------------------------------------------------------------------------
    # 1. Prompt Input Boundary
    # -------------------------------------------------------------------------

    def enforce_prompt(
        self,
        workflow_id: str,
        prompt: str,
        tenant_id: str,
        agent_id: Optional[str] = None,
    ) -> ScanResult:
        """Scan incoming user prompt, record step, and escalate workflow taint on threats."""
        ctx = self.context_manager.get_workflow(workflow_id, tenant_id)
        ctx.assert_agent(agent_id)

        if not ctx.is_active:
            raise WorkflowSecurityError(
                f"Workflow '{workflow_id}' is not active (status: {ctx.status.value}).",
                workflow_id=workflow_id,
                tenant_id=tenant_id,
            )

        # Execute Firewall prompt inspection
        res = self.firewall.scan(prompt, direction="input", tenant_id=tenant_id)
        step_num = ctx.step_count + 1
        content_hash = hashlib.sha256(prompt.encode("utf-8")).hexdigest()

        # Check for detected security threats
        threat_names = [f.threat_type.value if hasattr(f.threat_type, "value") else str(f.threat_type) for f in res.findings]

        if res.is_blocked:
            obs = ThreatObservation(
                threat_type="prompt_injection_blocked" if any("injection" in t for t in threat_names) else "policy_violation_blocked",
                severity=Severity.CRITICAL,
                confidence=1.0,
                step_number=step_num,
                boundary=StepBoundary.PROMPT_INPUT,
                source="firewall_input_scan",
                description=res.decision.reason,
            )
            ctx.add_threat_observation(obs)
            ctx.status = WorkflowStatus.BLOCKED
        elif res.findings:
            for f in res.findings:
                tt = f.threat_type.value if hasattr(f.threat_type, "value") else str(f.threat_type)
                obs = ThreatObservation(
                    threat_type=tt,
                    severity=f.severity,
                    confidence=f.confidence,
                    step_number=step_num,
                    boundary=StepBoundary.PROMPT_INPUT,
                    source=f.detector_name,
                    description=f.description,
                )
                ctx.add_threat_observation(obs)

        rec = WorkflowStepRecord(
            step_number=step_num,
            boundary=StepBoundary.PROMPT_INPUT,
            content_hash=content_hash,
            decision=res.action,
            reason=res.decision.reason,
            findings_count=len(res.findings),
            threat_types=threat_names,
        )
        ctx.add_step_record(rec)
        self.context_manager.update_workflow(ctx)
        return res

    # -------------------------------------------------------------------------
    # 2. RAG Retrieval Boundary
    # -------------------------------------------------------------------------

    def enforce_rag(
        self,
        workflow_id: str,
        chunks: List[Union[str, Dict[str, Any]]],
        tenant_id: str,
        agent_id: Optional[str] = None,
    ) -> ContextSecurityDecision:
        """Inspect retrieved context chunks, detect indirect injections, and taint workflow if poisoned."""
        ctx = self.context_manager.get_workflow(workflow_id, tenant_id)
        ctx.assert_agent(agent_id)

        if not ctx.is_active:
            raise WorkflowSecurityError(
                f"Workflow '{workflow_id}' is not active (status: {ctx.status.value}).",
                workflow_id=workflow_id,
                tenant_id=tenant_id,
            )

        rag_dec = self.firewall.rag.filter_and_secure(chunks)
        step_num = ctx.step_count + 1

        raw_text = "".join(c if isinstance(c, str) else str(c.get("content", "")) for c in chunks)
        content_hash = hashlib.sha256(raw_text.encode("utf-8")).hexdigest()

        # If any chunk was filtered or quarantined, record threat observation
        if len(rag_dec.quarantined_items) > 0 or len(rag_dec.filtered_items) > 0:
            obs = ThreatObservation(
                threat_type="rag_poisoning",
                severity=Severity.HIGH,
                confidence=0.95,
                step_number=step_num,
                boundary=StepBoundary.RAG_RETRIEVAL,
                source="rag_context_orchestrator",
                description=f"Retrieved content contained malicious instructions; {len(rag_dec.quarantined_items)} chunks quarantined.",
            )
            ctx.add_threat_observation(obs)

        rec = WorkflowStepRecord(
            step_number=step_num,
            boundary=StepBoundary.RAG_RETRIEVAL,
            content_hash=content_hash,
            decision=rag_dec.action,
            reason=rag_dec.reason,
            findings_count=len(rag_dec.findings),
            threat_types=["rag_poisoning"] if len(rag_dec.quarantined_items) > 0 else [],
        )
        ctx.add_step_record(rec)
        self.context_manager.update_workflow(ctx)
        return rag_dec

    # -------------------------------------------------------------------------
    # 3. Tool Pre-Execution Enforcement Boundary
    # -------------------------------------------------------------------------

    def enforce_tool_call(
        self,
        workflow_id: str,
        tool_name: str,
        arguments: Dict[str, Any],
        tenant_id: str,
        agent_id: Optional[str] = None,
    ) -> ToolSecurityDecision:
        """Execute pre-invocation authorization gating immediately before tool execution.

        Guarantees:
        - A denied tool decision raises ToolAuthorizationError so the underlying function never executes.
        - Tenant and agent identity are strictly verified against workflow bindings.
        - Prior threat observations (taint) restrict dangerous tool execution.
        - Scoped permissions and argument constraints are enforced deterministically.
        """
        ctx = self.context_manager.get_workflow(workflow_id, tenant_id)
        ctx.assert_agent(agent_id)

        # 1. Workflow lifecycle state checks
        if ctx.status == WorkflowStatus.CANCELLED:
            raise WorkflowCancelledError(
                f"Workflow '{workflow_id}' was cancelled: {ctx.cancellation_reason or 'Operation cancelled'}.",
                workflow_id=workflow_id,
                tenant_id=tenant_id,
            )
        if ctx.status == WorkflowStatus.TIMED_OUT or ctx.is_expired():
            ctx.status = WorkflowStatus.TIMED_OUT
            self.context_manager.update_workflow(ctx)
            raise WorkflowExpiredError(
                f"Workflow '{workflow_id}' has expired. Tool '{tool_name}' execution denied.",
                workflow_id=workflow_id,
                tenant_id=tenant_id,
            )
        if ctx.status == WorkflowStatus.BLOCKED:
            raise ToolAuthorizationError(
                f"Workflow '{workflow_id}' is permanently blocked due to prior critical violations.",
                tool_name=tool_name,
                workflow_id=workflow_id,
                tenant_id=tenant_id,
                reason="workflow_blocked",
            )
        if ctx.status == WorkflowStatus.COMPLETED:
            raise WorkflowSecurityError(
                f"Workflow '{workflow_id}' is completed; no further tool calls allowed.",
                workflow_id=workflow_id,
                tenant_id=tenant_id,
            )

        step_num = ctx.step_count + 1
        ctx.tool_call_count += 1

        # 2. Step and tool quota limits
        if step_num > ctx.max_steps:
            ctx.status = WorkflowStatus.BLOCKED
            self.context_manager.update_workflow(ctx)
            raise WorkflowLimitExceededError(
                f"Workflow step quota exceeded: {step_num} > max {ctx.max_steps}.",
                workflow_id=workflow_id,
                tenant_id=tenant_id,
            )
        if ctx.tool_call_count > ctx.max_tool_calls:
            ctx.status = WorkflowStatus.BLOCKED
            self.context_manager.update_workflow(ctx)
            raise WorkflowLimitExceededError(
                f"Workflow tool call limit exceeded: {ctx.tool_call_count} > max {ctx.max_tool_calls}.",
                workflow_id=workflow_id,
                tenant_id=tenant_id,
            )

        norm_tool = tool_name.strip().lower()

        # 3. Global tool allowlist / denylist
        if norm_tool in [t.lower() for t in ctx.denied_tools]:
            ctx.status = WorkflowStatus.BLOCKED
            self._record_denied_step(ctx, step_num, norm_tool, arguments, "Tool explicitly denied by workflow policy.")
            raise ToolAuthorizationError(
                f"Tool '{norm_tool}' is on workflow denylist.",
                tool_name=norm_tool,
                workflow_id=workflow_id,
                tenant_id=tenant_id,
                reason="tool_denied",
            )

        if ctx.allowed_tools is not None and norm_tool not in [t.lower() for t in ctx.allowed_tools]:
            self._record_denied_step(ctx, step_num, norm_tool, arguments, f"Tool '{norm_tool}' not in workflow allowed_tools.")
            raise ToolAuthorizationError(
                f"Tool '{norm_tool}' is not authorized in workflow allowlist.",
                tool_name=norm_tool,
                workflow_id=workflow_id,
                tenant_id=tenant_id,
                reason="tool_not_allowed",
            )

        # 4. Cross-step Threat Correlation (Taint Enforcement)
        if ctx.is_tainted:
            # Deny dangerous tools when workflow is tainted by earlier injections
            if norm_tool in DANGEROUS_TOOLS_ON_TAINT:
                reason = f"Tool '{norm_tool}' denied: workflow is in {ctx.threat_state.value.upper()} state due to earlier threat observations."
                self._record_denied_step(ctx, step_num, norm_tool, arguments, reason)
                raise ToolAuthorizationError(
                    reason,
                    tool_name=norm_tool,
                    workflow_id=workflow_id,
                    tenant_id=tenant_id,
                    reason="tainted_workflow_restricted",
                )

        # 5. Scoped Permissions Enforcement
        if norm_tool in ctx.scoped_permissions:
            perm = ctx.scoped_permissions[norm_tool]

            if perm.requires_clean_workflow and ctx.threat_state != WorkflowThreatState.CLEAN:
                reason = f"Tool '{norm_tool}' requires clean workflow, but threat state is {ctx.threat_state.value}."
                self._record_denied_step(ctx, step_num, norm_tool, arguments, reason)
                raise ToolAuthorizationError(
                    reason,
                    tool_name=norm_tool,
                    workflow_id=workflow_id,
                    tenant_id=tenant_id,
                    reason="clean_workflow_required",
                )

            # Check action parameter
            action_arg = arguments.get("action") or arguments.get("operation")
            if action_arg and not perm.allows_action(action_arg):
                reason = f"Action '{action_arg}' on tool '{norm_tool}' is not permitted by scoped policy."
                self._record_denied_step(ctx, step_num, norm_tool, arguments, reason)
                raise ToolAuthorizationError(
                    reason,
                    tool_name=norm_tool,
                    workflow_id=workflow_id,
                    tenant_id=tenant_id,
                    reason="action_scope_violation",
                )

            # Check resource parameters (paths, URLs, queries, tables)
            resource_arg = None
            for rk in ("path", "file", "url", "table", "endpoint", "resource", "service", "target"):
                if rk in arguments and isinstance(arguments[rk], str):
                    resource_arg = arguments[rk]
                    break

            if resource_arg and not perm.allows_resource(resource_arg):
                reason = f"Resource '{resource_arg}' on tool '{norm_tool}' is not permitted by scoped policy."
                self._record_denied_step(ctx, step_num, norm_tool, arguments, reason)
                raise ToolAuthorizationError(
                    reason,
                    tool_name=norm_tool,
                    workflow_id=workflow_id,
                    tenant_id=tenant_id,
                    reason="resource_scope_violation",
                )

        # 6. Built-in Parameter Safety Checks (Path traversal, command injection, SSRF)
        for k, v in arguments.items():
            if isinstance(v, str):
                # Path traversal
                if any(pk in k.lower() for pk in ("path", "file", "dir")):
                    path_finding = validate_path_safety(v)
                    if path_finding is not None:
                        reason = f"Path traversal attempt in tool argument '{k}': {path_finding.description}"
                        self._record_denied_step(ctx, step_num, norm_tool, arguments, reason)
                        raise ToolAuthorizationError(
                            reason,
                            tool_name=norm_tool,
                            workflow_id=workflow_id,
                            tenant_id=tenant_id,
                            reason="path_traversal",
                        )

                # Command injection: inspect all string arguments for destructive shell commands
                cmd_finding = inspect_command_safety(v)
                if cmd_finding is not None:
                    reason = f"Dangerous command syntax in tool argument '{k}': {cmd_finding.description}"
                    self._record_denied_step(ctx, step_num, norm_tool, arguments, reason)
                    raise ToolAuthorizationError(
                        reason,
                        tool_name=norm_tool,
                        workflow_id=workflow_id,
                        tenant_id=tenant_id,
                        reason="command_injection",
                    )

                # URL & SSRF
                if any(uk in k.lower() for uk in ("url", "endpoint", "uri", "webhook")):
                    url_finding = validate_url_safety(v)
                    if url_finding is not None:
                        reason = f"SSRF / private IP network access attempt in tool argument '{k}': {url_finding.description}"
                        self._record_denied_step(ctx, step_num, norm_tool, arguments, reason)
                        raise ToolAuthorizationError(
                            reason,
                            tool_name=norm_tool,
                            workflow_id=workflow_id,
                            tenant_id=tenant_id,
                            reason="ssrf_blocked",
                        )

        # 7. Execute Core Tool Engine Check
        call = ToolCall(
            tool_name=norm_tool,
            arguments=arguments,
            user_id=tenant_id,
            session_id=ctx.session_id,
            request_id=workflow_id,
        )
        tool_dec = self.firewall.check_tool_call(call, context={"workflow_id": workflow_id, "tenant_id": tenant_id, "_internal_cross_step": True})

        if tool_dec.is_blocked:
            self._record_denied_step(ctx, step_num, norm_tool, arguments, tool_dec.reason)
            raise ToolAuthorizationError(
                f"Tool '{norm_tool}' blocked by policy: {tool_dec.reason}",
                tool_name=norm_tool,
                workflow_id=workflow_id,
                tenant_id=tenant_id,
                reason=tool_dec.reason,
            )

        # 8. Record Approved Step
        sanitized_summary = {k: type(v).__name__ for k, v in arguments.items()}
        rec = WorkflowStepRecord(
            step_number=step_num,
            boundary=StepBoundary.TOOL_CALL,
            content_hash=hashlib.sha256(f"{norm_tool}:{list(arguments.keys())}".encode()).hexdigest(),
            tool_name=norm_tool,
            tool_arguments_summary=sanitized_summary,
            decision=Action.ALLOW,
            reason="Tool invocation authorized by cross-step security policies.",
            findings_count=len(tool_dec.findings),
            threat_types=[],
        )
        ctx.add_step_record(rec)
        self.context_manager.update_workflow(ctx)
        return tool_dec

    # -------------------------------------------------------------------------
    # 4. Tool Execution Result Boundary
    # -------------------------------------------------------------------------

    def enforce_tool_result(
        self,
        workflow_id: str,
        tool_name: str,
        output: str,
        tenant_id: str,
        agent_id: Optional[str] = None,
    ) -> ToolSecurityDecision:
        """Inspect output produced by an executed tool and taint workflow if unsafe."""
        ctx = self.context_manager.get_workflow(workflow_id, tenant_id)
        ctx.assert_agent(agent_id)

        step_num = ctx.step_count + 1
        content_hash = hashlib.sha256(output.encode("utf-8")).hexdigest()

        result_obj = ToolResult(
            tool_name=tool_name,
            output=output,
            request_id=workflow_id,
        )
        res_dec = self.firewall.check_tool_result(result_obj, context={"workflow_id": workflow_id, "tenant_id": tenant_id, "_internal_cross_step": True})

        threats = []
        if res_dec.is_blocked or len(res_dec.findings) > 0 or res_dec.action in (Action.BLOCK, Action.REDACT):
            max_sev = Severity.HIGH
            if res_dec.is_blocked or any(f.severity == Severity.CRITICAL for f in res_dec.findings):
                max_sev = Severity.CRITICAL
            obs = ThreatObservation(
                threat_type="unsafe_tool_result",
                severity=max_sev,
                confidence=0.95,
                step_number=step_num,
                boundary=StepBoundary.TOOL_RESULT,
                source=f"tool_output:{tool_name}",
                description=f"Output from tool '{tool_name}' contained security violations or raw credential leakage.",
            )
            ctx.add_threat_observation(obs)
            threats.append("unsafe_tool_result")

        rec = WorkflowStepRecord(
            step_number=step_num,
            boundary=StepBoundary.TOOL_RESULT,
            content_hash=content_hash,
            tool_name=tool_name,
            decision=res_dec.action,
            reason=res_dec.reason,
            findings_count=len(res_dec.findings),
            threat_types=threats,
        )
        ctx.add_step_record(rec)
        self.context_manager.update_workflow(ctx)
        return res_dec

    # -------------------------------------------------------------------------
    # Helper Methods
    # -------------------------------------------------------------------------

    def _record_denied_step(
        self,
        ctx: WorkflowSecurityContext,
        step_num: int,
        tool_name: str,
        arguments: Dict[str, Any],
        reason: str,
    ) -> None:
        """Record an unauthorized tool step into audit history and persist context."""
        obs = ThreatObservation(
            threat_type="unauthorized_tool_attempt",
            severity=Severity.HIGH,
            confidence=1.0,
            step_number=step_num,
            boundary=StepBoundary.TOOL_CALL,
            source="cross_step_enforcer",
            description=reason,
        )
        ctx.add_threat_observation(obs)

        sanitized_summary = {k: type(v).__name__ for k, v in arguments.items()}
        rec = WorkflowStepRecord(
            step_number=step_num,
            boundary=StepBoundary.TOOL_CALL,
            content_hash=hashlib.sha256(f"{tool_name}:{list(arguments.keys())}".encode()).hexdigest(),
            tool_name=tool_name,
            tool_arguments_summary=sanitized_summary,
            decision=Action.BLOCK,
            reason=reason,
            findings_count=1,
            threat_types=["unauthorized_tool_attempt"],
        )
        ctx.add_step_record(rec)
        self.context_manager.update_workflow(ctx)
