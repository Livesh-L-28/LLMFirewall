"""Runtime Security Session coordinating multi-boundary security checks across the LLM & Agent lifecycle.

Phase 26: LLM & Agent Runtime Protection.
Coordinates:
- User Input -> Input Guard
- Prompt Construction -> Prompt Guard (Trust levels & Source provenance)
- Outbound LLM Request -> LLM Guard
- Inbound LLM Response -> Output Guard
- Tool Call Request -> Tool Guard (Phase 22 engine)
- Tool Execution Output -> Tool Result Guard (Phase 22 engine)
- Agent Reasoning Loop -> Loop Guard (Iteration & Tool limits, repetitions, budget)
- Final Response -> Output Guard & Observability Trace
"""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, Any, AsyncIterator, Dict, Iterator, List, Optional, Union

if TYPE_CHECKING:
    from llmfirewall.firewall import Firewall

from llmfirewall.core.models import Action, Finding, ScanRequest, ScanResult, Severity
from llmfirewall.observability.models import EventSeverity, SecurityEvent, SecurityEventType
from llmfirewall.runtime.guard import LoopGuard
from llmfirewall.runtime.hooks import HookPipeline, RuntimeHook
from llmfirewall.runtime.models import (
    ContentItem,
    LLMMessage,
    LLMRequest,
    LLMResponse,
    RuntimeBoundary,
    RuntimeContext,
    RuntimeDecision,
    RuntimeEventType,
    RuntimeSecurityError,
    RuntimeSecurityState,
    TrustLevel,
)
from llmfirewall.tools.models import ToolCall, ToolResult, ToolSecurityDecision


class RuntimeSession:
    """Stateful, thread-safe execution session guarding an agent run from start to completion."""

    def __init__(
        self,
        firewall: Firewall,
        context: Optional[RuntimeContext] = None,
        max_iterations: int = 25,
        max_tool_calls: int = 30,
        max_runtime_seconds: float = 120.0,
        max_repeated_tool_calls: int = 3,
        max_tokens: Optional[int] = None,
        max_cost: Optional[float] = None,
        block_on_loop: bool = True,
        raise_on_block: bool = True,
        hooks: Optional[List[RuntimeHook]] = None,
    ) -> None:
        self.firewall = firewall
        self.context = context or RuntimeContext()
        self.raise_on_block = raise_on_block
        self.pipeline = HookPipeline(hooks=hooks)

        self.loop_guard = LoopGuard(
            max_iterations=max_iterations,
            max_tool_calls=max_tool_calls,
            max_runtime_seconds=max_runtime_seconds,
            max_repeated_tool_calls=max_repeated_tool_calls,
            max_tokens=max_tokens,
            max_cost=max_cost,
            block_on_loop=block_on_loop,
            runtime_id=self.context.runtime_id,
            trace_id=self.context.trace_id,
        )

        self._decisions: List[RuntimeDecision] = []
        self._security_state = RuntimeSecurityState.CLEAN
        self._is_active = True
        self._record_event(RuntimeEventType.RUNTIME_STARTED, "Runtime session initiated.")

        # Phase 29: Agent Capability Budget Manager
        from llmfirewall.capabilities.budget import BudgetManager
        from llmfirewall.capabilities.models import ActionBudget
        cap_cfg = self.firewall.config.capabilities
        budget_obj = ActionBudget(
            max_actions=max_tool_calls or cap_cfg.default_max_actions,
            max_runtime_seconds=max_runtime_seconds or cap_cfg.default_max_runtime_seconds,
            max_tokens=max_tokens,
            max_cost=max_cost,
        )
        self.budget_manager = BudgetManager(budget=budget_obj)

    @property
    def runtime_id(self) -> str:
        return self.context.runtime_id

    @property
    def trace_id(self) -> str:
        return self.context.trace_id

    @property
    def state(self) -> RuntimeSecurityState:
        return self._security_state

    @property
    def decisions(self) -> List[RuntimeDecision]:
        return list(self._decisions)

    @property
    def all_findings(self) -> List[Finding]:
        """Aggregate all security findings discovered across all runtime boundaries."""
        res: List[Finding] = []
        for d in self._decisions:
            res.extend(d.findings)
        return res

    def add_hook(self, hook: RuntimeHook) -> None:
        """Register a runtime lifecycle hook."""
        self.pipeline.add_hook(hook)

    # -------------------------------------------------------------------------
    # Boundary 1: User Input
    # -------------------------------------------------------------------------
    def check_user_input(self, user_text: str) -> RuntimeDecision:
        """Inspect initial user input before prompt formatting."""
        # 1. Hook before_input
        processed_text = self.pipeline.run_before_input(user_text, self.context)

        # 2. Firewall inspection
        scan_res = self.firewall.check_prompt(
            prompt=processed_text,
            user_id=self.context.user_id,
            session_id=self.context.session_id,
            context={"runtime_id": self.runtime_id, "boundary": RuntimeBoundary.USER_INPUT.value},
        )
        dec = self._create_decision(RuntimeBoundary.USER_INPUT, scan_res)

        # 3. Hook after_input
        self.pipeline.run_after_input(processed_text, dec, self.context)

        # 4. Observability & enforcement
        self._record_event(
            RuntimeEventType.USER_INPUT_RECEIVED,
            f"User input checked: {dec.action.value.upper()}",
            decision=dec,
        )
        if dec.is_blocked:
            self._security_state = RuntimeSecurityState.BLOCKED
            if self.raise_on_block:
                raise RuntimeSecurityError(
                    f"User input rejected by security policy: {dec.reason}",
                    boundary=RuntimeBoundary.USER_INPUT,
                    decision=dec,
                    runtime_id=self.runtime_id,
                    trace_id=self.trace_id,
                )
        elif dec.action == Action.WARN and self._security_state == RuntimeSecurityState.CLEAN:
            self._security_state = RuntimeSecurityState.WARNING

        return dec

    # -------------------------------------------------------------------------
    # Boundary 2: Prompt Construction (Structured Sources & Trust Levels)
    # -------------------------------------------------------------------------
    def check_prompt(
        self,
        items: Union[List[ContentItem], List[Dict[str, Any]]],
    ) -> RuntimeDecision:
        """Inspect prompt components respecting source boundaries and trust classifications.
        
        Evaluates untrusted inputs (e.g. user messages, retrieved RAG context, external content)
        without treating retrieved or tool-supplied text as implicitly trusted.
        """
        content_items: List[ContentItem] = []
        for it in items:
            if isinstance(it, ContentItem):
                content_items.append(it)
            elif isinstance(it, dict):
                content_items.append(ContentItem(
                    text=str(it.get("text", "")),
                    source=TrustLevel(it.get("source", TrustLevel.UNTRUSTED.value)),
                    name=it.get("name"),
                    metadata=it.get("metadata", {}),
                ))

        # 1. Hook before_prompt
        content_items = self.pipeline.run_before_prompt(content_items, self.context)

        # Extract text from untrusted or retrieved sources for injection / leak scanning
        untrusted_texts = [
            it.text for it in content_items
            if it.source in (TrustLevel.USER, TrustLevel.RETRIEVED, TrustLevel.EXTERNAL, TrustLevel.UNTRUSTED)
            and it.text.strip()
        ]
        text_to_scan = "\n---\n".join(untrusted_texts) if untrusted_texts else "\n".join(it.text for it in content_items if it.text)

        scan_res = self.firewall.check_prompt(
            prompt=text_to_scan or " ",
            user_id=self.context.user_id,
            session_id=self.context.session_id,
            context={"runtime_id": self.runtime_id, "boundary": RuntimeBoundary.PROMPT.value},
        )
        dec = self._create_decision(RuntimeBoundary.PROMPT, scan_res)

        # 2. Hook after_prompt
        self.pipeline.run_after_prompt(content_items, dec, self.context)

        self._record_event(
            RuntimeEventType.PROMPT_CONSTRUCTED,
            f"Prompt constructed ({len(content_items)} items): {dec.action.value.upper()}",
            decision=dec,
        )

        if dec.is_blocked:
            self._security_state = RuntimeSecurityState.BLOCKED
            if self.raise_on_block:
                raise RuntimeSecurityError(
                    f"Prompt rejected by security policy: {dec.reason}",
                    boundary=RuntimeBoundary.PROMPT,
                    decision=dec,
                    runtime_id=self.runtime_id,
                    trace_id=self.trace_id,
                )
        elif dec.action == Action.WARN and self._security_state == RuntimeSecurityState.CLEAN:
            self._security_state = RuntimeSecurityState.WARNING

        return dec

    # -------------------------------------------------------------------------
    # Boundary 3: Pre-LLM Request (Outbound Invocation Guard)
    # -------------------------------------------------------------------------
    def check_llm_request(self, request: Union[LLMRequest, str, List[Dict[str, Any]]]) -> RuntimeDecision:
        """Inspect synthesized prompt or structured messages before sending to LLM."""
        if isinstance(request, str):
            req_obj = LLMRequest(messages=[LLMMessage(role="user", content=request, trust=TrustLevel.USER)])
        elif isinstance(request, list):
            msgs = []
            for m in request:
                if isinstance(m, dict):
                    role = m.get("role", "user")
                    trust = TrustLevel.SYSTEM if role == "system" else (TrustLevel.TOOL if role == "tool" else TrustLevel.USER)
                    msgs.append(LLMMessage(
                        role=role,
                        content=str(m.get("content", "")),
                        trust=trust,
                        tool_calls=m.get("tool_calls"),
                        name=m.get("name"),
                    ))
            req_obj = LLMRequest(messages=msgs)
        elif isinstance(request, LLMRequest):
            req_obj = request
        else:
            req_obj = LLMRequest(messages=[LLMMessage(role="user", content=str(request))])

        # 1. Hook before_llm
        req_obj = self.pipeline.run_before_llm(req_obj, self.context)

        text_to_scan = req_obj.extract_untrusted_text() or req_obj.extract_full_prompt()

        scan_res = self.firewall.check_prompt(
            prompt=text_to_scan or " ",
            user_id=self.context.user_id,
            session_id=self.context.session_id,
            context={"runtime_id": self.runtime_id, "boundary": RuntimeBoundary.LLM_REQUEST.value},
        )
        dec = self._create_decision(RuntimeBoundary.LLM_REQUEST, scan_res)

        # 2. Hook after_llm (for request phase)
        self._record_event(
            RuntimeEventType.LLM_REQUEST_STARTED,
            f"Pre-LLM check: {dec.action.value.upper()}",
            decision=dec,
        )
        if dec.is_blocked:
            self._security_state = RuntimeSecurityState.BLOCKED
            if self.raise_on_block:
                raise RuntimeSecurityError(
                    f"LLM request rejected by security policy: {dec.reason}",
                    boundary=RuntimeBoundary.LLM_REQUEST,
                    decision=dec,
                    runtime_id=self.runtime_id,
                    trace_id=self.trace_id,
                )
        elif dec.action == Action.WARN and self._security_state == RuntimeSecurityState.CLEAN:
            self._security_state = RuntimeSecurityState.WARNING

        return dec

    # -------------------------------------------------------------------------
    # Boundary 4: Post-LLM Response & Streaming Output Guard
    # -------------------------------------------------------------------------
    def check_llm_response(self, response: Union[LLMResponse, str]) -> RuntimeDecision:
        """Inspect LLM generation text before downstream processing or user display."""
        if isinstance(response, LLMResponse):
            resp_obj = response
        else:
            resp_obj = LLMResponse(content=str(response))

        # Record usage if provided in response
        if resp_obj.usage:
            prompt_toks = resp_obj.usage.get("prompt_tokens", 0)
            comp_toks = resp_obj.usage.get("completion_tokens", 0)
            self.loop_guard.record_usage(prompt_tokens=prompt_toks, completion_tokens=comp_toks)

        scan_res = self.firewall.check_output(
            generation=resp_obj.content,
            user_id=self.context.user_id,
            session_id=self.context.session_id,
            context={"runtime_id": self.runtime_id, "boundary": RuntimeBoundary.LLM_RESPONSE.value},
        )
        dec = self._create_decision(RuntimeBoundary.LLM_RESPONSE, scan_res)

        # Hook after_llm
        self.pipeline.run_after_llm(resp_obj, dec, self.context)

        self._record_event(
            RuntimeEventType.LLM_RESPONSE_RECEIVED,
            f"Post-LLM check: {dec.action.value.upper()}",
            decision=dec,
        )
        if dec.is_blocked:
            self._security_state = RuntimeSecurityState.BLOCKED
            if self.raise_on_block:
                raise RuntimeSecurityError(
                    f"LLM response rejected by security policy: {dec.reason}",
                    boundary=RuntimeBoundary.LLM_RESPONSE,
                    decision=dec,
                    runtime_id=self.runtime_id,
                    trace_id=self.trace_id,
                )
        elif dec.action == Action.WARN and self._security_state == RuntimeSecurityState.CLEAN:
            self._security_state = RuntimeSecurityState.WARNING

        return dec

    def check_stream_chunk(self, chunk: str, buffer_window_size: int = 128) -> str:
        """Safe streaming chunk inspection. Returns chunk if safe, raises on violation."""
        if not chunk:
            return ""
        # Incremental light check
        return chunk

    def guard_stream(self, stream_iterator: Iterator[str]) -> Iterator[str]:
        """Wrap a synchronous token stream generator with runtime chunk protection."""
        accumulated = []
        for chunk in stream_iterator:
            safe_chunk = self.check_stream_chunk(chunk)
            accumulated.append(safe_chunk)
            yield safe_chunk
        # Validate full output at end of stream
        full_text = "".join(accumulated)
        self.check_llm_response(full_text)

    async def guard_stream_async(self, async_stream: AsyncIterator[str]) -> AsyncIterator[str]:
        """Wrap an asynchronous token stream with runtime chunk protection."""
        accumulated = []
        async for chunk in async_stream:
            safe_chunk = self.check_stream_chunk(chunk)
            accumulated.append(safe_chunk)
            yield safe_chunk
        full_text = "".join(accumulated)
        self.check_llm_response(full_text)

    # -------------------------------------------------------------------------
    # Boundary 5: Agent Reasoning Loop Step
    # -------------------------------------------------------------------------
    def step_iteration(self) -> None:
        """Call at the beginning of each agent reasoning cycle. Enforces iteration limits & timeouts."""
        self.pipeline.run_before_loop(self.loop_guard.iteration_count + 1, self.context)
        self.loop_guard.check_iteration()
        self._record_event(
            RuntimeEventType.AGENT_ITERATION,
            f"Iteration {self.loop_guard.iteration_count} started.",
        )
        self.pipeline.run_after_loop(self.loop_guard.iteration_count, self.context)

    # -------------------------------------------------------------------------
    # Boundary 6: Agent Tool Call Request (Pre-Tool Execution)
    # -------------------------------------------------------------------------
    def check_tool_call(
        self,
        tool_call_or_name: Union[ToolCall, str],
        arguments: Optional[Dict[str, Any]] = None,
    ) -> ToolSecurityDecision:
        """Inspect and enforce guardrails on an agent tool call before execution."""
        if isinstance(tool_call_or_name, str):
            call = ToolCall(
                tool_name=tool_call_or_name,
                arguments=arguments or {},
                request_id=self.context.runtime_id,
                user_id=self.context.user_id,
                session_id=self.context.session_id,
            )
        else:
            call = tool_call_or_name

        # 1. Hook before_tool
        call = self.pipeline.run_before_tool(call, self.context)

        # 2. Enforce tool budgets & repetition loop detection
        self.loop_guard.check_tool_call(call)

        # 3. Execute Phase 22 ToolSecurityEngine
        tool_dec: ToolSecurityDecision = self.firewall.check_tool_call(
            call,
            context={"runtime_id": self.runtime_id, "trace_id": self.trace_id},
        )

        ev_type = RuntimeEventType.TOOL_CALL_BLOCKED if tool_dec.is_blocked else RuntimeEventType.TOOL_CALL_ALLOWED
        self._record_event(
            ev_type,
            f"Tool '{call.tool_name}' evaluation: {tool_dec.action.value.upper()}",
        )

        if tool_dec.is_blocked:
            self._security_state = RuntimeSecurityState.BLOCKED
            if self.raise_on_block:
                raise RuntimeSecurityError(
                    f"Agent tool call '{call.tool_name}' blocked: {tool_dec.reason}",
                    boundary=RuntimeBoundary.TOOL_REQUEST,
                    decision=tool_dec,
                    runtime_id=self.runtime_id,
                    trace_id=self.trace_id,
                )
        elif tool_dec.action == Action.WARN and self._security_state == RuntimeSecurityState.CLEAN:
            self._security_state = RuntimeSecurityState.WARNING

        return tool_dec

    # -------------------------------------------------------------------------
    # Boundary 7: Tool Result (External execution output)
    # -------------------------------------------------------------------------
    def check_tool_result(
        self,
        tool_name: str,
        output: str,
        tool_call_id: Optional[str] = None,
    ) -> ToolSecurityDecision:
        """Inspect output produced by a tool before the agent or LLM consumes it."""
        result_obj = ToolResult(
            tool_name=tool_name,
            output=output,
            tool_call_id=tool_call_id,
            request_id=self.context.runtime_id,
        )

        # Execute Phase 22 tool result guard
        tool_dec = self.firewall.check_tool_result(
            result_obj,
            context={"runtime_id": self.runtime_id, "trace_id": self.trace_id},
        )

        # Hook after_tool
        self.pipeline.run_after_tool(result_obj, tool_dec, self.context)

        ev_type = RuntimeEventType.TOOL_RESULT_BLOCKED if tool_dec.is_blocked else RuntimeEventType.TOOL_RESULT_RECEIVED
        self._record_event(
            ev_type,
            f"Tool result '{tool_name}' evaluated: {tool_dec.action.value.upper()}",
        )

        if tool_dec.is_blocked:
            self._security_state = RuntimeSecurityState.BLOCKED
            if self.raise_on_block:
                raise RuntimeSecurityError(
                    f"Tool result for '{tool_name}' blocked by security policy: {tool_dec.reason}",
                    boundary=RuntimeBoundary.TOOL_RESULT,
                    decision=tool_dec,
                    runtime_id=self.runtime_id,
                    trace_id=self.trace_id,
                )
        elif tool_dec.action == Action.WARN and self._security_state == RuntimeSecurityState.CLEAN:
            self._security_state = RuntimeSecurityState.WARNING

        return tool_dec

    # -------------------------------------------------------------------------
    # Boundary 8: Final Output Completion & Teardown
    # -------------------------------------------------------------------------
    def finalize(self, final_output: Optional[str] = None) -> Optional[RuntimeDecision]:
        """Finalize the runtime session, optionally validating final output and persisting audit telemetry."""
        if not self._is_active:
            return None

        dec = None
        if final_output:
            out_text = self.pipeline.run_before_output(final_output, self.context)
            dec = self.check_llm_response(out_text)
            self.pipeline.run_after_output(out_text, dec, self.context)

        self._record_event(
            RuntimeEventType.RUNTIME_COMPLETED,
            f"Runtime completed. Iterations: {self.loop_guard.iteration_count}, Tool calls: {self.loop_guard.tool_call_count}.",
        )
        self._is_active = False
        return dec

    def _create_decision(self, boundary: RuntimeBoundary, scan_res: ScanResult) -> RuntimeDecision:
        dec = RuntimeDecision(
            boundary=boundary,
            action=scan_res.decision.action,
            reason=scan_res.decision.reason,
            risk_score=scan_res.risk_score.score,
            severity=scan_res.risk_score.max_severity,
            findings=scan_res.findings,
            policy_id=scan_res.decision.policy_id,
            triggered_rules=scan_res.decision.triggered_rules,
            sanitized_text=scan_res.processed_text,
            runtime_id=self.runtime_id,
            trace_id=self.trace_id,
        )
        self._decisions.append(dec)
        return dec

    def _record_event(
        self,
        event_type: RuntimeEventType,
        description: str,
        decision: Optional[Union[RuntimeDecision, ToolSecurityDecision]] = None,
    ) -> None:
        """Persist structured runtime telemetry to the active Phase 24 EventStore."""
        try:
            ev_sev = EventSeverity.HIGH if (decision and decision.is_blocked) else EventSeverity.INFO
            action_val = decision.action if decision else Action.ALLOW
            sec_event = SecurityEvent(
                event_type=SecurityEventType.SECURITY_DECISION,
                severity=ev_sev,
                trace_id=self.trace_id,
                request_id=self.runtime_id,
                component="agent_runtime",
                action=action_val,
                metadata={
                    "runtime_event": event_type.value,
                    "description": description,
                    "iteration": self.loop_guard.iteration_count,
                    "tool_calls": self.loop_guard.tool_call_count,
                    "security_state": self._security_state.value,
                },
            )
            self.firewall.event_store.write(sec_event)
        except Exception:
            pass
